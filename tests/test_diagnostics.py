import socket
import ssl
import threading
from dataclasses import replace

import pytest

from syslog_monitor.diagnostics import (
    CheckOptions, generate_certificates, run_check,
)

MESSAGE = b"<134>1 2026-11-06T00:00:00Z client app - - - CHECK"


def execute(options, send, certificate=None, baseline=False):
    ready = threading.Event()
    cancel = threading.Event()
    ports = []
    results = []
    errors = []

    def listening(port):
        ports.append(port)
        ready.set()

    def run():
        try:
            results.append(run_check(options, cancel, certificate=certificate,
                                     baseline_ok=baseline, ready=listening))
        except Exception as exc:
            errors.append(exc)
            ready.set()

    thread = threading.Thread(target=run)
    thread.start()
    client = None
    try:
        assert ready.wait(5)
        assert not errors
        client = send(ports[0])
        thread.join(5)
    finally:
        cancel.set()
        thread.join(5)
        if client is not None:
            client.close()
    assert not thread.is_alive()
    assert not errors
    return results[0]


def options(case):
    return CheckOptions(case, "127.0.0.1", 0, "127.0.0.1", "CHECK", timeout=1)


def test_udp_and_pri_mismatch():
    def send(port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(MESSAGE, ("127.0.0.1", port))
    assert execute(options("udp"), send).status == "passed"
    assert execute(replace(options("udp"), severity=3), send).status == "failed"


def test_tcp_framing_and_reconnect():
    def send(port):
        for _ in range(2):
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                frame = str(len(MESSAGE)).encode() + b" " + MESSAGE
                sock.sendall(frame[:5])
                sock.sendall(frame[5:])
    result = execute(options("tcp_reconnect"), send)
    assert (result.status, result.connections, result.messages) == ("passed", 2, 2)
    assert result.connection_attempts == 2


@pytest.mark.parametrize("payload", [
    MESSAGE,
    MESSAGE.replace(b"2026-11-06T00:00:00Z", b"invalid") + b"\n",
    MESSAGE.replace(b"CHECK", b"CHECK\xff") + b"\n",
])
def test_tcp_rejects_unterminated_or_malformed_test_message(payload):
    def send(port):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            sock.recv(1)
    assert execute(options("tcp"), send).status == "failed"


def test_rfc3164_udp_and_missing_reconnect():
    def udp(port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"<134>Nov  6 00:00:00 client app: CHECK", ("127.0.0.1", port))
    result = execute(replace(options("udp"), expected_format="rfc3164"), udp)
    assert result.status == "passed"
    assert result.datagrams == 1
    def tcp(port):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.sendall(MESSAGE + b"\n")
            sock.recv(1)
    assert execute(options("tcp_reconnect"), tcp).status == "inconclusive"


def test_no_traffic_and_wrong_client_are_not_passes():
    assert execute(options("udp"), lambda port: None).status == "inconclusive"
    def send(port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(MESSAGE, ("127.0.0.1", port))
    result = execute(replace(options("udp"), client_ip="192.0.2.50"), send)
    assert result.status == "inconclusive"
    assert result.ignored_sources == 1


@pytest.fixture
def certificates(tmp_path):
    return generate_certificates(tmp_path, "localhost")


@pytest.mark.parametrize("strict", [False, True])
def test_tls_positive_control(certificates, strict):
    context = ssl.create_default_context(cafile=str(certificates["ca"]))
    if strict:
        context.verify_flags |= ssl.VERIFY_X509_STRICT
    def send(port):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as tls:
                tls.sendall(str(len(MESSAGE)).encode() + b" " + MESSAGE)
                tls.recv(1)
    assert execute(options("tls_valid"), send, certificates["tls_valid"]).status == "passed"


@pytest.mark.parametrize("case", ["tls_untrusted", "tls_hostname", "tls_expired", "tls_usage"])
def test_verifying_client_rejects_bad_certificates(certificates, case):
    context = ssl.create_default_context(cafile=str(certificates["ca"]))
    def send(port):
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        tls = context.wrap_socket(sock, server_hostname="localhost", do_handshake_on_connect=False)
        try:
            with pytest.raises(ssl.SSLCertVerificationError):
                tls.do_handshake()
        except BaseException:
            tls.close()
            raise
        # Keep the socket open until the server has observed the fatal alert.
        return tls
    assert execute(options(case), send, certificates[case], baseline=True).status == "passed"


@pytest.mark.parametrize("case", ["tls_untrusted", "tls_hostname", "tls_expired", "tls_usage"])
def test_insecure_client_sending_message_fails_negative_test(certificates, case):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    def send(port):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as tls:
                tls.sendall(MESSAGE + b"\n")
                tls.recv(1)
    assert execute(options(case), send, certificates[case],
                   baseline=True).status == "failed"


def test_tls_positive_requires_octet_counted_frame_and_silent_client_is_inconclusive(certificates):
    context = ssl.create_default_context(cafile=str(certificates["ca"]))
    def send(port):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as tls:
                tls.sendall(MESSAGE + b"\n")
                tls.recv(1)
    assert execute(options("tls_valid"), send, certificates["tls_valid"]).status == "failed"
    assert execute(options("tls_expired"), lambda port: None,
                   certificates["tls_expired"], baseline=True).status == "inconclusive"


def test_cancel_stalled_tls_handshake(certificates):
    def send(port):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            # No ClientHello; the session must still terminate within its timeout.
            assert sock.recv(1) == b""
    assert execute(options("tls_valid"), send, certificates["tls_valid"]).status == "inconclusive"


def test_certificate_generation_rejects_invalid_names(tmp_path):
    with pytest.raises(ValueError, match="hostname"):
        generate_certificates(tmp_path, "not a hostname")


def test_port_conflict_is_explicit():
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        with pytest.raises(OSError):
            run_check(replace(options("tcp"), port=occupied.getsockname()[1]), threading.Event())


def test_negative_test_requires_baseline(certificates):
    with pytest.raises(ValueError, match="positive control"):
        run_check(options("tls_hostname"), threading.Event(), certificate=certificates["tls_hostname"])


def test_invalid_options_and_cancellation():
    with pytest.raises(ValueError):
        replace(options("udp"), bind_host="invalid").validate()
    cancel = threading.Event()
    cancel.set()
    assert run_check(options("udp"), cancel).status == "inconclusive"
