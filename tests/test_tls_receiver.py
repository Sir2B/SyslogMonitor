import queue
import socket
import ssl
import time

import pytest

from conftest import tls_client_context
from syslog_monitor import receiver as receiver_module
from syslog_monitor.receiver import TlsConfigError, TlsReceiver, create_tls_context
from syslog_monitor.stats import Stats


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def octet_frame(message: bytes) -> bytes:
    return str(len(message)).encode("ascii") + b" " + message


def drain(out: queue.Queue) -> list:
    events = []
    while True:
        try:
            events.append(out.get_nowait())
        except queue.Empty:
            return events


def start_receiver(context: ssl.SSLContext, maxsize: int = 0):
    out: queue.Queue = queue.Queue(maxsize=maxsize)
    stats = Stats()
    receiver = TlsReceiver("127.0.0.1", 0, out, stats, context)
    receiver.start()
    return receiver, out, stats


def connect_tls(port: int, context: ssl.SSLContext) -> ssl.SSLSocket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        return context.wrap_socket(sock, server_hostname="localhost")
    except BaseException:
        sock.close()
        raise


def test_context_loads_separate_or_combined_key_and_requires_tls12(tls_certs):
    context = create_tls_context(tls_certs.server_cert, tls_certs.server_key)
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_NONE
    combined = create_tls_context(tls_certs.combined)
    assert combined.verify_mode == ssl.CERT_NONE
    mutual = create_tls_context(tls_certs.server_cert, tls_certs.server_key, tls_certs.ca)
    assert mutual.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("files,match", [
    (("",), "no TLS certificate"),
    (("missing.crt",), "certificate or private key"),
    (("server_cert", "rogue_key"), "certificate or private key"),
    (("locked_cert", "locked_key"), "encrypted private keys"),
    (("server_cert", "server_key", "missing-ca.pem"), "client CA"),
])
def test_invalid_tls_files_raise_clear_errors(tls_certs, tmp_path, files, match):
    paths = [getattr(tls_certs, name, None) or (str(tmp_path / name) if name else "") for name in files]
    with pytest.raises(TlsConfigError, match=match):
        create_tls_context(*paths)


def test_tls_receives_octet_counted_and_line_frames_across_records(tls_certs):
    receiver, out, stats = start_receiver(create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    try:
        large = b"<14>1 - host app - - - " + b"x" * 100_000
        message = "<11>1 - host app - - - TLS größe\nzweite Zeile".encode()
        burst = b"".join(octet_frame(f"<14>burst {i}".encode()) for i in range(500))
        with connect_tls(receiver.bound_port, tls_client_context(tls_certs)) as client:
            client_port = client.getsockname()[1]
            assert client.version() in ("TLSv1.2", "TLSv1.3")
            frame = octet_frame(message)
            client.sendall(frame[:5])
            time.sleep(0.05)
            client.sendall(frame[5:] + octet_frame(large) + b"<14>line one\n" + burst + b"<14>final")
            assert wait_for(lambda: stats.snapshot().received == 503)
        assert wait_for(lambda: stats.snapshot().received == 504)
        events = drain(out)
        assert [event.raw for event in events[:3]] == [message, large, b"<14>line one"]
        assert events[-1].raw == b"<14>final"
        assert events[3].message == "burst 0" and events[-2].message == "burst 499"
        assert all((event.source_ip, event.source_port) == ("127.0.0.1", client_port) for event in events)
        snap = stats.snapshot()
        assert snap.tls_handshake_failures == 0 and snap.dropped_tcp_framing == 0
    finally:
        receiver.stop()


def test_plaintext_client_fails_handshake_without_stopping_the_listener(tls_certs):
    receiver, out, stats = start_receiver(create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    try:
        with socket.create_connection(("127.0.0.1", receiver.bound_port), timeout=5) as plain:
            plain.sendall(b"<14>plaintext message\n" * 20)
            assert wait_for(lambda: stats.snapshot().tls_handshake_failures == 1)
            plain.settimeout(5)
            try:
                while plain.recv(4096):
                    pass
            except ConnectionError:
                pass
        with connect_tls(receiver.bound_port, tls_client_context(tls_certs)) as client:
            client.sendall(b"<14>after plaintext\n")
            assert wait_for(lambda: stats.snapshot().received == 1)
        assert receiver.running
        assert [event.message for event in drain(out)] == ["after plaintext"]
    finally:
        receiver.stop()


def test_stalled_handshake_times_out(tls_certs, monkeypatch):
    monkeypatch.setattr(receiver_module, "TLS_HANDSHAKE_TIMEOUT_S", 0.2)
    receiver, _, stats = start_receiver(create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    try:
        with socket.create_connection(("127.0.0.1", receiver.bound_port), timeout=5) as idle:
            assert wait_for(lambda: stats.snapshot().tls_handshake_failures == 1)
            try:
                assert idle.recv(1) == b""
            except ConnectionError:
                pass
        assert receiver.running
    finally:
        receiver.stop()


@pytest.mark.parametrize("client,accepted", [(None, False), ("rogue", False), ("client", True)])
def test_client_ca_requires_a_trusted_client_certificate(tls_certs, client, accepted):
    context = create_tls_context(tls_certs.server_cert, tls_certs.server_key, tls_certs.ca)
    receiver, out, stats = start_receiver(context)
    try:
        try:
            with connect_tls(receiver.bound_port, tls_client_context(tls_certs, client)) as tls:
                tls.sendall(b"<14>from device\n")
                # TLS 1.3 reports a rejected client certificate only on the next read.
                tls.settimeout(2)
                try:
                    tls.recv(1)
                except (ssl.SSLError, ConnectionError, TimeoutError):
                    pass
        except (ssl.SSLError, ConnectionError):
            pass
        if accepted:
            assert wait_for(lambda: stats.snapshot().received == 1)
            assert [event.message for event in drain(out)] == ["from device"]
            assert stats.snapshot().tls_handshake_failures == 0
        else:
            assert wait_for(lambda: stats.snapshot().tls_handshake_failures == 1)
            assert stats.snapshot().received == 0
        assert receiver.running
    finally:
        receiver.stop()


def test_unfinished_tls_frame_is_counted_when_the_client_disconnects(tls_certs):
    receiver, out, stats = start_receiver(create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    try:
        with connect_tls(receiver.bound_port, tls_client_context(tls_certs)) as client:
            client.sendall(b"<14>complete\n40 <14>incomplete")
            assert wait_for(lambda: stats.snapshot().received == 1)
            client.close()
        assert wait_for(lambda: stats.snapshot().dropped_tcp_framing == 1)
        assert [event.message for event in drain(out)] == ["complete"]
    finally:
        receiver.stop()
