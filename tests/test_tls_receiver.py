import queue
import selectors
import socket
import ssl
import threading
import time
from unittest.mock import Mock, call

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


def connect_tls(port: int, context: ssl.SSLContext, *, suppress_ragged_eofs: bool = True) -> ssl.SSLSocket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        return context.wrap_socket(sock, server_hostname="localhost",
                                   suppress_ragged_eofs=suppress_ragged_eofs)
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
            with client.unwrap():
                pass
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


def test_abrupt_tls_close_discards_an_unterminated_message(tls_certs):
    receiver, out, stats = start_receiver(create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    try:
        with connect_tls(receiver.bound_port, tls_client_context(tls_certs)) as client:
            client.sendall(b"<14>complete\n<14>unfinished")
            assert wait_for(lambda: stats.snapshot().received == 1)

        assert wait_for(lambda: stats.snapshot().dropped_tcp_framing == 1
                        or stats.snapshot().received > 1)
        assert stats.snapshot().dropped_tcp_framing == 1
        assert [event.message for event in drain(out)] == ["complete"]
        assert receiver.running
    finally:
        receiver.stop()


@pytest.mark.parametrize("version", [
    ssl.TLSVersion.TLSv1_2,
    pytest.param(ssl.TLSVersion.TLSv1_3, marks=pytest.mark.skipif(
        not ssl.HAS_TLSv1_3, reason="TLS 1.3 is unavailable")),
])
def test_clean_tls_close_accepts_final_message_and_sends_close_notify(tls_certs, version):
    receiver, out, stats = start_receiver(create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    try:
        context = tls_client_context(tls_certs)
        context.minimum_version = version
        context.maximum_version = version
        with connect_tls(receiver.bound_port, context) as client:
            client.sendall(b"<14>unterminated final line")
            with client.unwrap():
                pass

        assert wait_for(lambda: stats.snapshot().received == 1)
        assert [event.message for event in drain(out)] == ["unterminated final line"]
        assert stats.snapshot().dropped_tcp_framing == 0
    finally:
        receiver.stop()


def test_clean_tls_close_discards_incomplete_octet_frame(tls_certs):
    receiver, out, stats = start_receiver(create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    try:
        with connect_tls(receiver.bound_port, tls_client_context(tls_certs)) as client:
            client.sendall(b"<14>complete\n40 <14>unfinished")
            with client.unwrap():
                pass

        assert wait_for(lambda: stats.snapshot().dropped_tcp_framing == 1)
        assert [event.message for event in drain(out)] == ["complete"]
    finally:
        receiver.stop()


def test_stopping_tls_listener_sends_close_notify(tls_certs):
    receiver, out, stats = start_receiver(create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    try:
        context = tls_client_context(tls_certs)
        with connect_tls(receiver.bound_port, context, suppress_ragged_eofs=False) as client:
            client.sendall(b"<14>connected\n")
            assert wait_for(lambda: stats.snapshot().received == 1)
            receiver.stop()
            assert client.recv(1) == b""
        assert [event.message for event in drain(out)] == ["connected"]
    finally:
        receiver.stop()


def test_tls_shutdown_retries_nonblocking_read_and_write(tls_certs):
    receiver = TlsReceiver("127.0.0.1", 0, queue.Queue(), Stats(),
                           create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    sock = Mock(spec=ssl.SSLSocket)
    sock.unwrap.side_effect = [ssl.SSLWantWriteError(), ssl.SSLWantReadError(), sock]
    client = receiver_module._TcpClient(sock, ("127.0.0.1", 12345))
    clients = {sock: client}
    selector = Mock(spec=selectors.BaseSelector)

    receiver._close_after_eof(selector, clients, client)
    assert client.shutdown_deadline is not None
    assert client.events == selectors.EVENT_WRITE
    receiver._read_client(selector, clients, client)
    assert client.events == selectors.EVENT_READ
    receiver._read_client(selector, clients, client)

    assert selector.modify.call_args_list == [
        call(sock, selectors.EVENT_WRITE, client),
        call(sock, selectors.EVENT_READ, client),
    ]
    assert not clients
    selector.unregister.assert_called_once_with(sock)
    sock.close.assert_called_once_with()


def test_stalled_tls_shutdown_times_out(tls_certs, caplog):
    receiver = TlsReceiver("127.0.0.1", 0, queue.Queue(), Stats(),
                           create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    sock = Mock(spec=ssl.SSLSocket)
    client = receiver_module._TcpClient(sock, ("127.0.0.1", 12345), shutdown_deadline=0)
    clients = {sock: client}
    selector = Mock(spec=selectors.BaseSelector)

    receiver._expire_clients(selector, clients)

    assert not clients
    assert "TLS shutdown with 127.0.0.1:12345 timed out" in caplog.text
    selector.unregister.assert_called_once_with(sock)
    sock.close.assert_called_once_with()


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


def test_stopping_tls_listener_closes_pending_handshake(tls_certs, monkeypatch):
    receiver, _, stats = start_receiver(create_tls_context(tls_certs.server_cert, tls_certs.server_key))
    try:
        accepted = threading.Event()
        new_client = receiver._new_client

        def remember_client(sock, address):
            client = new_client(sock, address)
            accepted.set()
            return client

        monkeypatch.setattr(receiver, "_new_client", remember_client)
        with socket.create_connection(("127.0.0.1", receiver.bound_port), timeout=5) as client:
            assert accepted.wait(5)
            receiver.stop()
            try:
                assert client.recv(1) == b""
            except ConnectionError:
                pass
        assert stats.snapshot().tls_handshake_failures == 0
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
