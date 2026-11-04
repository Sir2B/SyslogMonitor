import queue
import socket
import time
from contextlib import ExitStack

import pytest

from syslog_monitor import receiver as receiver_module
from syslog_monitor.receiver import (
    MAX_TCP_CLIENTS, MAX_TCP_MESSAGE_BYTES, TcpFramer, TcpFramingError, TcpReceiver, UdpReceiver,
)
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


def test_framing_is_independent_of_tcp_chunk_boundaries():
    first = "<14>1 - host app - - - größe\nsecond line".encode()
    last = b"<11>last"
    wire = octet_frame(first) + b"<14>line one\r\n<14>line two\x00" + octet_frame(last)
    expected = [first, b"<14>line one", b"<14>line two", last]

    for split in range(len(wire) + 1):
        framer = TcpFramer()
        assert list(framer.feed(wire[:split])) + list(framer.feed(wire[split:])) == expected
        assert framer.finish() is None

    framer = TcpFramer()
    assert [message for byte in wire for message in framer.feed(bytes((byte,)))] == expected


def test_clean_eof_accepts_only_unterminated_line_frames():
    framer = TcpFramer()
    assert list(framer.feed(b"<14>final")) == []
    assert framer.pending
    assert framer.finish() == b"<14>final"
    assert not framer.pending

    framer = TcpFramer()
    assert list(framer.feed(b"123")) == []
    assert framer.finish() == b"123"

    for partial in (b"10 ", b"10 <14>"):
        framer = TcpFramer()
        assert list(framer.feed(partial)) == []
        with pytest.raises(TcpFramingError, match="before .* complete"):
            framer.finish()


def test_message_size_limit_includes_exact_boundary_and_crlf():
    message = b"x" * MAX_TCP_MESSAGE_BYTES
    framer = TcpFramer()
    assert list(framer.feed(message)) == []
    assert list(framer.feed(b"\r")) == []
    assert list(framer.feed(b"\n")) == [message]
    assert framer.finish() is None

    framer = TcpFramer()
    assert list(framer.feed(octet_frame(message))) == [message]

    framer = TcpFramer()
    with pytest.raises(TcpFramingError, match="size limit"):
        list(framer.feed(message + b"x\n"))

    framer = TcpFramer()
    assert list(framer.feed(message + b"\r")) == []
    with pytest.raises(TcpFramingError, match="size limit"):
        framer.finish()

    framer = TcpFramer()
    with pytest.raises(TcpFramingError, match="octet count"):
        list(framer.feed(f"{MAX_TCP_MESSAGE_BYTES + 1} ".encode()))


def test_bad_frame_does_not_discard_preceding_complete_frames():
    framer = TcpFramer()
    frames = framer.feed(b"<14>valid\n99999999999999999999 ")
    assert next(frames) == b"<14>valid"
    with pytest.raises(TcpFramingError, match="octet count"):
        next(frames)


def test_line_length_limit_also_applies_before_a_delimiter(monkeypatch):
    monkeypatch.setattr(receiver_module, "MAX_TCP_MESSAGE_BYTES", 8)
    framer = TcpFramer()
    assert list(framer.feed(b"1234")) == []
    with pytest.raises(TcpFramingError, match="size limit"):
        list(framer.feed(b"56789"))


def test_tcp_queue_overflow_is_counted():
    events = queue.Queue(maxsize=1)
    stats = Stats()
    receiver = TcpReceiver("127.0.0.1", 0, events, stats)
    receiver.start()
    try:
        with socket.create_connection(("127.0.0.1", receiver.bound_port), timeout=3) as client:
            client.sendall(b"<14>one\n<14>two\n<14>three\n")
            assert wait_for(lambda: stats.snapshot().received == 3)
        assert stats.snapshot().dropped_queue_full == 2
        assert events.get_nowait().message == "one"
    finally:
        receiver.stop()


def test_tcp_client_limit_rejects_new_connections_without_stopping_existing_clients(monkeypatch):
    monkeypatch.setattr(receiver_module, "MAX_TCP_CLIENTS", 1)
    events = queue.Queue()
    stats = Stats()
    receiver = TcpReceiver("127.0.0.1", 0, events, stats)
    receiver.start()
    try:
        with socket.create_connection(("127.0.0.1", receiver.bound_port), timeout=3) as first:
            first.sendall(b"<14>first\n")
            assert wait_for(lambda: stats.snapshot().received == 1)
            with socket.create_connection(("127.0.0.1", receiver.bound_port), timeout=3):
                assert wait_for(lambda: stats.snapshot().tcp_connections_rejected == 1)
            first.sendall(b"<14>second\n")
            assert wait_for(lambda: stats.snapshot().received == 2)
        assert [events.get_nowait().message, events.get_nowait().message] == ["first", "second"]
    finally:
        receiver.stop()


def test_actual_tcp_client_limit_on_windows_and_other_platforms():
    stats = Stats()
    receiver = TcpReceiver("127.0.0.1", 0, queue.Queue(), stats)
    receiver.start()
    try:
        with ExitStack() as stack:
            clients = [
                stack.enter_context(socket.create_connection(("127.0.0.1", receiver.bound_port), timeout=5))
                for _ in range(MAX_TCP_CLIENTS)
            ]
            clients[-1].sendall(b"<14>last accepted\n")
            assert wait_for(lambda: stats.snapshot().received == 1, timeout=15)
            stack.enter_context(socket.create_connection(("127.0.0.1", receiver.bound_port), timeout=5))
            assert wait_for(lambda: stats.snapshot().tcp_connections_rejected == 1, timeout=15)
            clients[0].sendall(b"<14>still connected\n")
            assert wait_for(lambda: stats.snapshot().received == 2, timeout=5)
    finally:
        receiver.stop()


def test_stopping_with_a_partial_tcp_message_counts_the_drop():
    stats = Stats()
    receiver = TcpReceiver("127.0.0.1", 0, queue.Queue(), stats)
    receiver.start()
    try:
        with socket.create_connection(("127.0.0.1", receiver.bound_port), timeout=3) as client:
            client.sendall(b"<14>ready\n50 <14>unfinished")
            assert wait_for(lambda: stats.snapshot().received == 1)
            receiver.stop()
        assert stats.snapshot().dropped_tcp_framing == 1
    finally:
        receiver.stop()


@pytest.mark.parametrize("receiver_type,socket_type", [
    (UdpReceiver, socket.SOCK_DGRAM), (TcpReceiver, socket.SOCK_STREAM),
])
def test_thread_start_failure_releases_bound_socket(monkeypatch, receiver_type, socket_type):
    with socket.socket(socket.AF_INET, socket_type) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    receiver = receiver_type("127.0.0.1", port, queue.Queue(), Stats())

    def fail(_thread):
        raise RuntimeError("thread unavailable")

    monkeypatch.setattr(receiver_module.threading.Thread, "start", fail)
    with pytest.raises(RuntimeError, match="thread unavailable"):
        receiver.start()
    assert not receiver.running and receiver._sock is None
    with socket.socket(socket.AF_INET, socket_type) as probe:
        probe.bind(("127.0.0.1", port))


@pytest.mark.parametrize("receiver_type,socket_type", [
    (UdpReceiver, socket.SOCK_DGRAM), (TcpReceiver, socket.SOCK_STREAM),
])
def test_receiver_can_restart_after_its_thread_exits(monkeypatch, receiver_type, socket_type):
    with socket.socket(socket.AF_INET, socket_type) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    stats = Stats()
    receiver = receiver_type("127.0.0.1", port, queue.Queue(), stats)
    original_run = receiver._run
    monkeypatch.setattr(receiver, "_run", lambda: None)
    receiver.start()
    try:
        assert wait_for(lambda: not receiver.running)
        monkeypatch.setattr(receiver, "_run", original_run)
        receiver.start()
        if socket_type == socket.SOCK_DGRAM:
            with socket.socket(socket.AF_INET, socket_type) as client:
                client.sendto(b"<14>recovered", ("127.0.0.1", port))
        else:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(b"<14>recovered\n")
                assert wait_for(lambda: stats.snapshot().received == 1)
        assert wait_for(lambda: stats.snapshot().received == 1)
    finally:
        receiver.stop()


def test_stop_timeout_is_reported_in_listener_status(caplog, monkeypatch):
    stats = Stats()
    receiver = TcpReceiver("127.0.0.1", 0, queue.Queue(), stats)
    thread = receiver_module.threading.Thread()
    monkeypatch.setattr(thread, "join", lambda timeout: None)
    monkeypatch.setattr(thread, "is_alive", lambda: True)
    receiver._thread = thread
    with pytest.raises(RuntimeError, match="TCP receiver did not stop"):
        receiver.stop()
    assert stats.snapshot().listener_state == "error"
    assert "TCP receiver did not stop" in stats.snapshot().listener_error
    assert "TCP receiver did not stop" in caplog.text
