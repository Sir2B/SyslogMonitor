import socket
import time
from dataclasses import replace

from conftest import send_udp

from syslog_monitor import receiver as receiver_module
from syslog_monitor.config import Settings
from syslog_monitor.query import EventFilter, QueryRunner
from syslog_monitor.receiver import MAX_TCP_MESSAGE_BYTES
from syslog_monitor.service import CaptureService
from syslog_monitor.writer import WriterTuning

FAST = WriterTuning(flush_interval_s=0.05)


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def make_service(tmp_path, **settings):
    return CaptureService(tmp_path, Settings(bind_host="127.0.0.1", port=0, **settings), tuning=FAST)


def test_udp_end_to_end_and_restart_persistence(tmp_path):
    svc = make_service(tmp_path)
    assert svc.start_listener()
    port = svc.bound_port
    payloads = [f"<11>1 - host app - - - message {i}".encode() for i in range(200)]
    send_udp(port, *payloads, b"\xff not syslog")
    assert wait_for(lambda: svc.snapshot().received == 201)
    assert svc.flush()
    snap = svc.snapshot()
    assert snap.persisted == 201 and snap.dropped_queue_full == 0
    assert snap.parse_issues == 1
    assert snap.listener_state == "running"
    svc.shutdown()
    assert svc.snapshot().listener_state == "stopped"

    svc2 = make_service(tmp_path)
    rows = QueryRunner(svc2.db_path).fetch_older(EventFilter(), None, 1000)
    assert len(rows) == 201
    assert {r.message for r in rows} >= {"message 0", "message 199"}
    assert rows[0].source_ip == "127.0.0.1"
    svc2.shutdown()


def test_port_in_use_reports_error_and_recovers(tmp_path):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind(("127.0.0.1", 0))
    busy_port = blocker.getsockname()[1]
    svc = CaptureService(tmp_path, Settings(bind_host="127.0.0.1", port=busy_port), tuning=FAST)
    try:
        assert not svc.start_listener()
        snap = svc.snapshot()
        assert snap.listener_state == "error" and str(busy_port) in snap.listener_error
        assert svc.apply_settings(Settings(bind_host="127.0.0.1", port=0))
        assert svc.listening and svc.snapshot().listener_state == "running"
    finally:
        blocker.close()
        svc.shutdown()


def test_queue_overflow_is_counted(tmp_path):
    svc = CaptureService(tmp_path, Settings(bind_host="127.0.0.1", port=0), queue_size=1,
                         tuning=WriterTuning(flush_interval_s=2.0, batch_max=1))
    svc._writer._stop.set()  # writer idles: events pile up in the queue
    svc._writer._thread.join()
    svc.start_listener()
    send_udp(svc.bound_port, *[b"<14>x"] * 20)
    assert wait_for(lambda: svc.snapshot().received == 20)
    snap = svc.snapshot()
    assert snap.dropped_queue_full == 19 and snap.queued == 1
    svc.stop_listener()


def test_stop_and_restart_listener(tmp_path):
    svc = make_service(tmp_path)
    try:
        svc.start_listener()
        svc.stop_listener()
        assert not svc.listening and svc.bound_port is None
        assert svc.start_listener()
        send_udp(svc.bound_port, b"<14>again")
        assert wait_for(lambda: svc.snapshot().received == 1)
    finally:
        svc.shutdown()


def test_udp_and_tcp_receive_concurrent_clients_and_persist_messages(tmp_path):
    svc = make_service(tmp_path, tcp_enabled=True, tcp_port=0)
    assert svc.start_listener()
    ports = svc.bound_ports
    try:
        assert set(ports) == {"UDP", "TCP"}
        snap = svc.snapshot()
        assert snap.listener_address == f"127.0.0.1:{ports['UDP']}"
        assert snap.listener_display_address == (
            f"UDP 127.0.0.1:{ports['UDP']}, TCP 127.0.0.1:{ports['TCP']}")
        with (socket.create_connection(("127.0.0.1", ports["TCP"]), timeout=3) as first,
              socket.create_connection(("127.0.0.1", ports["TCP"]), timeout=3) as second):
            first_port = first.getsockname()[1]
            second_port = second.getsockname()[1]
            first.sendall(b"<14>partial")
            message = "<11>1 - host app - - - längere\nNachricht".encode()
            frame = str(len(message)).encode() + b" " + message
            second.sendall(frame[:2])
            send_udp(ports["UDP"], b"<14>udp message")
            second.sendall(frame[2:])
            assert wait_for(lambda: svc.snapshot().received == 2)

            first.sendall(b" line\r\n<14>nul-delimited\x00<14>final line")
            first.shutdown(socket.SHUT_WR)
            second.sendall(b"30 <14>incomplete")
            second.shutdown(socket.SHUT_WR)
            assert wait_for(lambda: svc.snapshot().received == 5
                            and svc.snapshot().dropped_tcp_framing == 1)

        assert svc.flush()
        runner = QueryRunner(svc.db_path)
        try:
            rows = runner.fetch_older(EventFilter(), None, 100)
            by_message = {row.message: row for row in rows}
            assert set(by_message) == {"udp message", "längere\nNachricht", "partial line",
                                       "nul-delimited", "final line"}
            tcp_event = runner.get_event(by_message["längere\nNachricht"].id)
            assert tcp_event.source_port == second_port
            assert runner.get_event(by_message["partial line"].id).source_port == first_port
            assert all(row.source_ip == "127.0.0.1" for row in rows)
            assert tcp_event.raw == message
        finally:
            runner.close()
    finally:
        svc.shutdown()


def test_tcp_bind_failure_keeps_udp_running_and_retry_recovers(tmp_path):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    busy_port = blocker.getsockname()[1]
    svc = make_service(tmp_path, tcp_enabled=True, tcp_port=busy_port)
    try:
        assert not svc.start_listener()
        udp_port = svc.bound_ports["UDP"]
        snap = svc.snapshot()
        assert svc.listening and snap.listener_state == "error"
        assert "TCP port" in snap.listener_error and str(busy_port) in snap.listener_error
        assert f"127.0.0.1:{udp_port}" == snap.listener_address
        assert f"UDP 127.0.0.1:{udp_port}" == snap.listener_display_address
        send_udp(udp_port, b"<14>udp still running")
        assert wait_for(lambda: svc.snapshot().received == 1)

        blocker.close()
        assert svc.start_listener()
        assert svc.bound_ports == {"UDP": udp_port, "TCP": busy_port}
        assert svc.snapshot().listener_state == "running"
        with socket.create_connection(("127.0.0.1", busy_port), timeout=3) as client:
            client.sendall(b"<14>tcp recovered\n")
            assert wait_for(lambda: svc.snapshot().received == 2)
    finally:
        blocker.close()
        svc.shutdown()


def test_udp_bind_failure_keeps_tcp_running_and_retry_recovers(tmp_path):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind(("127.0.0.1", 0))
    busy_port = blocker.getsockname()[1]
    settings = Settings(bind_host="127.0.0.1", port=busy_port, tcp_enabled=True, tcp_port=0)
    svc = CaptureService(tmp_path, settings, tuning=FAST)
    try:
        assert not svc.start_listener()
        tcp_port = svc.bound_ports["TCP"]
        assert "UDP port" in svc.snapshot().listener_error
        with socket.create_connection(("127.0.0.1", tcp_port), timeout=3) as client:
            client.sendall(b"<14>tcp still running\n")
            assert wait_for(lambda: svc.snapshot().received == 1)

        blocker.close()
        assert svc.start_listener()
        assert svc.bound_ports == {"TCP": tcp_port, "UDP": busy_port}
        assert svc.snapshot().listener_address == f"127.0.0.1:{busy_port}"
        send_udp(busy_port, b"<14>udp recovered")
        assert wait_for(lambda: svc.snapshot().received == 2)
    finally:
        blocker.close()
        svc.shutdown()


def test_udp_and_tcp_can_listen_on_the_same_port_number(tmp_path):
    with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_probe,
          socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_probe):
        tcp_probe.bind(("127.0.0.1", 0))
        port = tcp_probe.getsockname()[1]
        udp_probe.bind(("127.0.0.1", port))
    settings = Settings(bind_host="127.0.0.1", port=port, tcp_enabled=True, tcp_port=port)
    svc = CaptureService(tmp_path, settings, tuning=FAST)
    try:
        assert svc.start_listener()
        assert svc.bound_ports == {"UDP": port, "TCP": port}
        send_udp(port, b"<14>udp")
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(b"<14>tcp\n")
            assert wait_for(lambda: svc.snapshot().received == 2)
    finally:
        svc.shutdown()


def test_settings_reconfigure_only_changed_listeners_and_respect_stopped_state(tmp_path):
    settings = Settings(bind_host="127.0.0.1", port=0)
    svc = CaptureService(tmp_path, settings, tuning=FAST)
    try:
        assert svc.start_listener()
        udp_port = svc.bound_ports["UDP"]
        both = replace(settings, tcp_enabled=True, tcp_port=0)
        assert svc.apply_settings(both)
        assert svc.bound_ports["UDP"] == udp_port
        tcp_port = svc.bound_ports["TCP"]

        tcp_only = replace(both, udp_enabled=False)
        assert svc.apply_settings(tcp_only)
        assert svc.bound_ports == {"TCP": tcp_port}
        with socket.create_connection(("127.0.0.1", tcp_port), timeout=3) as client:
            client.sendall(b"<14>tcp only\n")
            assert wait_for(lambda: svc.snapshot().received == 1)

        svc.stop_listener()
        assert svc.apply_settings(both)
        assert not svc.listening and svc.bound_ports == {}
    finally:
        svc.shutdown()


def test_changing_tcp_port_does_not_restart_udp(tmp_path):
    settings = Settings(bind_host="127.0.0.1", port=0, tcp_enabled=True, tcp_port=0)
    svc = CaptureService(tmp_path, settings, tuning=FAST)
    assert svc.start_listener()
    try:
        udp_port = svc.bound_ports["UDP"]
        old_tcp_port = svc.bound_ports["TCP"]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            new_tcp_port = probe.getsockname()[1]
        with socket.create_connection(("127.0.0.1", old_tcp_port), timeout=3) as old_client:
            old_client.sendall(b"<14>before\n")
            assert wait_for(lambda: svc.snapshot().received == 1)
            assert svc.apply_settings(replace(settings, tcp_port=new_tcp_port))
            assert svc.bound_ports == {"UDP": udp_port, "TCP": new_tcp_port}
            old_client.settimeout(3)
            try:
                assert old_client.recv(1) == b""
            except ConnectionResetError:
                pass
        send_udp(udp_port, b"<14>udp unchanged")
        with socket.create_connection(("127.0.0.1", new_tcp_port), timeout=3) as client:
            client.sendall(b"<14>after\n")
            assert wait_for(lambda: svc.snapshot().received == 3)
    finally:
        svc.shutdown()


def test_tcp_thread_start_failure_is_reported_without_stopping_udp(tmp_path, monkeypatch):
    svc = make_service(tmp_path, tcp_enabled=True, tcp_port=0)

    def fail(_receiver):
        raise RuntimeError("thread unavailable")

    monkeypatch.setattr(receiver_module.TcpReceiver, "start", fail)
    try:
        assert not svc.start_listener()
        assert "Could not start TCP listener: thread unavailable" in svc.snapshot().listener_error
        assert set(svc.bound_ports) == {"UDP"}
        send_udp(svc.bound_ports["UDP"], b"<14>udp remains active")
        assert wait_for(lambda: svc.snapshot().received == 1)
    finally:
        svc.shutdown()


def test_tcp_loop_failure_is_visible_and_can_be_retried(tmp_path, monkeypatch):
    class BrokenSelector:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def register(self, *_):
            pass

        def select(self, _timeout):
            raise OSError("selector unavailable")

    svc = make_service(tmp_path, tcp_enabled=True, tcp_port=0)
    original_selector = receiver_module.selectors.DefaultSelector
    monkeypatch.setattr(receiver_module.selectors, "DefaultSelector", BrokenSelector)
    try:
        svc.start_listener()
        assert wait_for(lambda: svc.snapshot().listener_state == "error" and set(svc.bound_ports) == {"UDP"})
        assert "TCP" in svc.snapshot().listener_error
        assert set(svc.bound_ports) == {"UDP"}
        udp_port = svc.bound_ports["UDP"]
        monkeypatch.setattr(receiver_module.selectors, "DefaultSelector", original_selector)
        assert svc.start_listener()
        assert svc.bound_ports["UDP"] == udp_port and "TCP" in svc.bound_ports
        assert svc.snapshot().listener_state == "running"
    finally:
        svc.shutdown()


def test_tcp_only_can_stop_and_restart_with_an_active_client(tmp_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    settings = Settings(bind_host="127.0.0.1", udp_enabled=False, tcp_enabled=True, tcp_port=port)
    svc = CaptureService(tmp_path, settings, tuning=FAST)
    try:
        assert svc.start_listener()
        assert svc.bound_port == port and svc.bound_ports == {"TCP": port}
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(b"<14>before restart\n")
            assert wait_for(lambda: svc.snapshot().received == 1)
            svc.stop_listener()
            assert not svc.listening
            assert svc.start_listener(), svc.snapshot().listener_error
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(b"<14>after restart\n")
            assert wait_for(lambda: svc.snapshot().received == 2)
    finally:
        svc.shutdown()


def test_tcp_rejects_oversized_frames_but_keeps_listener_running(tmp_path):
    svc = make_service(tmp_path, udp_enabled=False, tcp_enabled=True, tcp_port=0)
    assert svc.start_listener()
    try:
        port = svc.bound_port
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(b"<14>before\n" + f"{MAX_TCP_MESSAGE_BYTES + 1} ".encode())
            assert wait_for(lambda: svc.snapshot().received == 1
                            and svc.snapshot().dropped_tcp_framing == 1)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
            client.sendall(b"<14>after\n")
            assert wait_for(lambda: svc.snapshot().received == 2)
        assert svc.listening and svc.snapshot().listener_state == "running"
    finally:
        svc.shutdown()


def test_bad_timestamps_do_not_stop_either_listener(tmp_path):
    svc = make_service(tmp_path, tcp_enabled=True, tcp_port=0)
    assert svc.start_listener()
    try:
        ports = svc.bound_ports
        send_udp(ports["UDP"], b"<14>1 9999-12-31T23:59:59-23:59 h app - - - udp")
        with socket.create_connection(("127.0.0.1", ports["TCP"]), timeout=3) as client:
            client.sendall(b"<14>1 0001-01-01T00:00:00+23:59 h app - - - tcp\n"
                           b"<14>1 - h app - - - still running\n")
            assert wait_for(lambda: svc.snapshot().received == 3)
        assert svc.snapshot().parse_issues == 2
        assert svc.snapshot().listener_state == "running"
        assert set(svc.bound_ports) == {"UDP", "TCP"}
        assert svc.flush()
    finally:
        svc.shutdown()


def test_maximum_sized_tcp_message_is_stored_without_truncation(tmp_path):
    svc = make_service(tmp_path, udp_enabled=False, tcp_enabled=True, tcp_port=0)
    assert svc.start_listener()
    try:
        header = b"<14>1 - host app - - - "
        message = header + b"x" * (MAX_TCP_MESSAGE_BYTES - len(header))
        with socket.create_connection(("127.0.0.1", svc.bound_port), timeout=5) as client:
            client.sendall(str(len(message)).encode() + b" " + message)
            assert wait_for(lambda: svc.snapshot().received == 1, timeout=10)
        assert svc.flush(timeout=15)
        runner = QueryRunner(svc.db_path)
        try:
            rows = runner.fetch_older(EventFilter(), None, 1)
            assert len(rows) == 1
            assert runner.get_event(rows[0].id).raw == message
        finally:
            runner.close()
    finally:
        svc.shutdown()
