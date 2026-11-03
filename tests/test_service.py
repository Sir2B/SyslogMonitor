import socket
import time

from conftest import send_udp

from syslog_monitor.config import Settings
from syslog_monitor.query import EventFilter, QueryRunner
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
