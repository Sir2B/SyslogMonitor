"""Load tests (opt-in): SYSLOG_MONITOR_SLOW_TESTS=1 pytest -m slow -s

Builds a 3-day equivalent at 10 msg/s (2,592,000 events) and checks that the
read paths used by the GUI stay bounded and responsive.
"""

import os
import random
import time

import pytest
from conftest import BASE_MS, send_udp

from syslog_monitor.config import Settings
from syslog_monitor.query import TEXT_MODE_SUBSTRING, EventFilter, QueryRunner
from syslog_monitor.service import CaptureService
from syslog_monitor.storage import EventStore, insert_events
from syslog_monitor.events import SyslogEvent

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not os.environ.get("SYSLOG_MONITOR_SLOW_TESTS"), reason="set SYSLOG_MONITOR_SLOW_TESTS=1"),
]

RATE = 10
DAYS = 3
TOTAL = RATE * 86_400 * DAYS
WORDS = ("link", "down", "up", "timeout", "user", "login", "failed", "disk", "temperature", "voltage",
         "service", "request", "response", "ok", "retry", "connection", "reset", "sensor", "alarm", "cleared")


def synthetic(i: int, rng: random.Random) -> SyslogEvent:
    severity = rng.choices(range(8), weights=(1, 1, 2, 10, 40, 100, 600, 246))[0]
    words = " ".join(rng.choice(WORDS) for _ in range(rng.randint(6, 14)))
    message = f"{words} id={i} value={rng.randint(0, 99999)}"
    sender = i % 350
    network = "192.0.2" if sender < 175 else "198.51.100"
    return SyslogEvent(received_at=BASE_MS + i * 1000 // RATE, source_ip=f"{network}.{sender % 175 + 1}",
                       source_port=514, raw=message.encode(), message=message, format="rfc5424",
                       severity=severity, facility=rng.choice((1, 3, 16, 23)),
                       hostname=f"dev{i % 50}", app_name=rng.choice(("sshd", "kernel", "worker", "web")))


@pytest.fixture(scope="module")
def big_db(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("big")
    store = EventStore(data_dir)
    rng = random.Random(42)
    started = time.perf_counter()
    batch = 5000
    for start in range(0, TOTAL, batch):
        insert_events(store._conn, [synthetic(i, rng) for i in range(start, start + batch)])
    elapsed = time.perf_counter() - started
    usage = store.usage()
    print(f"\ninsert {TOTAL:,} events: {elapsed:.0f}s ({TOTAL / elapsed:,.0f}/s); "
          f"files {usage.file_bytes / 2**20:,.0f} MiB = {usage.file_bytes / TOTAL:.0f} B/event")
    yield store
    store.close()


def timed(label, func, limit_s):
    started = time.perf_counter()
    result = func()
    elapsed = time.perf_counter() - started
    print(f"{label}: {elapsed * 1000:.0f} ms")
    assert elapsed < limit_s, f"{label} took {elapsed:.2f}s"
    return result


def test_gui_queries_stay_responsive(big_db):
    q = QueryRunner(big_db.path)
    end = BASE_MS + TOTAL * 1000 // RATE
    day_filter = EventFilter(start_ms=end - 86_400_000)
    head = timed("head page", lambda: q.fetch_older(day_filter, None, 501), 0.5)
    assert len(head) == 501
    timed("next page", lambda: q.fetch_older(day_filter, head[-1].cursor, 501), 0.5)
    timed("errors only page", lambda: q.fetch_older(EventFilter(severities=frozenset({0, 1, 2, 3})), None, 501), 1.0)
    timed("word search page", lambda: q.fetch_older(EventFilter(text="temperature alarm"), None, 501), 5.0)
    timed("rare word page", lambda: q.fetch_older(EventFilter(text="id=1234567"), None, 501), 2.0)
    timed("substring page (24h)", lambda: q.fetch_older(EventFilter(
        start_ms=end - 86_400_000, text="value=4242", text_mode=TEXT_MODE_SUBSTRING), None, 501), 10.0)
    timed("jump (around)", lambda: q.fetch_around(EventFilter(), BASE_MS + 86_400_000, 501, 251), 0.5)
    hist = timed("histogram 24h", lambda: q.histogram(EventFilter(), end - 86_400_000, end, 600), 5.0)
    assert hist.total == RATE * 86_400
    timed("histogram all (3 days)", lambda: q.histogram(EventFilter(), BASE_MS, end, 600), 15.0)
    timed("histogram errors 24h", lambda: q.histogram(
        EventFilter(severities=frozenset({0, 1, 2, 3})), end - 86_400_000, end, 600), 5.0)
    q.close()


def test_retention_of_one_day(big_db):
    end = BASE_MS + TOTAL * 1000 // RATE
    deleted = timed("retention delete 1 day", lambda: big_db.apply_retention(end, DAYS - 1, 2**40), 300)
    assert deleted == RATE * 86_400
    assert QueryRunner(big_db.path).fetch_older(EventFilter(text="link"), None, 1)


def test_live_rate_over_udp(tmp_path):
    svc = CaptureService(tmp_path, Settings(bind_host="127.0.0.1", port=0))
    svc.start_listener()
    seconds, sent = 20, 0
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        send_udp(svc.bound_port, *[f"<14>1 - h app - - - tick {sent + i}".encode() for i in range(RATE)])
        sent += RATE
        time.sleep(1)
    assert svc.flush(10)
    snap = svc.snapshot()
    svc.shutdown()
    print(f"udp live: sent {sent}, persisted {snap.persisted}, max queue {snap.queued}")
    assert snap.persisted == sent and snap.dropped_queue_full == 0
