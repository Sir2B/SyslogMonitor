import queue
import sqlite3
import threading
import time

from conftest import make_event

from syslog_monitor.stats import Stats
from syslog_monitor.storage import StorageUsage
from syslog_monitor.writer import EventWriter, RetentionPolicy, WriterTuning

FAST = WriterTuning(batch_max=50, flush_interval_s=0.05, retry_delays_s=(0.01, 0.01),
                    maintenance_interval_s=3600, usage_interval_s=0.05)
POLICY = RetentionPolicy(30, 2**30)


class FakeStore:
    def __init__(self, fail_times=0, usage_bytes=100):
        self.inserted = []
        self.fail_times = fail_times
        self.retention_calls = []
        self.usage_bytes = usage_bytes
        self.closed = False
        self.lock = threading.Lock()

    def insert(self, events):
        with self.lock:
            if self.fail_times:
                self.fail_times -= 1
                raise sqlite3.OperationalError("database or disk is full")
            self.inserted += events
        return len(events)

    def apply_retention(self, now_ms, days, budget, archive_budget=0):
        self.retention_calls.append((days, budget))
        return 3

    def usage(self):
        return StorageUsage(self.usage_bytes, self.usage_bytes, 0)

    def close(self):
        self.closed = True


def run_writer(store, events, policy=POLICY):
    q, stats = queue.Queue(), Stats()
    writer = EventWriter(q, store, stats, policy, FAST)
    writer.start()
    for ev in events:
        q.put(ev)
    assert writer.flush(5)
    return writer, stats


def test_writes_all_in_order_and_stops_cleanly():
    store = FakeStore()
    writer, stats = run_writer(store, [make_event(i) for i in range(120)])
    writer.stop()
    assert [e.received_at for e in store.inserted] == [make_event(i).received_at for i in range(120)]
    snap = stats.snapshot()
    assert snap.persisted == 120 and snap.write_failures == 0
    assert store.closed
    assert store.retention_calls == [(30, 2**30)]
    assert snap.retention_deleted == 3


def test_transient_failure_is_retried():
    store = FakeStore(fail_times=2)
    writer, stats = run_writer(store, [make_event(0)])
    writer.stop()
    snap = stats.snapshot()
    assert len(store.inserted) == 1 and snap.persisted == 1
    assert snap.write_failures == 2 and snap.writer_error == ""


def test_persistent_failure_drops_and_counts():
    store = FakeStore(fail_times=100)
    writer, stats = run_writer(store, [make_event(0), make_event(1)])
    snap = stats.snapshot()
    assert snap.persisted == 0 and snap.dropped_write_error == 2
    assert "disk is full" in snap.writer_error
    writer.stop()


def test_stop_drains_queue():
    store = FakeStore()
    q, stats = queue.Queue(), Stats()
    writer = EventWriter(q, store, stats, POLICY, FAST)
    for i in range(300):
        q.put(make_event(i))
    writer.start()
    writer.stop()
    assert len(store.inserted) == 300


def test_policy_change_triggers_maintenance_and_usage_flag():
    store = FakeStore(usage_bytes=500)
    writer, stats = run_writer(store, [], policy=RetentionPolicy(30, 1000))
    writer.set_policy(RetentionPolicy(7, 400))
    q_wait = threading.Event()
    for _ in range(100):
        if store.retention_calls[-1:] == [(7, 400)] and stats.snapshot().storage_budget_exceeded:
            break
        q_wait.wait(0.02)
    writer.stop()
    assert store.retention_calls[-1] == (7, 400)
    assert stats.snapshot().storage_budget_exceeded


def test_usage_is_reported_before_slow_first_maintenance_and_warns_near_archive_budget():
    import threading as _t
    from syslog_monitor.ui import status_text

    release = _t.Event()

    class SlowStore(FakeStore):
        def apply_retention(self, *args):
            release.wait(5)
            return 0

        def usage(self):
            return StorageUsage(1000, 1000, 0, archive_bytes=950, archive_oldest_end_ms=BASE)

    store = SlowStore()
    stats = Stats()
    writer = EventWriter(queue.Queue(), store, stats, RetentionPolicy(30, 2**30, 1000))
    writer.start()
    try:
        deadline = time.monotonic() + 5
        while stats.snapshot().storage_bytes != 1000 and time.monotonic() < deadline:
            time.sleep(0.01)
        snap = stats.snapshot()
        assert snap.storage_bytes == 1000 and snap.archive_expiring_ms == BASE
        assert "⏳" in status_text.storage(snap, 2**30, 1000)
        assert status_text.storage_tooltip(snap)
    finally:
        release.set()
        writer.stop()


BASE = 1_700_000_000_000
