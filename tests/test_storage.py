import sqlite3

import pytest
from conftest import BASE_MS, make_event

from syslog_monitor.query import EventFilter, QueryRunner
from syslog_monitor.storage import SCHEMA_VERSION, EventStore, StorageError, storage_usage


def fts_count(store, word):
    conn = sqlite3.connect(store.path)
    try:
        return conn.execute("SELECT count(*) FROM events_fts WHERE events_fts MATCH ?", (word,)).fetchone()[0]
    finally:
        conn.close()


def test_schema_created_with_wal_and_version(store):
    conn = sqlite3.connect(store.path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # incremental
    conn.close()


def test_data_survives_reopen(tmp_path):
    s = EventStore(tmp_path)
    s.insert([make_event(i) for i in range(5)])
    s.close()
    s = EventStore(tmp_path)
    assert len(QueryRunner(s.path).fetch_older(EventFilter(), None, 10)) == 5
    s.close()


def test_unusable_data_dir(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(StorageError):
        EventStore(blocker)


def test_newer_schema_is_rejected(tmp_path):
    EventStore(tmp_path).close()
    conn = sqlite3.connect(tmp_path / "syslog.sqlite3")
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(StorageError):
        EventStore(tmp_path)


def test_retention_by_age_keeps_fts_consistent(store):
    day = 86_400_000
    store.insert([make_event(-40 * day, message="ancient"), make_event(-10 * day, message="recent"),
                  make_event(0, message="now")])
    deleted = store.apply_retention(BASE_MS, retention_days=30, budget_bytes=10 * 2**30)
    assert deleted == 1
    assert fts_count(store, "ancient") == 0
    assert fts_count(store, "recent") == 1
    rows = QueryRunner(store.path).fetch_older(EventFilter(), None, 10)
    assert [r.message for r in rows] == ["now", "recent"]


def test_budget_deletes_oldest_and_bounds_files(store):
    payload = "x" * 2000
    for chunk in range(10):
        store.insert([make_event(chunk * 1000 + i, message=f"{payload} n{chunk}_{i}") for i in range(500)])
    before = storage_usage(store._conn, store.path)
    budget = before.used_bytes // 2
    deleted = store.apply_retention(BASE_MS, retention_days=3650, budget_bytes=budget)
    assert deleted > 0
    assert deleted < 5000 * 0.8, "only roughly the excess may be deleted"
    after = storage_usage(store._conn, store.path)
    assert after.used_bytes <= budget
    assert after.file_bytes <= budget  # free pages released, WAL truncated
    q = QueryRunner(store.path)
    oldest_left = q.fetch_older(EventFilter(), None, 10_000)[-1]
    assert oldest_left.received_at >= BASE_MS + (deleted // 500) * 1000 - 1000
    assert fts_count(store, "n0_0") == 0
    assert fts_count(store, "n9_499") == 1


def test_retention_noop_when_within_limits(store):
    store.insert([make_event(0)])
    assert store.apply_retention(BASE_MS, 30, 2**30) == 0
