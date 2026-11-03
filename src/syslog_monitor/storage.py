"""SQLite schema, connections, batch inserts and retention.

All writes go through a single connection owned by the writer thread. Readers
open their own connections (see :mod:`syslog_monitor.query`).
"""

from __future__ import annotations

import logging
import math
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from syslog_monitor.events import SyslogEvent

log = logging.getLogger(__name__)

DB_FILENAME = "syslog.sqlite3"
SCHEMA_VERSION = 1
DELETE_BATCH = 5000
# After exceeding the budget, delete down to this fraction to avoid churning.
BUDGET_LOW_WATERMARK = 0.9

EVENT_COLUMNS = (
    "received_at", "source_ip", "source_port", "facility", "severity", "format", "issues",
    "reported_time_text", "reported_time_utc", "hostname", "app_name", "procid", "msgid",
    "structured_data", "message", "raw",
)

_SCHEMA_V1 = """
CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    received_at INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    facility INTEGER,
    severity INTEGER,
    format TEXT NOT NULL,
    issues TEXT NOT NULL DEFAULT '',
    reported_time_text TEXT,
    reported_time_utc INTEGER,
    hostname TEXT,
    app_name TEXT,
    procid TEXT,
    msgid TEXT,
    structured_data TEXT,
    message TEXT NOT NULL,
    raw BLOB NOT NULL
);
CREATE INDEX ix_events_time ON events(received_at);
CREATE INDEX ix_events_severity_time ON events(severity, received_at);
CREATE VIRTUAL TABLE events_fts USING fts5(
    message, hostname, app_name, structured_data,
    content='events', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER events_ai AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, message, hostname, app_name, structured_data)
    VALUES (new.id, new.message, new.hostname, new.app_name, new.structured_data);
END;
CREATE TRIGGER events_ad AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, message, hostname, app_name, structured_data)
    VALUES ('delete', old.id, old.message, old.hostname, old.app_name, old.structured_data);
END;
"""

MIGRATIONS = {1: _SCHEMA_V1}


class StorageError(RuntimeError):
    pass


def db_path(data_dir: Path) -> Path:
    return data_dir / DB_FILENAME


def connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=10000")
    if readonly:
        conn.execute("PRAGMA query_only=ON")
    return conn


def check_fts5() -> None:
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE VIRTUAL TABLE t USING fts5(x)")
    except sqlite3.OperationalError as exc:
        raise StorageError("SQLite does not support FTS5; full-text search is unavailable") from exc
    finally:
        conn.close()


def open_database(data_dir: Path) -> sqlite3.Connection:
    """Create/migrate the database and return the writer connection."""
    check_fts5()
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        conn = connect(db_path(data_dir))
    except (OSError, sqlite3.Error) as exc:
        raise StorageError(f"Database in {data_dir} is unavailable: {exc}") from exc
    try:
        _configure_and_migrate(conn)
    except sqlite3.Error as exc:
        conn.close()
        raise StorageError(f"Database {db_path(data_dir)} is unavailable: {exc}") from exc
    return conn


def _configure_and_migrate(conn: sqlite3.Connection) -> None:
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version == 0:
        # Must be set before the first table exists.
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(f"PRAGMA journal_size_limit={64 * 1024 * 1024}")
    if version > SCHEMA_VERSION:
        raise sqlite3.DatabaseError(f"Database version {version} is newer than this application")
    for target in range(version + 1, SCHEMA_VERSION + 1):
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in _split_sql(MIGRATIONS[target]):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version={target}")
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        log.info("Migrated database schema to version %d", target)


def _split_sql(script: str) -> list[str]:
    """Split a script into statements, keeping trigger bodies intact."""
    statements, current = [], []
    for line in script.strip().splitlines():
        current.append(line)
        joined = "\n".join(current)
        if sqlite3.complete_statement(joined):
            statements.append(joined)
            current = []
    return statements


def event_to_row(event: SyslogEvent) -> tuple:
    return (
        event.received_at, event.source_ip, event.source_port, event.facility, event.severity,
        event.format, ",".join(event.issues), event.reported_time_text, event.reported_time_utc,
        event.hostname, event.app_name, event.procid, event.msgid, event.structured_data,
        event.message, event.raw,
    )


_INSERT_SQL = (
    f"INSERT INTO events ({', '.join(EVENT_COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in EVENT_COLUMNS)})"
)


def insert_events(conn: sqlite3.Connection, events: Iterable[SyslogEvent]) -> int:
    rows = [event_to_row(e) for e in events]
    if not rows:
        return 0
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.executemany(_INSERT_SQL, rows)
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    return len(rows)


@dataclass(frozen=True, slots=True)
class StorageUsage:
    file_bytes: int  # db + wal + shm on disk
    used_bytes: int  # pages holding data (excludes free pages)
    free_bytes: int


def storage_usage(conn: sqlite3.Connection, path: Path) -> StorageUsage:
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    free_pages = conn.execute("PRAGMA freelist_count").fetchone()[0]
    file_bytes = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            file_bytes += Path(str(path) + suffix).stat().st_size
        except FileNotFoundError:
            pass
    return StorageUsage(file_bytes, (page_count - free_pages) * page_size, free_pages * page_size)


def _delete_batch(conn: sqlite3.Connection, where: str, params: tuple, limit: int = DELETE_BATCH) -> int:
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            f"DELETE FROM events WHERE id IN "
            f"(SELECT id FROM events WHERE {where} ORDER BY received_at, id LIMIT ?)",
            (*params, limit),
        )
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    return cur.rowcount


def delete_older_than(conn: sqlite3.Connection, cutoff_ms: int) -> int:
    deleted = 0
    while (n := _delete_batch(conn, "received_at < ?", (cutoff_ms,))) > 0:
        deleted += n
    return deleted


def enforce_budget(conn: sqlite3.Connection, path: Path, budget_bytes: int) -> int:
    """Delete oldest events until used pages fit the budget; release excess free pages.

    Returns the number of deleted events.
    """
    deleted = 0
    usage = storage_usage(conn, path)
    if usage.used_bytes > budget_bytes:
        target = budget_bytes * BUDGET_LOW_WATERMARK
        while usage.used_bytes > target:
            count = conn.execute("SELECT count(*) FROM events").fetchone()[0]
            if count == 0:
                break
            # Estimate how many of the oldest rows free the excess space.
            bytes_per_row = usage.used_bytes / count
            wanted = math.ceil((usage.used_bytes - target) / bytes_per_row)
            n = _delete_batch(conn, "1", (), max(1, min(wanted, DELETE_BATCH)))
            if n == 0:
                break
            deleted += n
            usage = storage_usage(conn, path)
        log.info("Storage budget: deleted %d oldest events", deleted)
    shrink_file(conn, path, budget_bytes)
    return deleted


def shrink_file(conn: sqlite3.Connection, path: Path, budget_bytes: int) -> None:
    """Return free pages to the file system if the files exceed the budget."""
    usage = storage_usage(conn, path)
    if usage.file_bytes > budget_bytes and usage.free_bytes > 0:
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        excess_pages = (usage.file_bytes - budget_bytes) // page_size + 1
        # Python's execute() steps only once (one page); executescript runs to completion.
        conn.executescript(f"PRAGMA incremental_vacuum({int(excess_pages)});")
    checkpoint(conn)


def checkpoint(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()


class EventStore:
    """Write-side facade over the database used by :class:`EventWriter`."""

    def __init__(self, data_dir: Path) -> None:
        self.path = db_path(data_dir)
        self._conn = open_database(data_dir)

    def insert(self, events: list[SyslogEvent]) -> int:
        return insert_events(self._conn, events)

    def apply_retention(self, now_ms: int, retention_days: int, budget_bytes: int) -> int:
        cutoff = now_ms - retention_days * 86_400_000
        deleted = delete_older_than(self._conn, cutoff)
        deleted += enforce_budget(self._conn, self.path, budget_bytes)
        return deleted

    def usage(self) -> StorageUsage:
        return storage_usage(self._conn, self.path)

    def close(self) -> None:
        try:
            checkpoint(self._conn)
        except sqlite3.Error:
            log.exception("Database checkpoint failed during shutdown")
        self._conn.close()
