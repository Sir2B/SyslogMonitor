"""Importing exported files, syslog server logs and plain syslog lines."""

from datetime import datetime
from threading import Event

import pytest

from syslog_monitor.export import EXPORT_COLUMNS, ExportOptions, export_events
from syslog_monitor.importer import (
    FORMAT_CSV, FORMAT_JSONL, FORMAT_LINES, FORMAT_TABBED, ImportCancelled, import_file, preview, read_events,
)
from syslog_monitor.parser import parse_datagram
from syslog_monitor.query import EventFilter
from syslog_monitor.storage import connect, db_path, insert_events, open_database

NOW = int(datetime(2026, 11, 10, 18, 0).astimezone().timestamp() * 1000)
TABBED = (
    "192.0.2.10\tNov 10 07:46:01\t1\tauth\tinfo\t\t2026-09-26T16:47:14.448+00:00 device1 webd 139 - "
    "[meta sequenceId=\"893\"] User 'admin' changed setting 'output/1' to '0'. \n"
    "192.0.2.10\tNov 10 07:46:02\t1\tauth\terr\t\t2026-09-26T16:47:15.469+00:00 device1 webd 139 - - failed\n"
)


@pytest.fixture
def database(tmp_path):
    open_database(tmp_path / "data").close()
    return db_path(tmp_path / "data")


def rows(path):
    conn = connect(path, readonly=True)
    try:
        return conn.execute(
            "SELECT received_at, source_ip, facility, severity, format, hostname, app_name, "
            "procid, structured_data, message, raw FROM events ORDER BY id").fetchall()
    finally:
        conn.close()


def test_tab_separated_server_log(tmp_path, database):
    source = tmp_path / "syslog"
    source.write_text(TABBED, encoding="utf-8")
    result = import_file(database, source, now_ms=NOW)
    assert (result.rows, result.format) == (2, FORMAT_TABBED)
    first, second = rows(database)
    assert first[0] == int(datetime(2026, 11, 10, 7, 46, 1).astimezone().timestamp() * 1000)
    assert first[1:9] == ("192.0.2.10", 4, 6, "rfc5424", "device1", "webd", "139",
                          '[meta sequenceId="893"]')
    assert first[9].startswith("User 'admin' changed setting")
    assert second[3] == 3


def test_year_is_inferred_from_the_past(tmp_path):
    source = tmp_path / "syslog"
    source.write_text(TABBED.replace("Nov 10", "Dec 31"), encoding="utf-8")
    _kind, events = read_events(source, NOW)
    assert datetime.fromtimestamp(next(events).received_at / 1000).year == 2025


def test_plain_lines_with_and_without_pri(tmp_path, database):
    source = tmp_path / "messages.log"
    source.write_text("<34>Oct 11 22:14:15 mymachine su: 'su root' failed\n\n"
                      "Nov 10 07:46:01 host app[12]: hello\nfree text\n", encoding="utf-8")
    result = import_file(database, source, now_ms=NOW)
    assert (result.rows, result.format) == (3, FORMAT_LINES)
    pri, plain, free = rows(database)
    assert pri[1:4] == ("mymachine", 4, 2) and pri[9] == "'su root' failed"
    assert plain[1:4] == ("host", None, None) and plain[6:8] == ("app", "12")
    assert plain[10] == b"Nov 10 07:46:01 host app[12]: hello"
    assert free[1] == "import" and free[0] == NOW and free[9] == "free text"


@pytest.mark.parametrize("fmt", ["csv", "jsonl"])
@pytest.mark.parametrize("with_raw", [False, True])
def test_export_round_trip(tmp_path, database, fmt, with_raw):
    datagram = b"<165>1 2026-11-10T10:00:00Z router app 42 ID7 [x a=\"1\"] =SUM(A1) caf\xc3\xa9"
    conn = connect(database)
    insert_events(conn, [parse_datagram(datagram, "10.0.0.1", 514, NOW - 1000)])
    conn.close()
    columns = EXPORT_COLUMNS if with_raw else tuple(c for c in EXPORT_COLUMNS if c != "raw_base64")
    exported = tmp_path / f"export.{fmt}"
    export_events(database, exported, ExportOptions(
        "custom", fmt, EventFilter().with_time(NOW - 10_000, NOW), columns=columns), now_ms=NOW)
    target_dir = tmp_path / "other"
    open_database(target_dir).close()
    result = import_file(db_path(target_dir), exported, now_ms=NOW)
    assert (result.rows, result.format) == (1, FORMAT_CSV if fmt == "csv" else FORMAT_JSONL)
    assert rows(db_path(target_dir))[0][:10] == rows(database)[0][:10]
    if with_raw:
        assert rows(db_path(target_dir))[0][10] == datagram


def test_cancel_keeps_written_batches(tmp_path, database, monkeypatch):
    monkeypatch.setattr("syslog_monitor.importer.BATCH_SIZE", 2)
    source = tmp_path / "messages.log"
    source.write_text("".join(f"line {i}\n" for i in range(5)), encoding="utf-8")
    cancel = Event()
    with pytest.raises(ImportCancelled):
        import_file(database, source, now_ms=NOW, cancel=cancel, progress=lambda _count: cancel.set())
    assert len(rows(database)) == 2

def test_preview_shows_first_events_and_honours_forced_format(tmp_path):
    source = tmp_path / "syslog"
    source.write_text(TABBED * 15, encoding="utf-8")
    kind, events = preview(source, NOW)
    assert kind == FORMAT_TABBED and len(events) == 20 and events[0].hostname == "device1"
    kind, events = preview(source, NOW, FORMAT_LINES, limit=1)
    assert kind == FORMAT_LINES and events[0].facility is None
