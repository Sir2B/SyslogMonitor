import base64
import csv
import json
from threading import Event

import pytest
from conftest import BASE_MS, make_event

from syslog_monitor.export import (
    BATCH_SIZE, DEFAULT_EXPORT_COLUMNS, EXPORT_COLUMNS, ExportCancelled, ExportOptions, export_events,
)
from syslog_monitor.query import EventFilter, FilterRule
from syslog_monitor.storage import db_path


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_default_columns_are_compact_log_fields():
    assert ExportOptions().columns == (
        "received_at", "facility", "severity", "hostname", "app_name", "message",
    )


def run_export(store, tmp_path, options=ExportOptions(format="jsonl"), **kwargs):
    output = tmp_path / f"export.{options.format}"
    result = export_events(db_path(tmp_path), output, options, now_ms=BASE_MS + 100_000, **kwargs)
    return result, output


def test_last_reboot_per_device_with_exact_tie_boundary(store, tmp_path):
    store.insert([
        make_event(0, message="Initializing system"),
        make_event(10, message="old session"),
        make_event(20, message="before boot, same timestamp"),
        make_event(20, message="INITIALIZING SYSTEM again"),
        make_event(20, message="after boot, same timestamp"),
        make_event(5, source_ip="192.0.2.2", message="Initializing system"),
        make_event(15, source_ip="192.0.2.2", message="second device"),
        make_event(30, source_ip="192.0.2.3", message="no boot marker"),
        make_event(200_000, message="Initializing system in future"),
    ])
    result, output = run_export(store, tmp_path)
    assert result.rows == 4
    assert result.skipped_devices == 1
    rows = read_jsonl(output)
    assert [row["message"] for row in rows] == [
        "Initializing system", "second device", "INITIALIZING SYSTEM again", "after boot, same timestamp"]
    assert "source_ip" not in rows[0]


def test_boot_lookup_is_independent_of_export_filters(store, tmp_path):
    store.insert([make_event(0, message="Startup", severity=6),
                  make_event(1, message="error", severity=3),
                  make_event(2, message="info", severity=6)])
    result, output = run_export(
        store, tmp_path, ExportOptions(format="jsonl", boot_marker="missing;Startup",
                                       filters=EventFilter(severities=frozenset({3}))))
    assert result.rows == 1
    assert read_jsonl(output)[0]["message"] == "error"


def test_boot_marker_is_literal_and_missing_marker_does_not_replace_destination(store, tmp_path):
    store.insert([make_event(0, message="bootXYZ"), make_event(1, message="hello")])
    output = tmp_path / "existing.csv"
    output.write_text("keep me", encoding="utf-8")
    with pytest.raises(ValueError, match="No stored boot marker"):
        export_events(db_path(tmp_path), output, ExportOptions(boot_marker="boot%"),
                      now_ms=BASE_MS + 100)
    assert output.read_text() == "keep me"
    assert not list(tmp_path.glob(".*.tmp"))


def test_last_24h_boundaries_and_no_page_limit(store, tmp_path):
    now = BASE_MS + 86_400_000
    store.insert([make_event(-1), make_event(0, message="start"),
                  *(make_event(i + 1) for i in range(6000)),
                  make_event(86_400_000, message="now"),
                  make_event(86_400_001, message="future")])
    output = tmp_path / "day.jsonl"
    progress = []
    result = export_events(db_path(tmp_path), output, ExportOptions(period="24h", format="jsonl"),
                           now_ms=now, progress=progress.append)
    rows = read_jsonl(output)
    assert result.rows == len(rows) == 6002
    assert rows[0]["message"] == "start"
    assert rows[-1]["message"] == "now"
    assert progress[-1] == result.rows
    assert all(0 < right - left <= BATCH_SIZE for left, right in zip([0, *progress], progress))


def test_custom_range_filters_and_jsonl_lossless_fields(store, tmp_path):
    event = make_event(1, message='Grüße, "world"\n=SUM(A1)\t', severity=None, facility=None)
    event.raw = b"\xff\x00\r\n"
    event.reported_time_utc = BASE_MS
    event.structured_data = '[meta note="test"]'
    store.insert([make_event(0), event, make_event(2)])
    options = ExportOptions(
        period="custom", format="jsonl", columns=EXPORT_COLUMNS,
        filters=EventFilter(start_ms=BASE_MS + 1, end_ms=BASE_MS + 2,
                            rules=(FilterRule("sender", "equals", event.source_ip),)))
    result, output = run_export(store, tmp_path, options)
    assert result.rows == 1
    row = read_jsonl(output)[0]
    assert tuple(row) == EXPORT_COLUMNS
    assert row["message"] == event.message
    assert row["severity"] is None and row["facility"] is None
    assert row["structured_data"] == event.structured_data
    assert base64.b64decode(row["raw_base64"]) == event.raw
    assert row["received_at"].endswith(".001+00:00")
    assert row["reported_time_utc"].endswith(".000+00:00")
    assert row["source_port"] == 514


@pytest.mark.parametrize("text", ["=1+1", " +1", "-1", "@SUM(A1)", "\ttext", "\rtext", "\ntext"])
def test_csv_formula_protection_and_multiline_unicode(store, tmp_path, text):
    message = text + ', "Grüße"\nnext line'
    store.insert([make_event(0, message=message)])
    result, output = run_export(store, tmp_path, ExportOptions(period="24h", columns=EXPORT_COLUMNS))
    assert result.rows == 1
    assert output.read_bytes().startswith(b"\xef\xbb\xbf")
    with output.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0]["message"] == "'" + message
    assert base64.b64decode(rows[0]["raw_base64"]) == message.encode()


def test_empty_period_creates_header_or_empty_jsonl(store, tmp_path):
    for format in ("csv", "jsonl"):
        result, output = run_export(store, tmp_path, ExportOptions(period="24h", format=format))
        assert result.rows == 0
        if format == "csv":
            assert output.read_text(encoding="utf-8-sig").strip() == ",".join(DEFAULT_EXPORT_COLUMNS)
        else:
            assert output.read_bytes() == b""


@pytest.mark.parametrize("format", ["csv", "jsonl"])
@pytest.mark.parametrize("columns", [DEFAULT_EXPORT_COLUMNS, ("message",),
                                    ("raw_base64", "reported_time_utc", "message", "received_at"),
                                    ("hostname", "severity")])
def test_selected_columns_exact_shape_and_order(store, tmp_path, format, columns):
    event = make_event(0, message="hello", hostname=None, severity=None)
    store.insert([event])
    result, output = run_export(store, tmp_path, ExportOptions(period="24h", format=format, columns=columns))
    assert result.rows == 1
    if format == "csv":
        with output.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            assert tuple(reader.fieldnames) == columns
            row = next(reader)
    else:
        row = read_jsonl(output)[0]
    assert tuple(row) == columns
    if "message" in columns:
        assert row["message"] == event.message
    if "raw_base64" in columns:
        assert base64.b64decode(row["raw_base64"]) == event.raw
    if "received_at" in columns:
        assert row["received_at"].endswith(".000+00:00")
    if "reported_time_utc" in columns:
        assert row["reported_time_utc"] == ("" if format == "csv" else None)


@pytest.mark.parametrize("columns", [(), ("bogus",), ("message", "message"),
                                    ("message; DROP TABLE events",)])
def test_invalid_columns_do_not_change_destination(store, tmp_path, columns):
    output = tmp_path / "export.csv"
    output.write_text("unchanged")
    with pytest.raises(ValueError):
        run_export(store, tmp_path, ExportOptions(period="24h", columns=columns))
    assert output.read_text() == "unchanged"
    assert not list(tmp_path.glob(".*.tmp"))


def test_default_export_does_not_encode_raw(store, tmp_path, monkeypatch):
    from syslog_monitor import export
    store.insert([make_event(0)])
    def unexpected_raw(*args):
        pytest.fail("Raw data should not be encoded unless selected")
    monkeypatch.setattr(export.base64, "b64encode", unexpected_raw)
    result, output = run_export(store, tmp_path, ExportOptions(period="24h", format="jsonl"))
    assert result.rows == 1
    assert tuple(read_jsonl(output)[0]) == DEFAULT_EXPORT_COLUMNS


@pytest.mark.parametrize("format", ["csv", "jsonl"])
def test_facility_and_severity_are_readable_names(store, tmp_path, format):
    from syslog_monitor.events import FACILITY_NAMES, SEVERITY_NAMES
    store.insert(make_event(index, facility=index, severity=index % 8)
                 for index in range(len(FACILITY_NAMES)))
    result, output = run_export(
        store, tmp_path, ExportOptions(period="24h", format=format, columns=("facility", "severity")))
    if format == "csv":
        with output.open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
    else:
        rows = read_jsonl(output)
    assert result.rows == len(FACILITY_NAMES)
    assert rows == [{"facility": name, "severity": SEVERITY_NAMES[index % 8]}
                    for index, name in enumerate(FACILITY_NAMES)]


def test_cancel_during_stream_preserves_destination_and_cleans_temp(store, tmp_path):
    store.insert(make_event(i) for i in range(BATCH_SIZE + 10))
    output = tmp_path / "export.csv"
    output.write_text("original")
    cancel = Event()
    with pytest.raises(ExportCancelled):
        run_export(store, tmp_path, ExportOptions(period="24h"), cancel=cancel,
                   progress=lambda count: cancel.set())
    assert output.read_text() == "original"
    assert not list(tmp_path.glob(".*.tmp"))


def test_replace_failure_preserves_destination_and_cleans_temp(store, tmp_path, monkeypatch):
    from syslog_monitor import export
    store.insert([make_event(0)])
    output = tmp_path / "export.csv"
    output.write_text("original")
    def deny_replace(*args):
        raise PermissionError("Destination is open in another application")
    monkeypatch.setattr(export.os, "replace", deny_replace)
    with pytest.raises(PermissionError):
        run_export(store, tmp_path, ExportOptions(period="24h"))
    assert output.read_text() == "original"
    assert not list(tmp_path.glob(".*.tmp"))


def test_export_uses_consistent_snapshot(store, tmp_path):
    store.insert(make_event(i) for i in range(BATCH_SIZE + 10))
    def insert_while_exporting(count):
        if count == BATCH_SIZE:
            store.insert([make_event(50_000, message="arrived during export")])
    result, output = run_export(store, tmp_path, ExportOptions(period="24h", format="jsonl"),
                                progress=insert_while_exporting)
    assert result.rows == BATCH_SIZE + 10
    assert all(row["message"] != "arrived during export" for row in read_jsonl(output))


@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
def test_database_cannot_be_overwritten(store, tmp_path, suffix):
    database = db_path(tmp_path)
    with pytest.raises(ValueError, match="must not be the log database"):
        export_events(database, type(database)(str(database) + suffix),
                      ExportOptions(period="24h"), now_ms=BASE_MS)


def test_invalid_options_and_write_failure(store, tmp_path):
    for options in (ExportOptions(period="bad"), ExportOptions(format="bad"),
                    ExportOptions(boot_marker=" ; "),
                    ExportOptions(period="custom"),
                    ExportOptions(period="custom", filters=EventFilter(start_ms=2, end_ms=1))):
        with pytest.raises(ValueError):
            run_export(store, tmp_path, options)
    with pytest.raises(OSError):
        export_events(db_path(tmp_path), tmp_path / "absent" / "file.csv",
                      ExportOptions(period="24h"), now_ms=BASE_MS)
    with pytest.raises(FileNotFoundError):
        export_events(tmp_path / "missing.sqlite3", tmp_path / "file.csv",
                      ExportOptions(period="24h"), now_ms=BASE_MS)
    assert not (tmp_path / "missing.sqlite3").exists()
