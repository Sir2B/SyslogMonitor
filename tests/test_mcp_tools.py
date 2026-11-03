"""Tests for the read-only AI query layer behind the MCP server."""

import threading
import time
from datetime import datetime

import pytest
from conftest import BASE_MS, make_event

from syslog_monitor import mcp_tools
from syslog_monitor.mcp_tools import LogTools, format_time, parse_min_severity, parse_time

A, B = "192.0.2.1", "192.0.2.10"  # B starts with A's address: must not be mixed up
NOW_MS = BASE_MS + 3_600_000


@pytest.fixture
def tools(store):
    return LogTools(store.path, clock=lambda: NOW_MS / 1000)


def boot_log(store):
    """Device A boots twice, device B once (latest overall)."""
    store.insert([
        make_event(0, source_ip=A, hostname="dev-a", message="Initializing system"),
        make_event(1000, source_ip=A, hostname="dev-a", severity=3, message="disk 12 failed"),
        make_event(10_000, source_ip=A, hostname="dev-a", message="Initializing system"),
        make_event(11_000, source_ip=A, hostname="dev-a", severity=4, message="temp high"),
        make_event(12_000, source_ip=A, hostname="dev-a", severity=3, message="disk 13 failed"),
        make_event(13_000, source_ip=B, hostname="dev-b", message="Initializing system"),
        make_event(14_000, source_ip=B, hostname="dev-b", message="b running"),
        make_event(15_000, source_ip=A, hostname="dev-a", message="a running"),
    ])


def messages(result):
    return [e["message"] for e in result["events"]]


def test_parse_time_relative_iso_and_errors():
    assert parse_time(None, NOW_MS) is None
    assert parse_time(" ", NOW_MS) is None
    assert parse_time("now", NOW_MS) == NOW_MS
    assert parse_time("30m", NOW_MS) == NOW_MS - 30 * 60_000
    assert parse_time("1.5h", NOW_MS) == NOW_MS - 90 * 60_000
    assert parse_time("2d", NOW_MS) == NOW_MS - 2 * 86_400_000
    assert parse_time("2026-01-02T03:04:05Z", NOW_MS) == 1_767_323_045_000
    local = datetime(2026, 1, 2, 3, 4, 5).astimezone()
    assert parse_time("2026-01-02T03:04:05", NOW_MS) == int(local.timestamp() * 1000)
    assert parse_time(format_time(BASE_MS + 123), NOW_MS) == BASE_MS + 123  # round trip
    with pytest.raises(ValueError, match="ISO 8601"):
        parse_time("yesterday", NOW_MS)


def test_parse_min_severity():
    assert parse_min_severity(None) is None
    assert parse_min_severity("") is None
    assert parse_min_severity("warning") == frozenset(range(5))
    assert parse_min_severity("ERR") == frozenset(range(4))
    assert parse_min_severity("3") == frozenset(range(4))
    assert parse_min_severity(0) == frozenset({0})
    with pytest.raises(ValueError, match="Invalid severity"):
        parse_min_severity("fatal")
    with pytest.raises(ValueError):
        parse_min_severity(9)


def test_logs_since_boot_picks_latest_boot_and_device(tools, store):
    boot_log(store)
    latest = tools.logs_since_boot()
    assert latest["found"] and latest["ip"] == B and latest["device"] == "dev-b"
    assert messages(latest) == ["Initializing system", "b running"]
    assert latest["until"].startswith("now")

    a = tools.logs_since_boot(device=A)
    assert a["ip"] == A and a["boot_time"] == format_time(BASE_MS + 10_000)
    assert messages(a) == ["Initializing system", "temp high", "disk 13 failed", "a running"]
    assert a["previous_boot_time"] == format_time(BASE_MS)
    assert a["counts_by_severity"] == {"error": 1, "warning": 1, "info": 2}
    assert tools.logs_since_boot(device="dev-a")["ip"] == A

    earlier = tools.logs_since_boot(device=A, boot=1)
    assert messages(earlier) == ["Initializing system", "disk 12 failed"]
    assert earlier["until"] == format_time(BASE_MS + 10_000)
    assert earlier["previous_boot_time"] is None

    errors = tools.logs_since_boot(device=A, min_severity="warning")
    assert messages(errors) == ["temp high", "disk 13 failed"]
    assert errors["counts_by_severity"]["info"] == 2  # counts always cover the whole boot

    assert not tools.logs_since_boot(device=A, boot=2)["found"]
    assert not tools.logs_since_boot(device="unknown")["found"]
    assert messages(tools.logs_since_boot(device=A, marker="temp"))[0] == "temp high"


def test_logs_since_boot_pages_via_get_logs(tools, store):
    boot_log(store)
    first = tools.logs_since_boot(device=A, limit=2)
    assert first["truncated"] and first["returned"] == 2
    rest = tools.get_logs(device=A, after=first["next_after"])
    assert messages(first) + messages(rest) == [
        "Initializing system", "temp high", "disk 13 failed", "a running"]
    assert not rest["truncated"] and rest["next_after"] is None
    with pytest.raises(ValueError, match="cursor"):
        tools.get_logs(after="nonsense")


def test_logs_since_boot_without_marker_configured(store):
    with pytest.raises(ValueError, match="boot marker"):
        LogTools(store.path, boot_marker=" ; ").logs_since_boot()


def test_get_logs_time_range_and_device(tools, store):
    boot_log(store)
    since = format_time(BASE_MS + 11_000)
    until = format_time(BASE_MS + 14_000)
    result = tools.get_logs(since=since, until=until)
    assert messages(result) == ["temp high", "disk 13 failed", "Initializing system"]
    assert messages(tools.get_logs(device=B)) == ["Initializing system", "b running"]
    assert len(tools.get_logs(device="192.0.2")["events"]) == 8  # partial address = substring
    with pytest.raises(ValueError, match="before"):
        tools.get_logs(since=until, until=since)


def test_search_logs(tools, store):
    boot_log(store)
    result = tools.search_logs("failed")
    assert result["total_matches"] == 2
    assert messages(result) == ["disk 12 failed", "disk 13 failed"]
    limited = tools.search_logs("Initializing", limit=1)
    assert limited["total_matches"] == 3 and messages(limited) == ["Initializing system"]
    assert limited["events"][0]["ip"] == B  # newest match
    assert tools.search_logs("disk", device=A, mode="words")["total_matches"] == 2
    with pytest.raises(ValueError):
        tools.search_logs("  ")
    with pytest.raises(ValueError, match="mode"):
        tools.search_logs("x", mode="regex")


def test_get_context_same_device(tools, store):
    boot_log(store)
    anchor = tools.search_logs("disk 13")["events"][0]["id"]
    context = tools.get_context(anchor, before=2, after=5)
    assert messages(context) == ["Initializing system", "temp high", "disk 13 failed", "a running"]
    assert context["anchor_id"] == anchor
    mixed = tools.get_context(anchor, before=0, after=1, same_device=False)
    assert messages(mixed) == ["disk 13 failed", "Initializing system"]
    with pytest.raises(ValueError, match="No message"):
        tools.get_context(9999)


def test_summarize_groups_errors_and_lists_boots(tools, store):
    boot_log(store)
    summary = tools.summarize(since="2h")
    assert summary["total"] == 8
    assert summary["counts_by_severity"] == {"error": 2, "warning": 1, "info": 5}
    top = summary["top_errors"][0]
    assert top["count"] == 2 and top["example"]["message"] == "disk 13 failed"
    assert top["first_seen"] == format_time(BASE_MS + 1000)
    assert [b["device"] for b in summary["boots"]] == ["dev-a", "dev-a", "dev-b"]
    assert {d["ip"] for d in summary["devices"]} == {A, B}
    assert tools.summarize(device=B, since="2h")["top_errors"] == []


def test_error_timeline_buckets(tools, store):
    boot_log(store)
    timeline = tools.error_timeline(since=format_time(BASE_MS), until=format_time(BASE_MS + 20_000),
                                    buckets=2)
    assert timeline["bucket_seconds"] == 10.0
    first, second = timeline["buckets"]
    assert (first["errors"], first["total"], first["boots"]) == (1, 2, 1)
    assert (second["errors"], second["warnings"], second["boots"]) == (1, 1, 2)


def test_status_and_devices(store):
    boot_log(store)
    tools = LogTools(store.path, clock=lambda: (BASE_MS + 60_000) / 1000,
                     status_provider=lambda: {"state": "running"})
    status = tools.status()
    assert status["stored_messages"] == 8
    assert status["oldest"] == format_time(BASE_MS)
    assert status["receiver"] == {"state": "running"}
    assert [d["ip"] for d in status["devices_last_24h"]] == [A, B]  # most recently active first
    devices = tools.list_devices()["devices"]
    assert devices[0] == {"ip": A, "hostname": "dev-a", "messages": 6,
                          "last_seen": format_time(BASE_MS + 15_000)}


def test_long_messages_are_truncated(tools, store):
    store.insert([make_event(0, message="x" * (mcp_tools.MAX_MESSAGE_CHARS + 50))])
    message = tools.get_logs()["events"][0]["message"]
    assert message.endswith("[50 chars truncated]")


def test_wait_for_message_sees_only_new_matching_messages(tools, store):
    boot_log(store)  # existing boot markers must not count

    def later():
        time.sleep(0.3)
        store.insert([make_event(20_000, source_ip=B, message="Initializing system")])
        time.sleep(0.3)
        store.insert([make_event(21_000, source_ip=A, message="Initializing system")])

    threading.Thread(target=later).start()
    result = tools.wait_for_message("initializing", device=A, timeout_s=10, poll_s=0.05)
    assert result["found"] and result["event"]["ip"] == A


def test_wait_for_message_timeout_and_stop(tools, store):
    start = time.monotonic()
    assert not tools.wait_for_message("never", timeout_s=1, poll_s=0.05)["found"]
    assert 0.9 < time.monotonic() - start < 3
    threading.Timer(0.2, tools.stopping.set).start()
    start = time.monotonic()
    assert not tools.wait_for_message("never", timeout_s=60)["found"]
    assert time.monotonic() - start < 3
