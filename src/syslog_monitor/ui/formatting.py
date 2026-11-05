"""Pure formatting helpers for the UI (no Qt dependency)."""

from __future__ import annotations

from datetime import datetime, timezone

from syslog_monitor.events import SyslogEvent, facility_name, severity_name
from syslog_monitor.i18n import tr

ISSUE_LABELS = {
    "no_pri": "No PRI header (severity unknown)",
    "invalid_pri": "Invalid PRI value",
    "invalid_utf8": "Invalid UTF-8 (bytes shown as \\xNN)",
    "bad_timestamp": "Sender timestamp cannot be interpreted as UTC",
    "bad_structured_data": "Malformed structured data",
    "no_timestamp": "No sender timestamp",
}


def format_ts(ms: int, *, with_date: bool = True) -> str:
    local = datetime.fromtimestamp(ms / 1000, tz=timezone.utc).astimezone()
    fmt = "%Y-%m-%d %H:%M:%S.%f" if with_date else "%H:%M:%S.%f"
    return local.strftime(fmt)[:-3]


def format_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def format_count(n: int) -> str:
    return f"{n:,}"


def format_event_details(ev: SyslogEvent) -> str:
    sev = tr("Unknown") if ev.severity is None else f"{tr(severity_name(ev.severity))} ({ev.severity})"
    fac = "-" if ev.facility is None else f"{facility_name(ev.facility)} ({ev.facility})"
    if ev.reported_time_utc is not None:
        reported = f"{ev.reported_time_text}  ->  {format_ts(ev.reported_time_utc)} (local)"
    else:
        reported = ev.reported_time_text or "-"
    issues = ", ".join(tr(ISSUE_LABELS.get(i, i)) for i in ev.issues) or tr("none")
    lines = [
        f"{tr('Received')}:       {format_ts(ev.received_at)} ({tr('local')})",
        f"{tr('Sender time')}:    {reported}",
        f"{tr('Source')}:         {ev.source_ip}:{ev.source_port}",
        f"{tr('Reported host')}:  {ev.hostname or '-'}",
        f"{tr('Severity')}:       {sev}",
        f"{tr('Facility')}:       {fac}",
        f"{tr('Application')}:    {ev.app_name or '-'}   PID: {ev.procid or '-'}   MsgID: {ev.msgid or '-'}",
        f"{tr('Format')}:         {ev.format}",
        f"{tr('Parser notes')}:    {issues}",
    ]
    if ev.structured_data:
        lines.append(f"{tr('Structured Data')}: {ev.structured_data}")
    lines += ["", f"{tr('Message')}:", ev.message, "", f"{tr('Raw data ({count} bytes)', count=len(ev.raw))}:",
              ev.raw.decode("utf-8", errors="backslashreplace")]
    return "\n".join(lines)
