"""Read-only log queries for AI assistants (used by the MCP server).

Independent of the MCP SDK and Qt so it can be tested directly. Every call
opens its own read-only connection (calls arrive on worker threads) and all
results are bounded so a single answer never floods the AI context.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator

from syslog_monitor.config import DEFAULT_BOOT_MARKER
from syslog_monitor.events import SEVERITY_NAMES, SeverityClass, severity_name
from syslog_monitor.query import (
    TEXT_MODE_SUBSTRING, TEXT_MODE_WORDS, Cursor, EventFilter, EventRow, FilterRule, QueryRunner,
    parse_highlights,
)

DEFAULT_LIMIT = 200
MAX_LIMIT = 2000
MAX_MESSAGE_CHARS = 2000
MAX_CONTEXT = 200
MAX_WAIT_S = 600
_SUMMARY_SAMPLE = 5000
_RELATIVE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(s|sec|m|min|h|d|w)\s*$", re.IGNORECASE)
_UNITS = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "d": 86400, "w": 604800}
_SEVERITY_ALIASES = {
    "emerg": 0, "panic": 0, "crit": 2, "err": 3, "warn": 4, "information": 6, "informational": 6,
}
_NUMBER_RE = re.compile(r"\d+")


def parse_time(value: str | None, now_ms: int) -> int | None:
    """``None``/"" -> None, "now", relative ("30m", "2h", "1d" = that long ago) or ISO 8601.

    ISO times without offset are local time.
    """
    if value is None or not str(value).strip():
        return None
    text = str(value).strip()
    if text.lower() == "now":
        return now_ms
    if match := _RELATIVE_RE.match(text):
        seconds = float(match.group(1)) * _UNITS[match.group(2).lower()]
        return now_ms - int(seconds * 1000)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(
            f"Invalid time {value!r}: use ISO 8601 (e.g. 2026-10-24T14:30) "
            "or relative like 30m, 2h, 1d.") from None
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return int(parsed.timestamp() * 1000)


def format_time(ms: int | None) -> str | None:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000).astimezone().isoformat(timespec="milliseconds")


def parse_min_severity(value: str | int | None) -> frozenset[int | None] | None:
    """"warning" -> severities 0..4 (warning or worse). ``None``/"" -> no filter."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, int) or str(value).strip().isdigit():
        level = int(value)
    else:
        name = str(value).strip().lower()
        names = {n.lower(): i for i, n in enumerate(SEVERITY_NAMES)}
        level = names.get(name, _SEVERITY_ALIASES.get(name, -1))
    if not 0 <= level <= 7:
        raise ValueError(f"Invalid severity {value!r}: use 0-7 or one of "
                         f"{', '.join(n.lower() for n in SEVERITY_NAMES)}.")
    return frozenset(range(level + 1))


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def _encode_cursor(row: EventRow) -> str:
    return f"{row.received_at}:{row.id}"


def _decode_cursor(text: str) -> Cursor:
    try:
        received_at, event_id = (int(part) for part in text.split(":"))
    except ValueError:
        raise ValueError(f"Invalid cursor {text!r}: pass next_after from a previous result.") from None
    return received_at, event_id


def _message(text: str) -> str:
    if len(text) <= MAX_MESSAGE_CHARS:
        return text
    return text[:MAX_MESSAGE_CHARS] + f"… [{len(text) - MAX_MESSAGE_CHARS} chars truncated]"


def row_dict(row: EventRow) -> dict[str, Any]:
    app = row.app_name or ""
    if row.procid:
        app = f"{app}[{row.procid}]"
    return {
        "id": row.id,
        "time": format_time(row.received_at),
        "device": row.hostname or row.source_ip,
        "ip": row.source_ip,
        "severity": severity_name(row.severity).lower(),
        "app": app,
        "message": _message(row.message),
    }


def _normalize(message: str) -> str:
    """Group messages differing only in numbers (PIDs, counters, addresses)."""
    return _NUMBER_RE.sub("#", message.strip())[:300]


def _device_matches(f: EventFilter, row: EventRow) -> bool:
    """Python equivalent of the device part of a filter built by ``LogTools._filter``."""
    candidates = (row.source_ip.lower(), (row.hostname or "").lower())
    if f.rules:
        return f.rules[0].value.lower() in candidates
    return not f.sender or any(f.sender.lower() in value for value in candidates)


class LogTools:
    """The operations exposed to the AI; all read-only."""

    def __init__(self, db_path: Path, *, boot_marker: str = DEFAULT_BOOT_MARKER,
                 status_provider: Callable[[], dict[str, Any]] | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.db_path = db_path
        self.boot_marker = boot_marker
        self._status_provider = status_provider
        self._clock = clock
        self.stopping = threading.Event()  # ends wait_for_message early on shutdown

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    @contextmanager
    def _runner(self) -> Iterator[QueryRunner]:
        runner = QueryRunner(self.db_path)
        try:
            yield runner
        finally:
            runner.close()

    def _filter(self, *, device: str | None = None, since: str | None = None,
                until: str | None = None, min_severity: str | int | None = None) -> EventFilter:
        now = self._now_ms()
        start, end = parse_time(since, now), parse_time(until, now)
        if start is not None and end is not None and start >= end:
            raise ValueError("'since' must be before 'until'.")
        f = EventFilter(start_ms=start, end_ms=end, severities=parse_min_severity(min_severity))
        device = (device or "").strip()
        try:
            ipaddress.IPv4Address(device)
        except ValueError:
            return replace(f, sender=device)  # host name or partial address: substring
        return self._exact_device(f, device)

    @staticmethod
    def _exact_device(f: EventFilter, ip: str) -> EventFilter:
        return replace(f, sender="", rules=(FilterRule("sender", "equals", ip, required=True),))

    def _markers(self, marker: str | None) -> str:
        marker = self.boot_marker if marker is None else marker
        if not parse_highlights(marker):
            raise ValueError("No boot marker configured: pass 'marker' (texts separated by ';').")
        return marker

    # -- tools ---------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        with self._runner() as runner:
            bounds = runner.time_bounds()
            total = runner.count(EventFilter())
            devices = runner.senders(self._now_ms() - 86_400_000, 20)
        result: dict[str, Any] = {
            "now": format_time(self._now_ms()),
            "stored_messages": total,
            "oldest": format_time(bounds[0]) if bounds else None,
            "newest": format_time(bounds[1]) if bounds else None,
            "boot_marker": self.boot_marker,
            "devices_last_24h": [self._device(d) for d in devices],
        }
        if self._status_provider is not None:
            result["receiver"] = self._status_provider()
        return result

    @staticmethod
    def _device(d) -> dict[str, Any]:
        return {"ip": d.source_ip, "hostname": d.hostname, "messages": d.count,
                "last_seen": format_time(d.last_ms)}

    def list_devices(self, since: str = "7d", limit: int = 50) -> dict[str, Any]:
        start = parse_time(since, self._now_ms()) or 0
        with self._runner() as runner:
            devices = runner.senders(start, _clamp(limit, 1, 500))
        return {"since": format_time(start), "devices": [self._device(d) for d in devices]}

    def logs_since_boot(self, device: str | None = None, boot: int = 0,
                        min_severity: str | int | None = None, limit: int = DEFAULT_LIMIT,
                        marker: str | None = None) -> dict[str, Any]:
        markers = self._markers(marker)
        boot = _clamp(boot, 0, 1000)
        limit = _clamp(limit, 1, MAX_LIMIT)
        base = self._filter(device=device)
        with self._runner() as runner:
            latest = runner.fetch_highlighted(base, markers, 1)
            if not latest:
                where = f" from device matching {device!r}" if device else ""
                return {"found": False, "boot_marker": markers,
                        "hint": f"No message containing the boot marker{where} is stored. "
                                "Use list_devices/search_logs or pass another 'marker'."}
            ip = latest[0].source_ip
            device_filter = self._exact_device(EventFilter(), ip)
            boots = runner.fetch_highlighted(device_filter, markers, boot + 2)
            if boot >= len(boots):
                return {"found": False, "boot_marker": markers, "device": ip,
                        "hint": f"Device has only {len(boots)} recorded boot(s)."}
            start = boots[boot]
            end_ms = boots[boot - 1].received_at if boot > 0 else None
            previous = boots[boot + 1] if boot + 1 < len(boots) else None
            window = replace(device_filter, start_ms=start.received_at, end_ms=end_ms)
            counts = runner.severity_counts(window)
            view = replace(window, severities=parse_min_severity(min_severity))
            rows = list(reversed(runner.fetch_newer(view, (start.received_at, start.id - 1), limit + 1)))
        page = rows[:limit]
        return {
            "found": True,
            "device": start.hostname or ip,
            "ip": ip,
            "boot": boot,
            "boot_time": format_time(start.received_at),
            "boot_event_id": start.id,
            "boot_message": _message(start.message),
            "until": format_time(end_ms) if end_ms else "now (current boot)",
            "previous_boot_time": format_time(previous.received_at) if previous else None,
            "counts_by_severity": {severity_name(s).lower(): n for s, n in sorted(
                counts.items(), key=lambda item: 8 if item[0] is None else item[0])},
            "returned": len(page),
            "truncated": len(rows) > limit,
            "next_after": _encode_cursor(page[-1]) if len(rows) > limit else None,
            "events": [row_dict(r) for r in page],
        }

    def get_logs(self, device: str | None = None, since: str | None = None,
                 until: str | None = None, min_severity: str | int | None = None,
                 limit: int = DEFAULT_LIMIT, after: str | None = None) -> dict[str, Any]:
        limit = _clamp(limit, 1, MAX_LIMIT)
        f = self._filter(device=device, since=since, until=until, min_severity=min_severity)
        if after:
            cursor = _decode_cursor(after)
        elif f.start_ms is not None:
            cursor = (f.start_ms, 0)
        else:
            cursor = (-1, 0)
        with self._runner() as runner:
            rows = list(reversed(runner.fetch_newer(f, cursor, limit + 1)))
        page = rows[:limit]
        return {
            "returned": len(page),
            "truncated": len(rows) > limit,
            "next_after": _encode_cursor(page[-1]) if len(rows) > limit else None,
            "events": [row_dict(r) for r in page],
        }

    def search_logs(self, query: str, device: str | None = None, since: str | None = None,
                    until: str | None = None, min_severity: str | int | None = None,
                    mode: str = "substring", limit: int = 100) -> dict[str, Any]:
        if not query.strip():
            raise ValueError("'query' must not be empty.")
        if mode not in (TEXT_MODE_SUBSTRING, TEXT_MODE_WORDS):
            raise ValueError("'mode' must be 'substring' or 'words'.")
        limit = _clamp(limit, 1, MAX_LIMIT)
        f = replace(self._filter(device=device, since=since, until=until, min_severity=min_severity),
                    text=query, text_mode=mode)
        with self._runner() as runner:
            total = runner.count(f)
            rows = runner.fetch_older(f, None, limit)
        return {
            "total_matches": total,
            "returned": len(rows),
            "note": "newest matches, listed oldest first" if total > len(rows) else None,
            "events": [row_dict(r) for r in reversed(rows)],
        }

    def get_context(self, event_id: int, before: int = 20, after: int = 20,
                    same_device: bool = True) -> dict[str, Any]:
        before, after = _clamp(before, 0, MAX_CONTEXT), _clamp(after, 0, MAX_CONTEXT)
        with self._runner() as runner:
            event = runner.get_event(int(event_id))
            if event is None:
                raise ValueError(f"No message with id {event_id}.")
            f = self._exact_device(EventFilter(), event.source_ip) if same_device else EventFilter()
            cursor = (event.received_at, int(event_id))
            newer, older = runner.fetch_context(f, cursor, before + 1, after)
        rows = [*reversed(older), *reversed(newer)]  # chronological, anchor included
        return {"anchor_id": int(event_id), "events": [row_dict(r) for r in rows]}

    def summarize(self, device: str | None = None, since: str = "24h",
                  until: str | None = None) -> dict[str, Any]:
        f = self._filter(device=device, since=since, until=until)
        markers = parse_highlights(self.boot_marker)
        with self._runner() as runner:
            counts = runner.severity_counts(f)
            errors = runner.fetch_older(replace(f, severities=frozenset(range(4))), None, _SUMMARY_SAMPLE)
            warnings = runner.fetch_older(replace(f, severities=frozenset({4})), None, _SUMMARY_SAMPLE)
            boots = runner.fetch_highlighted(f, self.boot_marker, 100) if markers else []
            devices = runner.senders(f.start_ms or 0, 20) if not device else []
        return {
            "since": format_time(f.start_ms),
            "until": format_time(f.end_ms) or "now",
            "total": sum(counts.values()),
            "counts_by_severity": {severity_name(s).lower(): n for s, n in sorted(
                counts.items(), key=lambda item: 8 if item[0] is None else item[0])},
            "boots": [{"time": format_time(b.received_at), "device": b.hostname or b.source_ip,
                       "event_id": b.id} for b in reversed(boots)],
            "top_errors": self._top(errors, 15),
            "top_warnings": self._top(warnings, 10),
            "devices": [self._device(d) for d in devices],
            "note": (f"top lists based on the newest {_SUMMARY_SAMPLE} messages per class"
                     if len(errors) == _SUMMARY_SAMPLE or len(warnings) == _SUMMARY_SAMPLE else None),
        }

    @staticmethod
    def _top(rows: list[EventRow], n: int) -> list[dict[str, Any]]:
        groups: Counter[str] = Counter()
        latest: dict[str, EventRow] = {}
        first: dict[str, int] = {}
        for row in rows:  # newest first
            key = _normalize(row.message)
            groups[key] += 1
            latest.setdefault(key, row)
            first[key] = row.received_at
        return [{
            "count": count,
            "example": row_dict(latest[key]),
            "first_seen": format_time(first[key]),
        } for key, count in groups.most_common(n)]

    def error_timeline(self, device: str | None = None, since: str = "24h",
                       until: str | None = None, buckets: int = 24) -> dict[str, Any]:
        f = self._filter(device=device, since=since, until=until)
        end = f.end_ms if f.end_ms is not None else self._now_ms()
        start = f.start_ms if f.start_ms is not None else end - 86_400_000
        buckets = _clamp(buckets, 1, 200)
        with self._runner() as runner:
            histogram = runner.histogram(f, start, end, buckets, self.boot_marker)
        span = max(1, end - start)
        rows = []
        for index, bucket in enumerate(histogram.counts):
            rows.append({
                "start": format_time(start + span * index // buckets),
                "errors": bucket[SeverityClass.ERROR],
                "warnings": bucket[SeverityClass.WARNING],
                "total": sum(bucket),
                "boots": histogram.highlights[index],
            })
        return {"bucket_seconds": round(span / buckets / 1000, 1), "buckets": rows}

    def wait_for_message(self, text: str, device: str | None = None,
                         timeout_s: float = 120, poll_s: float = 1.0) -> dict[str, Any]:
        """Block until a new message containing ``text`` arrives (or timeout)."""
        if not parse_highlights(text):
            raise ValueError("'text' must not be empty.")
        deadline = time.monotonic() + _clamp(timeout_s, 1, MAX_WAIT_S)
        wanted = EventFilter() if not (device or "").strip() else self._filter(device=device)
        with self._runner() as runner:
            after_id = runner.max_id()
            while True:
                batch = runner.new_highlights(after_id, text, 50)
                after_id = batch.last_id
                for row in reversed(batch.rows):  # oldest first
                    if _device_matches(wanted, row):
                        return {"found": True, "event": row_dict(row)}
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.stopping.wait(min(poll_s, remaining)):
                    return {"found": False, "hint": "Timeout: no matching message received."}
