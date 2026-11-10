"""Import syslog messages from files into the log database.

Supported formats are detected automatically:

* CSV and JSONL files written by this application's export,
* tab-separated logs of syslog servers (sender, time, version, facility, severity, tag, message),
* plain text with one syslog message per line, with or without ``<PRI>``.
"""

from __future__ import annotations

import base64
import binascii
import csv
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime
from itertools import islice
from pathlib import Path
from threading import Event
from typing import Callable, Iterator

from syslog_monitor.events import FACILITY_NAMES, SEVERITY_NAMES, SyslogEvent
from syslog_monitor.export import EXPORT_COLUMNS
from syslog_monitor.parser import parse_datagram
from syslog_monitor.storage import connect, insert_events

BATCH_SIZE = 1000
IMPORT_SOURCE = "import"
FORMAT_CSV = "csv"
FORMAT_JSONL = "jsonl"
FORMAT_TABBED = "tabbed"
FORMAT_LINES = "lines"

_BSD_TIME_RE = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})$")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_FACILITIES = {name: code for code, name in enumerate(FACILITY_NAMES)}
_SEVERITIES = {name.lower(): code for code, name in enumerate(SEVERITY_NAMES)}
_SEVERITIES.update({"emerg": 0, "crit": 2, "err": 3, "warn": 4, "information": 6,
                    "informational": 6})
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


class ImportCancelled(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ImportResult:
    rows: int
    format: str


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def _iso_ms(value: object) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.astimezone()
    return int(moment.timestamp() * 1000)


def _bsd_ms(text: str, now_ms: int) -> int | None:
    """Local "Nov 10 07:46:01" without a year: use the latest year that is not in the future."""
    match = _BSD_TIME_RE.match(text.strip())
    if not match or match.group(1) not in _MONTHS:
        return None
    month = _MONTHS.index(match.group(1)) + 1
    day, hour, minute, second = (int(match.group(i)) for i in range(2, 6))
    year = datetime.fromtimestamp(now_ms / 1000).year
    for candidate in (year, year - 1):
        try:
            moment = datetime(candidate, month, day, hour, minute, second).astimezone()
        except ValueError:
            continue
        stamp = int(moment.timestamp() * 1000)
        if stamp <= now_ms + 86_400_000:
            return stamp
    return None


def _code(value: object, names: dict[str, int], limit: int) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.isdigit():
        number = int(text)
        return number if number < limit else None
    return names.get(text.lower() if names is _SEVERITIES else text)


def _unprotect(value: object) -> object:
    # Reverse the export's spreadsheet formula protection.
    if isinstance(value, str) and value.startswith("'") and value[1:].lstrip().startswith(_FORMULA_PREFIXES):
        return value[1:]
    if isinstance(value, str) and value.startswith("'") and value[1:2] in ("\t", "\r", "\n"):
        return value[1:]
    return value


def _from_record(record: dict, now_ms: int) -> SyslogEvent:
    """Rebuild an event from an exported CSV row or JSONL object."""
    received = _iso_ms(record.get("received_at")) or now_ms
    source_ip = str(record.get("source_ip") or record.get("hostname") or IMPORT_SOURCE)
    try:
        source_port = int(record.get("source_port") or 0)
    except ValueError:
        source_port = 0
    encoded = record.get("raw_base64")
    if encoded:
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raw = None
        if raw is not None:
            return parse_datagram(raw, source_ip, source_port, received)
    message = str(record.get("message") or "")
    text = lambda key: (str(record[key]) if record.get(key) not in (None, "") else None)  # noqa: E731
    issues = tuple(part for part in str(record.get("issues") or "").split(",") if part)
    return SyslogEvent(
        received_at=received, source_ip=source_ip, source_port=source_port,
        raw=message.encode("utf-8"), message=message,
        format=str(record.get("format") or "unparsed"), issues=issues,
        facility=_code(record.get("facility"), _FACILITIES, len(FACILITY_NAMES)),
        severity=_code(record.get("severity"), _SEVERITIES, len(SEVERITY_NAMES)),
        reported_time_text=text("reported_time_text"),
        reported_time_utc=_iso_ms(record.get("reported_time_utc")),
        hostname=text("hostname"), app_name=text("app_name"), procid=text("procid"),
        msgid=text("msgid"), structured_data=text("structured_data"),
    )


def _from_tabbed(fields: list[str], now_ms: int) -> SyslogEvent:
    sender, stamp, version, facility, severity, tag = fields[:6]
    rest = "\t".join(fields[6:]).rstrip()
    fac = _code(facility, _FACILITIES, len(FACILITY_NAMES))
    sev = _code(severity, _SEVERITIES, len(SEVERITY_NAMES))
    received = _bsd_ms(stamp, now_ms) or now_ms
    if version.strip().isdigit():
        body = f"{version.strip()} {rest}"
    elif tag.strip():
        body = f"{stamp} {sender} {tag.strip()}: {rest}"
    else:
        body = rest
    if fac is not None and sev is not None:
        event = parse_datagram(f"<{fac * 8 + sev}>{body}".encode("utf-8"), sender.strip() or IMPORT_SOURCE, 0, received)
    else:
        event = _from_line(body, now_ms, received)
        event.source_ip = sender.strip() or event.source_ip
    return event


def _from_line(line: str, now_ms: int, received: int | None = None) -> SyslogEvent:
    if line.startswith("<"):
        event = parse_datagram(line.encode("utf-8"), IMPORT_SOURCE, 0, received or now_ms)
        if event.facility is not None:
            event.received_at = received or event.reported_time_utc or now_ms
            event.source_ip = event.hostname or IMPORT_SOURCE
            return event
    # Plain log files (e.g. /var/log/syslog) omit the PRI; parse the header without inventing one.
    event = parse_datagram(f"<13>{line}".encode("utf-8"), IMPORT_SOURCE, 0, received or now_ms)
    event.facility = event.severity = None
    event.raw = line.encode("utf-8")
    event.received_at = received or event.reported_time_utc or now_ms
    event.source_ip = event.hostname or IMPORT_SOURCE
    return event


def detect_format(first_line: str) -> str:
    stripped = first_line.strip()
    if stripped.startswith("{"):
        return FORMAT_JSONL
    header = next(csv.reader([stripped]), [])
    if header and all(column in EXPORT_COLUMNS for column in header):
        return FORMAT_CSV
    fields = first_line.split("\t")
    if len(fields) >= 7 and _BSD_TIME_RE.match(fields[1].strip()):
        return FORMAT_TABBED
    return FORMAT_LINES


FORMATS = (FORMAT_CSV, FORMAT_JSONL, FORMAT_TABBED, FORMAT_LINES)


def read_events(path: Path, now_ms: int, kind: str | None = None) -> tuple[str, Iterator[SyslogEvent]]:
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    text = _decode(data)
    first = next((line for line in text.splitlines() if line.strip()), "")
    kind = kind or detect_format(first)

    def events() -> Iterator[SyslogEvent]:
        if kind == FORMAT_CSV:
            for row in csv.DictReader(io.StringIO(text, newline="")):
                yield _from_record({key: _unprotect(value) for key, value in row.items()}, now_ms)
        elif kind == FORMAT_JSONL:
            for line in text.splitlines():
                if line.strip():
                    yield _from_record(json.loads(line), now_ms)
        else:
            for line in text.splitlines():
                if not line.strip():
                    continue
                fields = line.split("\t")
                if kind == FORMAT_TABBED and len(fields) >= 7:
                    yield _from_tabbed(fields, now_ms)
                else:
                    yield _from_line(line.rstrip(), now_ms)

    return kind, events()


def preview(path: Path, now_ms: int, kind: str | None = None, limit: int = 20) -> tuple[str, list[SyslogEvent]]:
    """Detected (or forced) format and the first events exactly as they would be imported."""
    kind, events = read_events(path, now_ms, kind)
    return kind, list(islice(events, limit))


def import_file(db_path: Path, source: Path, *, now_ms: int, cancel: Event | None = None,
                progress: Callable[[int], None] | None = None, kind: str | None = None) -> ImportResult:
    """Insert all messages of ``source``; batches already written stay on cancel."""
    cancel = cancel if cancel is not None else Event()
    kind, events = read_events(source, now_ms, kind)
    conn = connect(db_path)
    count = 0
    try:
        batch: list[SyslogEvent] = []
        for event in events:
            batch.append(event)
            if len(batch) >= BATCH_SIZE:
                if cancel.is_set():
                    raise ImportCancelled(count)
                count += insert_events(conn, batch)
                batch = []
                if progress:
                    progress(count)
        if cancel.is_set():
            raise ImportCancelled(count)
        count += insert_events(conn, batch)
    finally:
        conn.close()
    return ImportResult(count, kind)
