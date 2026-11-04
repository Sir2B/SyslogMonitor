"""Tolerant syslog parser for RFC 5424 and RFC 3164 (BSD) datagrams.

Parsing never fails: anything that cannot be interpreted is kept as free text and
the problems are recorded in ``SyslogEvent.issues``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from syslog_monitor.events import SyslogEvent

NIL = "-"
MAX_PRI = 191

_PRI_RE = re.compile(r"<(\d{1,3})>")
_RFC5424_HEADER_RE = re.compile(r"1 (\S+) (\S+) (\S+) (\S+) (\S+) ?", re.DOTALL)
_BSD_TIME_RE = re.compile(r"([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) ")
_ISO_TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*) ")
_TAG_RE = re.compile(r"([^\s:\[\]]{1,48})(?:\[([^\]\s]{0,128})\])?: ?(.*)", re.DOTALL)


def parse_datagram(data: bytes, source_ip: str, source_port: int, received_at: int) -> SyslogEvent:
    text, issues = _decode(data)
    event = SyslogEvent(
        received_at=received_at,
        source_ip=source_ip,
        source_port=source_port,
        raw=data,
        message=text,
    )

    pri_match = _PRI_RE.match(text)
    if not pri_match:
        issues.append("no_pri")
        event.issues = tuple(issues)
        return event
    pri = int(pri_match.group(1))
    if pri > MAX_PRI:
        issues.append("invalid_pri")
        event.issues = tuple(issues)
        return event

    event.facility, event.severity = pri >> 3, pri & 7
    rest = text[pri_match.end():]
    header = _RFC5424_HEADER_RE.match(rest)
    if header and rest[header.end():header.end() + 1] in (NIL, "["):
        _parse_rfc5424(event, header, rest[header.end():], issues)
    else:
        _parse_rfc3164(event, rest, issues)
    event.issues = tuple(issues)
    return event


def _decode(data: bytes) -> tuple[str, list[str]]:
    data = data.rstrip(b"\r\n\x00")
    try:
        return data.decode("utf-8"), []
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="backslashreplace"), ["invalid_utf8"]


def _nil(value: str) -> str | None:
    return None if value == NIL else value


def _parse_iso_time(text: str) -> int | None:
    """Return UTC epoch ms for an ISO-8601 timestamp with offset, else None."""
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return None
        return int(parsed.astimezone(timezone.utc).timestamp() * 1000)
    except (ValueError, OverflowError, OSError):
        return None


def _parse_rfc5424(event: SyslogEvent, header: re.Match[str], tail: str, issues: list[str]) -> None:
    event.format = "rfc5424"
    timestamp, hostname, app_name, procid, msgid = header.groups()
    event.hostname, event.app_name = _nil(hostname), _nil(app_name)
    event.procid, event.msgid = _nil(procid), _nil(msgid)
    if timestamp != NIL:
        event.reported_time_text = timestamp
        event.reported_time_utc = _parse_iso_time(timestamp)
        if event.reported_time_utc is None:
            issues.append("bad_timestamp")

    structured, message, ok = split_structured_data(tail)
    if not ok:
        issues.append("bad_structured_data")
    event.structured_data = structured
    event.message = message.removeprefix(" ").removeprefix("\ufeff")


def split_structured_data(tail: str) -> tuple[str | None, str, bool]:
    """Split ``STRUCTURED-DATA [SP MSG]`` into (sd or None, msg, valid)."""
    if tail.startswith(NIL):
        return None, tail[1:], True
    pos = 0
    while pos < len(tail) and tail[pos] == "[":
        end = _element_end(tail, pos)
        if end < 0:
            return None, tail, False
        pos = end + 1
    return tail[:pos], tail[pos:], True


def _element_end(text: str, start: int) -> int:
    """Index of the ``]`` closing the SD element at ``start``; -1 if unterminated."""
    in_quotes = False
    i = start + 1
    while i < len(text):
        char = text[i]
        if char == "\\" and in_quotes:
            i += 2
            continue
        if char == '"':
            in_quotes = not in_quotes
        elif char == "]" and not in_quotes:
            return i
        i += 1
    return -1


def _parse_rfc3164(event: SyslogEvent, rest: str, issues: list[str]) -> None:
    event.format = "rfc3164"
    time_match = _BSD_TIME_RE.match(rest) or _ISO_TIME_RE.match(rest)
    if time_match:
        event.reported_time_text = time_match.group(1)
        if time_match.re is _ISO_TIME_RE:
            event.reported_time_utc = _parse_iso_time(time_match.group(1))
        rest = rest[time_match.end():]
        hostname, sep, after = rest.partition(" ")
        if sep and hostname and not _looks_like_tag(hostname):
            event.hostname = hostname
            rest = after
    else:
        issues.append("no_timestamp")

    tag = _TAG_RE.fullmatch(rest)
    if tag:
        event.app_name, event.procid, rest = tag.group(1), tag.group(2), tag.group(3)
    event.message = rest


def _looks_like_tag(token: str) -> bool:
    return token.endswith(":") or "[" in token
