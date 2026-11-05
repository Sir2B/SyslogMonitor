"""Read-side queries: filtering, keyset pagination, histogram, details.

All functions use parameterised SQL and bounded result sizes; nothing loads the
whole table. Ordering is always ``(received_at, id)`` so pages are stable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import NamedTuple

from syslog_monitor.events import SeverityClass, SyslogEvent
from syslog_monitor.storage import EVENT_COLUMNS, connect

TEXT_MODE_WORDS = "words"
TEXT_MODE_SUBSTRING = "substring"
_MAX_ID = 2**63 - 1
_WORD_RE = re.compile(r"\w+", re.UNICODE)

Cursor = tuple[int, int]  # (received_at, id)

RULE_FIELDS = {
    "text": ("message", "hostname", "app_name", "structured_data"),
    "message": ("message",),
    "sender": ("source_ip", "hostname"),
    "hostname": ("hostname",),
    "app": ("app_name",),
}
RULE_OPERATORS = ("contains", "not_contains", "equals", "not_equals", "words", "not_words")
DEFAULT_HIGHLIGHT = "Initializing system"
DEFAULT_HIGHLIGHT_COLOR = "#7b1fa2"
HIGHLIGHT_SEPARATOR = ";"
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def parse_highlights(text: str) -> tuple[str, ...]:
    """Split ``"a; b;;A"`` into unique, non-empty texts (case-insensitive duplicates removed)."""
    result: dict[str, str] = {}
    for part in text.split(HIGHLIGHT_SEPARATOR):
        part = part.strip()
        if part:
            result.setdefault(part.translate(_ASCII_LOWER), part)
    return tuple(result.values())


def highlight_matches(message: str, text: str) -> bool:
    """True if any ``;``-separated text occurs literally (ASCII case-insensitive like SQLite LIKE)."""
    lowered = message.translate(_ASCII_LOWER)
    return any(part.translate(_ASCII_LOWER) in lowered for part in parse_highlights(text))


def highlight_sql(text: str) -> tuple[str, list[str]]:
    """SQL boolean expression matching :func:`highlight_matches` (``0`` if nothing to highlight)."""
    parts = parse_highlights(text)
    if not parts:
        return "0", []
    sql = " OR ".join("message LIKE ? ESCAPE '\\'" for _ in parts)
    return f"({sql})", [like_pattern(part) for part in parts]


@dataclass(frozen=True, slots=True)
class HighlightRule:
    text: str = ""
    color: str = DEFAULT_HIGHLIGHT_COLOR
    enabled: bool = True
    popup: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not isinstance(self.enabled, bool) \
                or not isinstance(self.popup, bool):
            raise ValueError("Invalid highlight rule")
        if not isinstance(self.color, str) or not re.fullmatch(r"#[0-9a-fA-F]{6}", self.color):
            raise ValueError("Highlight color must be #RRGGBB")


def active_highlights(rules: tuple[HighlightRule, ...]) -> tuple[HighlightRule, ...]:
    return tuple(rule for rule in rules if rule.enabled and parse_highlights(rule.text))


def matching_highlight(message: str, rules: tuple[HighlightRule, ...]) -> HighlightRule | None:
    """The first enabled, non-empty matching rule wins."""
    return next((rule for rule in rules if rule.enabled and highlight_matches(message, rule.text)), None)


@dataclass(frozen=True, slots=True)
class FilterRule:
    field: str = "message"
    operator: str = "contains"
    value: str = ""
    required: bool = False

    def __post_init__(self) -> None:
        if self.field not in RULE_FIELDS or self.operator not in RULE_OPERATORS:
            raise ValueError(f"Invalid filter rule: {self.field}/{self.operator}")
        if self.operator in ("words", "not_words") and self.field != "text":
            raise ValueError("Word search is only available for Text (all fields).")


@dataclass(frozen=True, slots=True)
class EventFilter:
    start_ms: int | None = None  # inclusive
    end_ms: int | None = None  # exclusive
    severities: frozenset[int | None] | None = None  # None = all; None inside = unknown
    facility: int | None = None
    sender: str = ""  # substring of source IP or reported host name
    app: str = ""  # substring of app name
    text: str = ""
    text_mode: str = TEXT_MODE_WORDS
    rules: tuple[FilterRule, ...] = ()
    rules_match: str = "all"

    def __post_init__(self) -> None:
        if self.rules_match not in ("all", "any"):
            raise ValueError(f"Invalid filter combination: {self.rules_match}")

    def with_time(self, start_ms: int | None, end_ms: int | None) -> "EventFilter":
        return replace(self, start_ms=start_ms, end_ms=end_ms)


class EventRow(NamedTuple):
    id: int
    received_at: int
    source_ip: str
    facility: int | None
    severity: int | None
    hostname: str | None
    app_name: str | None
    procid: str | None
    message: str
    issues: str

    @property
    def cursor(self) -> Cursor:
        return (self.received_at, self.id)


_ROW_COLUMNS = "id, received_at, source_ip, facility, severity, hostname, app_name, procid, message, issues"


@dataclass(frozen=True, slots=True)
class Histogram:
    start_ms: int
    end_ms: int
    counts: list[list[int]] = field(default_factory=list)  # [bucket][SeverityClass]
    highlights: list[int] = field(default_factory=list)
    highlight_rules: tuple[HighlightRule, ...] = ()
    highlight_counts: list[list[int]] = field(default_factory=list)  # [bucket][rule], first match wins
    highlight_hourly_counts: list[dict[int, int]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(sum(bucket) for bucket in self.counts)

    def class_total(self, cls: SeverityClass) -> int:
        return sum(bucket[cls] for bucket in self.counts)

    def highlight_hourly_statistics(self, rule_index: int) -> tuple[float, float]:
        """Mean and time-weighted population deviation of hourly rates, including empty hours."""
        hours = max(1, self.end_ms - self.start_ms) / 3_600_000
        counts = self.highlight_hourly_counts[rule_index]
        mean = sum(counts.values()) / hours
        second_moment = sum(
            count * count / min(1.0, hours - hour) for hour, count in counts.items()) / hours
        return mean, max(0.0, second_moment - mean * mean) ** 0.5


class SenderSummary(NamedTuple):
    source_ip: str
    hostname: str | None
    count: int
    last_ms: int


class HighlightBatch(NamedTuple):
    last_id: int  # highest event id inspected
    count: int  # matching rows in (after_id, last_id]
    rows: list[EventRow]  # newest matches first, bounded by the caller's limit


def fts_query(text: str) -> str | None:
    """Turn free user input into a safe FTS5 query (all words, prefix match)."""
    tokens = _WORD_RE.findall(text)
    if not tokens:
        return None
    return " ".join(f'"{token}"*' for token in tokens)


def like_pattern(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def build_where(f: EventFilter) -> tuple[str, list]:
    clauses: list[str] = []
    params: list = []
    if f.start_ms is not None:
        clauses.append("received_at >= ?")
        params.append(f.start_ms)
    if f.end_ms is not None:
        clauses.append("received_at < ?")
        params.append(f.end_ms)
    if f.severities is not None:
        known = sorted(s for s in f.severities if s is not None)
        parts = []
        if known:
            parts.append(f"severity IN ({', '.join('?' for _ in known)})")
            params.extend(known)
        if None in f.severities:
            parts.append("severity IS NULL")
        clauses.append(f"({' OR '.join(parts)})" if parts else "0")
    if f.facility is not None:
        clauses.append("facility = ?")
        params.append(f.facility)
    if f.sender.strip():
        pattern = like_pattern(f.sender.strip())
        clauses.append("(source_ip LIKE ? ESCAPE '\\' OR hostname LIKE ? ESCAPE '\\')")
        params += [pattern, pattern]
    if f.app.strip():
        clauses.append("app_name LIKE ? ESCAPE '\\'")
        params.append(like_pattern(f.app.strip()))
    if f.text.strip():
        if f.text_mode == TEXT_MODE_SUBSTRING:
            pattern = like_pattern(f.text.strip())
            clauses.append(
                "(message LIKE ? ESCAPE '\\' OR hostname LIKE ? ESCAPE '\\' "
                "OR app_name LIKE ? ESCAPE '\\')")
            params += [pattern, pattern, pattern]
        elif (query := fts_query(f.text)) is not None:
            clauses.append("id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
            params.append(query)
    rule_clauses = []
    rule_params = []
    for rule in f.rules:
        if not rule.value.strip():
            continue
        if rule.operator in ("words", "not_words"):
            query = fts_query(rule.value)
            if query is None:
                continue
            expression = "id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)"
            values = [query]
        else:
            columns = RULE_FIELDS[rule.field]
            contains = rule.operator in ("contains", "not_contains")
            comparison = "LIKE ? ESCAPE '\\'" if contains else "= ? COLLATE NOCASE"
            expression = " OR ".join(f"COALESCE({col}, '') {comparison}" for col in columns)
            value = like_pattern(rule.value.strip()) if contains else rule.value.strip()
            values = [value] * len(columns)
        if rule.operator.startswith("not_"):
            expression = f"NOT ({expression})"
        if rule.required:
            clauses.append(f"({expression})")
            params.extend(values)
        else:
            rule_clauses.append(f"({expression})")
            rule_params.extend(values)
    if rule_clauses:
        joiner = " AND " if f.rules_match == "all" else " OR "
        clauses.append(f"({joiner.join(rule_clauses)})")
        params.extend(rule_params)
    return (" AND ".join(clauses) or "1"), params


class QueryRunner:
    """Owns one read-only connection; safe to interrupt from another thread."""

    def __init__(self, db_file: Path) -> None:
        self._conn = connect(db_file, readonly=True)

    def interrupt(self) -> None:
        self._conn.interrupt()

    def close(self) -> None:
        self._conn.close()

    def _rows(self, sql: str, params: list) -> list[EventRow]:
        return [EventRow(*row) for row in self._conn.execute(sql, params)]

    def fetch_older(self, f: EventFilter, cursor: Cursor | None, limit: int) -> list[EventRow]:
        """Rows strictly older than ``cursor`` (newest first)."""
        where, params = build_where(f)
        if cursor is not None:
            where += " AND (received_at, id) < (?, ?)"
            params += list(cursor)
        sql = (f"SELECT {_ROW_COLUMNS} FROM events WHERE {where} "
               "ORDER BY received_at DESC, id DESC LIMIT ?")
        return self._rows(sql, params + [limit])

    def fetch_newer(self, f: EventFilter, cursor: Cursor, limit: int) -> list[EventRow]:
        """The ``limit`` rows directly newer than ``cursor`` (returned newest first)."""
        where, params = build_where(f)
        where += " AND (received_at, id) > (?, ?)"
        params += list(cursor)
        sql = (f"SELECT {_ROW_COLUMNS} FROM events WHERE {where} "
               "ORDER BY received_at ASC, id ASC LIMIT ?")
        return list(reversed(self._rows(sql, params + [limit])))

    def fetch_around(self, f: EventFilter, time_ms: int, before: int, after: int
                     ) -> tuple[list[EventRow], list[EventRow]]:
        """Rows around ``time_ms``, both newest first: (newer than time, at or before time)."""
        pivot = (time_ms, _MAX_ID)
        return self.fetch_newer(f, pivot, after), self.fetch_older(f, pivot, before)

    def find_match(self, f: EventFilter, text: str, text_mode: str,
                   cursor: Cursor | None = None, *, newer: bool = False) -> EventRow | None:
        """Find a text match within the active filters, independently of their text filter."""
        if not text.strip() or (text_mode == TEXT_MODE_WORDS and fts_query(text) is None):
            return None
        where, params = build_where(f)
        search_where, search_params = build_where(EventFilter(text=text, text_mode=text_mode))
        matches = f"({where}) AND ({search_where})"
        params += search_params
        if cursor is not None:
            matches += f" AND (received_at, id) {'>' if newer else '<'} (?, ?)"
            params += list(cursor)
        order = "ASC" if newer else "DESC"
        rows = self._rows(
            f"SELECT {_ROW_COLUMNS} FROM events WHERE {matches} "
            f"ORDER BY received_at {order}, id {order} LIMIT 1", params)
        return rows[0] if rows else None

    def find_highlight_match(self, f: EventFilter, text: str, cursor: Cursor | None = None,
                             *, newer: bool = False) -> EventRow | None:
        """Find the next row matching any text in a semicolon-separated highlight rule."""
        parts = parse_highlights(text)
        if not parts:
            return None
        where, params = build_where(f)
        search_where, search_params = highlight_sql(text)
        matches = f"({where}) AND ({search_where})"
        params.extend(search_params)
        if cursor is not None:
            matches += f" AND (received_at, id) {'>' if newer else '<'} (?, ?)"
            params += list(cursor)
        order = "ASC" if newer else "DESC"
        rows = self._rows(
            f"SELECT {_ROW_COLUMNS} FROM events WHERE {matches} "
            f"ORDER BY received_at {order}, id {order} LIMIT 1", params)
        return rows[0] if rows else None

    def fetch_context(self, f: EventFilter, cursor: Cursor, before: int, after: int
                      ) -> tuple[list[EventRow], list[EventRow]]:
        """Return context including the exact anchor, even with equal timestamps."""
        where, params = build_where(f)
        older = self._rows(
            f"SELECT {_ROW_COLUMNS} FROM events WHERE {where} AND (received_at, id) <= (?, ?) "
            "ORDER BY received_at DESC, id DESC LIMIT ?", params + list(cursor) + [before])
        return self.fetch_newer(f, cursor, after), older

    def histogram(self, f: EventFilter, start_ms: int, end_ms: int, buckets: int,
                  highlight: str | tuple[HighlightRule, ...] = "") -> Histogram:
        buckets = max(1, buckets)
        span = max(1, end_ms - start_ms)
        where, params = build_where(f.with_time(start_ms, end_ms))
        rules = active_highlights(
            (HighlightRule(highlight),) if isinstance(highlight, str) else highlight)
        cases: list[str] = []
        highlight_params: list[str] = []
        for i, rule in enumerate(rules):
            expr, values = highlight_sql(rule.text)
            cases.append(f"WHEN {expr} THEN {i}")
            highlight_params.extend(values)
        highlight_expr = "CASE " + " ".join(cases) + " ELSE -1 END" if cases else "-1"
        hour_expr = "(received_at - ?) / 3600000" if rules else "0"
        sql = (
            "SELECT MIN(?, (received_at - ?) * ? / ?) AS bucket, "
            "CASE WHEN severity IS NULL THEN 4 WHEN severity <= 3 THEN 0 "
            "WHEN severity = 4 THEN 1 WHEN severity <= 6 THEN 2 ELSE 3 END AS cls, "
            f"{highlight_expr} AS highlight_rule, COUNT(*), {hour_expr} AS hour "
            f"FROM events WHERE {where} "
            "GROUP BY bucket, cls, highlight_rule, hour"
        )
        counts = [[0] * len(SeverityClass) for _ in range(buckets)]
        highlights = [0] * buckets
        highlight_counts = [[0] * len(rules) for _ in range(buckets)]
        hourly_counts: list[dict[int, int]] = [{} for _ in rules]
        for bucket, cls, rule_index, count, hour in self._conn.execute(
                sql, [buckets - 1, start_ms, buckets, span, *highlight_params,
                      *([start_ms] if rules else []), *params]):
            counts[bucket][cls] += count
            if rule_index >= 0:
                highlights[bucket] += count
                highlight_counts[bucket][rule_index] += count
                hourly_counts[rule_index][hour] = hourly_counts[rule_index].get(hour, 0) + count
        return Histogram(start_ms, end_ms, counts, highlights, rules, highlight_counts, hourly_counts)

    def max_id(self) -> int:
        return self._conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]

    def count(self, f: EventFilter) -> int:
        where, params = build_where(f)
        return self._conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]

    def senders(self, since_ms: int, limit: int) -> list[SenderSummary]:
        """Sending devices since ``since_ms``, most recently active first."""
        rows = self._conn.execute(
            "SELECT source_ip, MAX(hostname), COUNT(*), MAX(received_at) FROM events "
            "WHERE received_at >= ? GROUP BY source_ip ORDER BY 4 DESC LIMIT ?", (since_ms, limit))
        return [SenderSummary(*row) for row in rows]

    def fetch_highlighted(self, f: EventFilter, highlight: str, limit: int,
                          offset: int = 0) -> list[EventRow]:
        """Rows within ``f`` matching any highlight text, newest first."""
        expr, highlight_params = highlight_sql(highlight)
        if expr == "0":
            return []
        where, params = build_where(f)
        return self._rows(
            f"SELECT {_ROW_COLUMNS} FROM events WHERE ({where}) AND {expr} "
            "ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?",
            params + highlight_params + [limit, offset])

    def severity_counts(self, f: EventFilter) -> dict[int | None, int]:
        where, params = build_where(f)
        return dict(self._conn.execute(
            f"SELECT severity, COUNT(*) FROM events WHERE {where} GROUP BY severity", params))

    def new_highlights(self, after_id: int, highlight: str, limit: int) -> HighlightBatch:
        """Highlight matches with ``id > after_id`` regardless of the view filter.

        ``last_id`` covers every new row (matching or not), so the caller can
        continue from there without rescanning.
        """
        last_id = max(after_id, self.max_id())
        expr, params = highlight_sql(highlight)
        if expr == "0" or last_id == after_id:
            return HighlightBatch(last_id, 0, [])
        count = self._conn.execute(
            f"SELECT COUNT(*) FROM events WHERE id > ? AND id <= ? AND {expr}",
            [after_id, last_id, *params]).fetchone()[0]
        rows = self._rows(
            f"SELECT {_ROW_COLUMNS} FROM events WHERE id > ? AND id <= ? AND {expr} "
            "ORDER BY id DESC LIMIT ?", [after_id, last_id, *params, limit]) if count else []
        return HighlightBatch(last_id, count, rows)

    def time_bounds(self, f: EventFilter = EventFilter()) -> tuple[int, int] | None:
        where, params = build_where(f)
        first = self._conn.execute(
            f"SELECT received_at FROM events WHERE {where} ORDER BY received_at, id LIMIT 1",
            params).fetchone()
        if first is None:
            return None
        last = self._conn.execute(
            f"SELECT received_at FROM events WHERE {where} ORDER BY received_at DESC, id DESC LIMIT 1",
            params).fetchone()
        return None if last is None else (first[0], last[0])

    def get_event(self, event_id: int) -> SyslogEvent | None:
        row = self._conn.execute(
            f"SELECT id, {', '.join(EVENT_COLUMNS)} FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        if row is None:
            return None
        values = dict(zip(("id", *EVENT_COLUMNS), row))
        values["issues"] = tuple(i for i in values["issues"].split(",") if i)
        return SyslogEvent(**values)
