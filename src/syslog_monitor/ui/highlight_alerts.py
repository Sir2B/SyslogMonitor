"""Aggregated, rate-limited notifications for newly received highlight matches."""

from __future__ import annotations

import time
from typing import Callable

from syslog_monitor.query import EventRow, HighlightBatch
from syslog_monitor.ui.formatting import format_count, format_ts

MAX_LISTED = 3
MAX_MESSAGE_CHARS = 120
MIN_INTERVAL_S = 10.0

ShowFunc = Callable[[str, str], None]


def _describe(row: EventRow) -> str:
    sender = row.hostname or row.source_ip
    message = " ".join(row.message.split())
    if len(message) > MAX_MESSAGE_CHARS:
        message = message[:MAX_MESSAGE_CHARS - 1] + "…"
    return f"{format_ts(row.received_at, with_date=False)[:8]} {sender}: {message}"


class HighlightAlerter:
    """Collects new matches and shows at most one notification per ``min_interval_s``.

    Matches arriving during the quiet period are summed up and shown together
    once the interval has passed, so a burst produces one popup, not hundreds.
    """

    def __init__(self, show: ShowFunc, *, min_interval_s: float = MIN_INTERVAL_S,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.show = show
        self.enabled = True
        self._min_interval = min_interval_s
        self._clock = clock
        self._last_shown: float | None = None
        self._pending = 0
        self._latest: list[EventRow] = []

    @property
    def pending(self) -> int:
        return self._pending

    def add(self, batch: HighlightBatch) -> None:
        if not self.enabled or batch.count <= 0:
            return
        self._pending += batch.count
        self._latest = (list(batch.rows) + self._latest)[:MAX_LISTED]

    def flush(self) -> bool:
        """Show pending matches if the rate limit allows it; returns True if shown."""
        if not self._pending:
            return False
        now = self._clock()
        if self._last_shown is not None and now - self._last_shown < self._min_interval:
            return False
        count = self._pending
        title = ("Highlight: 1 new message" if count == 1
                 else f"Highlight: {format_count(count)} new messages")
        lines = [_describe(row) for row in self._latest]
        if count > len(lines):
            lines.append(f"… and {format_count(count - len(lines))} more")
        self._pending = 0
        self._latest = []
        self._last_shown = now
        self.show(title, "\n".join(lines))
        return True

    def clear(self) -> None:
        self._pending = 0
        self._latest = []
