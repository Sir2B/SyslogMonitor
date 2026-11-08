"""Rows shown in the message table: head reload, keyset paging, autoscroll and the newer banner."""

from __future__ import annotations

import time
from collections.abc import Callable

from PySide6.QtCore import QEvent, QObject, QTimer, Signal
from PySide6.QtWidgets import QAbstractItemView

from syslog_monitor.query import Cursor, EventFilter
from syslog_monitor.ui.event_model import EventTableModel
from syslog_monitor.ui.event_table import NEWER_COUNT_LIMIT, EventTable
from syslog_monitor.ui.query_worker import QueryClient

PAGE_SIZE = 500
MAX_ROWS = 5000
LIVE_FETCH_LIMIT = 1000
SCROLL_PREFETCH_ROWS = 50


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


class LogView(QObject):
    """Keeps the table model in sync with storage.

    While following (autoscroll on) new rows are prepended on every :meth:`tick`;
    otherwise the view stays put and the banner above the first row counts what
    is newer. The owner reacts to :attr:`live_changed` (status, zoom, reload)
    and :attr:`reload_requested` (too far behind to catch up incrementally).
    """

    live_changed = Signal(bool)
    reload_requested = Signal()
    visible_range_changed = Signal()

    def __init__(self, table: EventTable, model: EventTableModel, queries: QueryClient,
                 list_filter: Callable[[], EventFilter], is_active: Callable[[], bool],
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.table, self.model, self.queries = table, model, queries
        self._list_filter, self._is_active = list_filter, is_active
        self.live = True
        self._paused_at_ms = 0
        self._adjusting_scroll = False
        self._older_request: int | None = None
        self._newer_request: int | None = None
        self._live_request: int | None = None
        self._count_request: int | None = None
        self.banner = table.banner
        self._count_timer = QTimer(self, singleShot=True, interval=150)
        self._count_timer.timeout.connect(self._request_newer_count)
        self._visible_timer = QTimer(self, singleShot=True)
        self._visible_timer.timeout.connect(self.visible_range_changed)
        for signal in (model.modelReset, model.rowsInserted):
            signal.connect(lambda *_args: self._count_timer.start() if not self.live else None)
        for signal in (model.modelReset, model.rowsInserted, model.rowsRemoved,
                       table.verticalScrollBar().rangeChanged):
            signal.connect(lambda *_args: self._visible_timer.start(0))
        table.verticalScrollBar().valueChanged.connect(self._on_scroll)
        table.viewport().installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt naming
        if watched is self.table.viewport() and event.type() == QEvent.Resize:
            self._visible_timer.start(0)
        return super().eventFilter(watched, event)

    def shutdown(self) -> None:
        self._visible_timer.stop()
        self._count_timer.stop()

    # ------------------------------------------------------------- autoscroll
    def set_live(self, live: bool, *, notify: bool = True) -> None:
        if live == self.live:
            return
        self.live = live
        self.table.set_banner_visible(not live)
        if not live:
            self._paused_at_ms = _now_ms()
            self.banner.set_count(None)
            self._count_timer.start()
        if notify:
            self.live_changed.emit(live)

    def mark_seen(self) -> None:
        """Everything stored so far no longer counts as new in the banner."""
        self._paused_at_ms = _now_ms()

    def tick(self) -> None:
        if not self._is_active():
            return
        if not self.live:
            if not self.queries.is_pending(self._count_request):
                self._request_newer_count()
            return
        if self.queries.is_pending(self._live_request):
            return
        cursor = self.model.top_cursor
        if cursor is None:
            self.reload_requested.emit()
            return
        f = self._list_filter()
        self._live_request = self.queries.submit(
            lambda r: r.fetch_newer(f, cursor, LIVE_FETCH_LIMIT), self._apply_live)

    def _apply_live(self, rows) -> None:
        if not self.live:
            return
        if len(rows) >= LIVE_FETCH_LIMIT:
            self.reload_requested.emit()  # too far behind: start again from the newest rows
            return
        self.model.prepend(rows)

    def _request_newer_count(self) -> None:
        if self.live:
            return
        top_row = self.model.row_at(self.table.rowAt(0))
        top = top_row.cursor if top_row else self.model.top_cursor
        since_pause: Cursor = (self._paused_at_ms, 0)
        new_cursor = since_pause if top is None else max(top, since_pause)
        f = self._list_filter()
        self._count_request = self.queries.submit(
            lambda r: (r.count_newer(f, top, NEWER_COUNT_LIMIT),
                       r.count_newer(f, new_cursor, NEWER_COUNT_LIMIT)),
            lambda counts: self.banner.set_count(*counts) if not self.live else None)

    # ---------------------------------------------------------------- loading
    def cancel(self) -> None:
        """Forget paging requests; call after ``queries.new_generation()``."""
        self._older_request = self._newer_request = self._live_request = None

    def load_head(self) -> None:
        f = self._list_filter()
        self.queries.submit(lambda r: r.fetch_older(f, None, PAGE_SIZE + 1), self._apply_head)

    def _apply_head(self, rows) -> None:
        self.model.reset_rows(rows[:PAGE_SIZE], has_older=len(rows) > PAGE_SIZE, has_newer=False)
        self._scroll_to(0)

    def load_around(self, time_ms: int) -> None:
        f, before, after = self._list_filter(), PAGE_SIZE, PAGE_SIZE // 2
        self.queries.submit(lambda r: r.fetch_around(f, time_ms, before + 1, after + 1),
                            lambda result: self.show_context(result, before, after))

    def show_context(self, result, before: int = PAGE_SIZE, after: int = PAGE_SIZE // 2) -> None:
        """Show ``(newer, older)`` rows around an anchor and select it."""
        newer, older = result
        rows = newer[-after:] + older[:before]
        self._adjusting_scroll = True
        try:
            self.model.reset_rows(rows, has_older=len(older) > before, has_newer=len(newer) > after)
            anchor = min(len(newer[-after:]), max(len(rows) - 1, 0))
            if rows:
                self.table.selectRow(anchor)
                self.table.scrollTo(self.model.index(anchor, 0), QAbstractItemView.PositionAtCenter)
        finally:
            self._adjusting_scroll = False
        self.visible_range_changed.emit()

    def _on_scroll(self, value: int) -> None:
        if self._adjusting_scroll:
            return
        self.visible_range_changed.emit()
        if not self.live:
            self._count_timer.start()
        if self.live and value > 0:
            self.set_live(False)  # user scrolled away: pause the live view
        bar = self.table.verticalScrollBar()
        if (value >= bar.maximum() - SCROLL_PREFETCH_ROWS and self.model.has_older
                and not self.queries.is_pending(self._older_request)):
            self._request_older()
        if (value <= SCROLL_PREFETCH_ROWS // 5 and self.model.has_newer and not self.live
                and not self.queries.is_pending(self._newer_request)):
            self._request_newer()

    def _request_older(self) -> None:
        cursor, f = self.model.bottom_cursor, self._list_filter()
        if cursor is None:
            return
        self._older_request = self.queries.submit(
            lambda r: r.fetch_older(f, cursor, PAGE_SIZE + 1), self._apply_older)

    def _apply_older(self, rows) -> None:
        removed = self.model.append(rows[:PAGE_SIZE])
        self.model.has_older = len(rows) > PAGE_SIZE
        if removed:
            self._scroll_to(self.table.verticalScrollBar().value() - removed)

    def _request_newer(self) -> None:
        cursor, f = self.model.top_cursor, self._list_filter()
        if cursor is None:
            return
        self._newer_request = self.queries.submit(
            lambda r: r.fetch_newer(f, cursor, PAGE_SIZE + 1), self._apply_newer)

    def _apply_newer(self, rows) -> None:
        has_more = len(rows) > PAGE_SIZE
        inserted = self.model.prepend(rows[-PAGE_SIZE:])  # the rows closest to the cursor
        self.model.has_newer = has_more
        self._scroll_to(self.table.verticalScrollBar().value() + inserted)

    def _scroll_to(self, value: int) -> None:
        self._adjusting_scroll = True
        try:
            self.table.verticalScrollBar().setValue(max(0, value))
        finally:
            self._adjusting_scroll = False
        self.visible_range_changed.emit()
