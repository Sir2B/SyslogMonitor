"""Load details and periodically refresh statistics for the selected message."""

from __future__ import annotations

import time
from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer, Signal

from syslog_monitor.events import SyslogEvent
from syslog_monitor.i18n import tr
from syslog_monitor.query import EventFilter, EventRow
from syslog_monitor.ui.event_model import EventTableModel
from syslog_monitor.ui.formatting import format_ts
from syslog_monitor.ui.message_inspector import MessageInspector
from syslog_monitor.ui.query_worker import QueryClient


class InspectorController(QObject):
    error = Signal(str)

    def __init__(self, inspector: MessageInspector, model: EventTableModel,
                 details_queries: QueryClient, statistics_queries: QueryClient,
                 list_filter: Callable[[], EventFilter], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.inspector = inspector
        self.model = model
        self.details_queries = details_queries
        self.statistics_queries = statistics_queries
        self._list_filter = list_filter
        self._selected_row: EventRow | None = None
        self._custom_regex: tuple[int, str] | None = None
        self.timer = QTimer(self, singleShot=True, interval=100)
        self.timer.timeout.connect(self._request_statistics)
        statistics_queries.error.connect(self._on_error)
        inspector.regex_changed.connect(self._set_regex)
        model.modelReset.connect(self.clear)

    def shutdown(self) -> None:
        self.timer.stop()
        self.statistics_queries.shutdown()

    def select_row(self, current, _previous) -> None:
        row = self.model.row_at(current.row())
        self.clear()
        self._selected_row = row
        if row is None:
            return
        self.details_queries.submit(
            lambda runner: runner.get_event(row.id),
            lambda event: self._show_details(event)
            if self._selected_row is not None and self._selected_row.id == row.id else None)
        self.inspector.show_statistics_message(tr("Calculating message statistics…"))
        self.timer.start(100)

    def clear(self) -> None:
        self._selected_row = None
        self.statistics_queries.new_generation()
        self.timer.stop()
        self.inspector.clear()

    def _on_error(self, message: str) -> None:
        self.inspector.show_statistics_message(tr("Statistics failed: {message}", message=message))
        self.error.emit(message)

    def _set_regex(self, regex: str | None) -> None:
        row = self._selected_row
        if row is None:
            return
        self._custom_regex = (row.id, regex) if regex else None
        self.statistics_queries.new_generation()
        self.timer.start(0)

    def _request_statistics(self) -> None:
        row = self._selected_row
        if row is None:
            return
        if self.statistics_queries.busy:
            self.timer.start(250)
            return
        filters, now = self._list_filter(), time.time_ns() // 1_000_000
        regex = self._custom_regex[1] if self._custom_regex and self._custom_regex[0] == row.id else None

        def job(runner):
            return runner.get_event(row.id), runner.message_statistics(filters, row, now, regex)

        def apply(result):
            if self._selected_row is None or self._selected_row.id != row.id:
                return
            event, stats = result
            self._show_details(event)
            if event is None:
                self.inspector.show_statistics_message(tr("Message no longer exists (deleted by retention)."))
                return
            lines = [
                tr("Same sender and application; active filters and time range (including zoom)."),
                tr("Sender: {sender} · Application: {app}", sender=row.source_ip, app=row.app_name or "–"),
                f"{format_ts(stats.start_ms)} – {format_ts(stats.end_ms)}",
                tr("Regex: {regex}", regex=stats.regex),
                tr("Only numbers vary; all other characters must match exactly. This is a heuristic, not semantic similarity."),
                tr("Rates include empty hours. Partial hours are time-weighted; minimum observation window: 1 second. For an open start, use the first matching sender/application event."),
            ]
            self.inspector.show_statistics(stats, lines, row.received_at)
            self.timer.start(5000)

        self.statistics_queries.submit(job, apply)

    def _show_details(self, event: SyslogEvent | None) -> None:
        if event is None:
            self.inspector.details.setPlainText(tr("Message no longer exists (deleted by retention)."))
        else:
            self.inspector.show_event(event)
