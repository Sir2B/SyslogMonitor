"""Bounded sliding-window table model over the event list (newest first).

The model never holds more than ``max_rows`` rows. Loading newer rows trims the
oldest end and vice versa, so memory does not grow with the database size.
"""

from __future__ import annotations

import csv
import io

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt
from PySide6.QtGui import QBrush, QColor

from syslog_monitor.events import SeverityClass, facility_name, severity_class, severity_name
from syslog_monitor.query import DEFAULT_HIGHLIGHT, Cursor, EventRow, HighlightRule, matching_highlight
from syslog_monitor.ui.formatting import format_ts
from syslog_monitor.ui.palette import highlight_text_color, is_dark

COLUMNS = ("Time", "Severity", "Facility", "Sender", "Host", "Application", "Message")
MAX_MESSAGE_DISPLAY = 500

ROW_BACKGROUND = {
    SeverityClass.ERROR: QColor(255, 220, 220),
    SeverityClass.WARNING: QColor(255, 240, 205),
    SeverityClass.UNKNOWN: QColor(236, 236, 240),
    SeverityClass.INFO: QColor(225, 239, 255),
    SeverityClass.DEBUG: QColor(242, 244, 246),
}
ROW_BACKGROUND_DARK = {
    SeverityClass.ERROR: QColor("#39232a"),
    SeverityClass.WARNING: QColor("#332c20"),
    SeverityClass.UNKNOWN: QColor("#25232c"),
    SeverityClass.INFO: QColor("#1c2733"),
    SeverityClass.DEBUG: QColor("#1e2228"),
}

_Index = QModelIndex | QPersistentModelIndex


class EventTableModel(QAbstractTableModel):
    def __init__(self, max_rows: int = 5000, parent=None) -> None:
        super().__init__(parent)
        self.max_rows = max_rows
        self._rows: list[EventRow] = []
        self.highlight_text = DEFAULT_HIGHLIGHT
        self.highlight_rules = (HighlightRule(DEFAULT_HIGHLIGHT),)
        self.has_older = False
        self.has_newer = False

    # --- Qt model interface -------------------------------------------------
    def rowCount(self, parent: _Index = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: _Index = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index: _Index, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        if role == Qt.DisplayRole:
            return self._display(row, index.column())
        if role in (Qt.BackgroundRole, Qt.ForegroundRole):
            rule = matching_highlight(row.message, self.highlight_rules)
            if rule:
                color = QColor(rule.color)
                return QBrush(color if role == Qt.BackgroundRole else highlight_text_color(color))
        if role in (Qt.BackgroundRole, Qt.ForegroundRole):
            dark = is_dark()
            if role == Qt.ForegroundRole and not dark:
                return None
            colors = ROW_BACKGROUND_DARK if dark else ROW_BACKGROUND
            color = colors[severity_class(row.severity)]
            return QBrush(color if role == Qt.BackgroundRole else highlight_text_color(color))
        if role == Qt.ToolTipRole and index.column() == 6:
            return row.message[:2000]
        return None

    @staticmethod
    def _display(row: EventRow, column: int) -> str:
        match column:
            case 0:
                return format_ts(row.received_at)
            case 1:
                return severity_name(row.severity)
            case 2:
                return facility_name(row.facility)
            case 3:
                return row.source_ip
            case 4:
                return row.hostname or ""
            case 5:
                return f"{row.app_name}[{row.procid}]" if row.procid else (row.app_name or "")
            case _:
                text = row.message.replace("\r", " ").replace("\n", " ⏎ ")
                return text[:MAX_MESSAGE_DISPLAY]

    def set_highlight(self, text: str) -> None:
        self.set_highlight_rules((HighlightRule(text),))

    def set_highlight_rules(self, rules: tuple[HighlightRule, ...]) -> None:
        self.highlight_rules = rules
        self.highlight_text = ";".join(rule.text for rule in rules if rule.enabled)
        if self._rows:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self._rows) - 1, len(COLUMNS) - 1),
                                  [Qt.BackgroundRole, Qt.ForegroundRole])

    # --- window management --------------------------------------------------
    def copy_text(self, row_numbers: list[int]) -> str:
        """TSV in table order, with full messages and quoted multiline fields."""
        output = io.StringIO(newline="")
        writer = csv.writer(output, delimiter="\t", lineterminator="\r\n")
        for i in sorted(set(row_numbers)):
            row = self.row_at(i)
            if row is not None:
                writer.writerow([self._display(row, col) for col in range(6)] + [row.message])
        return output.getvalue()

    def row_at(self, i: int) -> EventRow | None:
        return self._rows[i] if 0 <= i < len(self._rows) else None

    @property
    def top_cursor(self) -> Cursor | None:
        return self._rows[0].cursor if self._rows else None

    @property
    def bottom_cursor(self) -> Cursor | None:
        return self._rows[-1].cursor if self._rows else None

    def reset_rows(self, rows: list[EventRow], *, has_older: bool, has_newer: bool) -> None:
        self.beginResetModel()
        self._rows = list(rows[: self.max_rows])
        self.has_older = has_older or len(rows) > self.max_rows
        self.has_newer = has_newer
        self.endResetModel()

    def prepend(self, rows: list[EventRow]) -> int:
        """Insert newer rows at the top; returns how many were inserted."""
        if not rows:
            return 0
        rows = rows[: self.max_rows]
        self.beginInsertRows(QModelIndex(), 0, len(rows) - 1)
        self._rows[:0] = rows
        self.endInsertRows()
        excess = len(self._rows) - self.max_rows
        if excess > 0:
            self.beginRemoveRows(QModelIndex(), self.max_rows, len(self._rows) - 1)
            del self._rows[self.max_rows:]
            self.endRemoveRows()
            self.has_older = True
        return len(rows)

    def append(self, rows: list[EventRow]) -> int:
        """Append older rows at the bottom; returns how many rows were trimmed at the top."""
        if not rows:
            return 0
        rows = rows[: self.max_rows]
        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(rows) - 1)
        self._rows.extend(rows)
        self.endInsertRows()
        excess = len(self._rows) - self.max_rows
        if excess > 0:
            self.beginRemoveRows(QModelIndex(), 0, excess - 1)
            del self._rows[:excess]
            self.endRemoveRows()
            self.has_newer = True
            return excess
        return 0
