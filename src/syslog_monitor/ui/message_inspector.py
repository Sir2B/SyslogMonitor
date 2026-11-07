"""Compact bottom panel for message details and frequency."""

from __future__ import annotations

from html import escape

from PySide6.QtCore import QPoint, QRectF, Qt, Signal
from PySide6.QtGui import QFont, QFontDatabase, QMouseEvent, QPainter, QPaintEvent, QPalette, QPen
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QSizePolicy,
    QTextBrowser, QToolButton, QToolTip, QVBoxLayout, QWidget,
)

from syslog_monitor.events import SyslogEvent, facility_name, severity_name
from syslog_monitor.i18n import tr
from syslog_monitor.query import MessageFrequency, MessageStatistics
from syslog_monitor.ui.formatting import ISSUE_LABELS, format_count, format_ts
from syslog_monitor.ui.palette import is_dark

MODE_EXACT = "exact"
MODE_PATTERN = "pattern"
STATISTICS_MODES = (MODE_EXACT, MODE_PATTERN)


def format_bucket(ms: int) -> str:
    for unit, size in (("d", 86_400_000), ("h", 3_600_000), ("min", 60_000), ("s", 1_000)):
        if ms >= size and ms % size == 0:
            return f"{ms // size} {unit}"
    return f"{ms / 1000:g} s"


class FrequencyGraph(QWidget):
    """Bar chart of occurrences per time bucket with a marker for the selected message."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self.setMinimumHeight(48)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setAccessibleName(tr("Occurrences over time"))
        self.start_ms = 0
        self.bucket_ms = 1
        self.series: tuple[int, ...] = ()
        self.marker_ms: int | None = None

    def set_series(self, start_ms: int, bucket_ms: int, series: tuple[int, ...],
                   marker_ms: int | None = None) -> None:
        self.start_ms, self.bucket_ms, self.series, self.marker_ms = start_ms, bucket_ms, series, marker_ms
        self.update()

    def clear(self) -> None:
        self.set_series(0, 1, ())

    def _plot_rect(self) -> QRectF:
        top = self.fontMetrics().height() + 2
        return QRectF(1, top, max(1, self.width() - 2), max(1, self.height() - top - 1))

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        palette = self.palette()
        painter.fillRect(self.rect(), palette.color(QPalette.Base))
        if not self.series:
            return
        plot = self._plot_rect()
        peak = max(self.series)
        painter.setPen(palette.color(QPalette.PlaceholderText))
        painter.drawText(QRectF(4, 0, self.width() - 8, plot.top()), Qt.AlignLeft | Qt.AlignVCenter,
                         tr("max {count} per {bucket}", count=format_count(peak),
                            bucket=format_bucket(self.bucket_ms)))
        painter.setPen(QPen(palette.color(QPalette.Mid), 1))
        painter.drawLine(plot.bottomLeft(), plot.bottomRight())
        width = plot.width() / len(self.series)
        color = palette.color(QPalette.Highlight)
        if is_dark():
            color = color.lighter(130)
        for index, count in enumerate(self.series):
            if count and peak:
                height = max(2.0, plot.height() * count / peak)
                painter.fillRect(QRectF(plot.left() + index * width + (1 if width > 4 else 0),
                                        plot.bottom() - height, max(1.0, width - (2 if width > 4 else 0)),
                                        height), color)
        if self.marker_ms is not None:
            span = self.bucket_ms * len(self.series)
            x = plot.left() + plot.width() * (self.marker_ms - self.start_ms) / span
            if plot.left() <= x <= plot.right():
                painter.setPen(QPen(palette.color(QPalette.Text), 1, Qt.DashLine))
                painter.drawLine(round(x), round(plot.top()), round(x), round(plot.bottom()))

    def bucket_at(self, x: float) -> int | None:
        plot = self._plot_rect()
        if not self.series or not plot.left() <= x <= plot.right():
            return None
        return min(len(self.series) - 1, int((x - plot.left()) * len(self.series) / plot.width()))

    def bucket_tooltip(self, index: int) -> str:
        start = self.start_ms + index * self.bucket_ms
        return tr("{start} – {end}: {count} occurrences", start=format_ts(start),
                  end=format_ts(start + self.bucket_ms, with_date=False),
                  count=format_count(self.series[index]))

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        index = self.bucket_at(event.position().x())
        if index is None:
            QToolTip.hideText()
        else:
            QToolTip.showText(event.globalPosition().toPoint() + QPoint(12, 12),
                              self.bucket_tooltip(index), self)


class MessageInspector(QWidget):
    mode_changed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.setPlaceholderText(tr("Select a message to view its details and raw data."))
        left_layout.addWidget(self.details, 1)
        self.toggle = QToolButton(checkable=True)
        self.toggle.setText(tr("Raw data"))
        self.toggle.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle.setArrowType(Qt.RightArrow)
        self.toggle.toggled.connect(self._expand_details)
        left_layout.addWidget(self.toggle)
        self.raw = QPlainTextEdit(readOnly=True)
        self.raw.hide()
        left_layout.addWidget(self.raw, 1)
        layout.addWidget(left, 3)
        layout.addWidget(self._build_statistics(), 2)

    def _build_statistics(self) -> QWidget:
        self.statistics = QWidget()
        self.statistics.setAccessibleName(tr("Message statistics"))
        column = QVBoxLayout(self.statistics)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(4)
        modes = QHBoxLayout()
        modes.setSpacing(0)
        self.mode_group = QButtonGroup(self)
        self.mode_buttons: dict[str, QToolButton] = {}
        for mode, tip in ((MODE_EXACT, tr("Count messages with exactly the same text.")),
                          (MODE_PATTERN, tr("Count messages matching the regex: only numbers may differ."))):
            button = QToolButton(checkable=True)
            button.setToolTip(tip)
            button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            self.mode_group.addButton(button)
            self.mode_buttons[mode] = button
            modes.addWidget(button)
        self.mode_buttons[MODE_EXACT].setChecked(True)
        modes_style = ("QToolButton { padding: 3px 8px; } QToolButton:checked { "
                       "background: palette(highlight); color: palette(highlighted-text); font-weight: bold; }")
        for button in self.mode_buttons.values():
            button.setStyleSheet(modes_style)
        self.mode_group.buttonToggled.connect(self._on_mode_toggled)
        column.addLayout(modes)
        self.summary = QLabel()
        bold = QFont(self.summary.font())
        bold.setBold(True)
        self.summary.setFont(bold)
        self.summary.setWordWrap(True)
        self.summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        column.addWidget(self.summary)
        regex_row = QHBoxLayout()
        self.regex = QLineEdit(readOnly=True)
        self.regex.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.regex.setAccessibleName(tr("Regex pattern"))
        self.regex.setToolTip(tr("Regex pattern: numbers are replaced by {number}; all other characters must match.",
                                 number=r"-?\d+(?:\.\d+)?"))
        self.copy_regex = QToolButton()
        self.copy_regex.setText(tr("Copy"))
        self.copy_regex.setToolTip(tr("Copy regex to the clipboard"))
        self.copy_regex.clicked.connect(lambda: QApplication.clipboard().setText(self.regex.text()))
        regex_row.addWidget(self.regex, 1)
        regex_row.addWidget(self.copy_regex)
        self.regex_row = QWidget()
        self.regex_row.setLayout(regex_row)
        regex_row.setContentsMargins(0, 0, 0, 0)
        column.addWidget(self.regex_row)
        self.graph = FrequencyGraph()
        column.addWidget(self.graph, 1)
        self.footer = QLabel()
        self.footer.setWordWrap(True)
        self.footer.setForegroundRole(QPalette.PlaceholderText)
        column.addWidget(self.footer)
        self._stats: MessageStatistics | None = None
        self._marker_ms: int | None = None
        self._update_mode_labels()
        self.clear_statistics()
        return self.statistics

    @property
    def mode(self) -> str:
        return MODE_PATTERN if self.mode_buttons[MODE_PATTERN].isChecked() else MODE_EXACT

    def set_mode(self, mode: str) -> None:
        self.mode_buttons[mode if mode in STATISTICS_MODES else MODE_EXACT].setChecked(True)

    def _on_mode_toggled(self, _button, checked: bool) -> None:
        if checked:
            self._render_statistics()
            self.mode_changed.emit(self.mode)

    def _update_mode_labels(self) -> None:
        stats = self._stats
        for mode, title in ((MODE_EXACT, tr("Identical text")), (MODE_PATTERN, tr("Pattern (regex)"))):
            if stats is not None:
                count = (stats.exact if mode == MODE_EXACT else stats.similar).count
                title = f"{title} · {format_count(count)}"
            self.mode_buttons[mode].setText(title)

    def clear_statistics(self, message: str = "") -> None:
        self._stats = None
        self._update_mode_labels()
        self.summary.setText(message)
        self.regex.clear()
        self.regex_row.hide()
        self.graph.clear()
        self.footer.clear()
        self.statistics.setToolTip("")

    def show_statistics_message(self, message: str) -> None:
        self.clear_statistics(message)

    def statistics_text(self) -> str:
        parts = [self.summary.text()]
        if self._stats is not None:
            parts.insert(0, " | ".join(button.text() for button in self.mode_buttons.values()))
        if not self.regex_row.isHidden():
            parts.append(self.regex.text())
        parts.append(self.footer.text())
        return "\n".join(part for part in parts if part)

    def show_statistics(self, stats: MessageStatistics, scope: list[str],
                        marker_ms: int | None = None) -> None:
        self._stats, self._marker_ms = stats, marker_ms
        self.statistics.setToolTip("\n".join(scope))
        self._update_mode_labels()
        self._render_statistics()

    def _render_statistics(self) -> None:
        stats = self._stats
        if stats is None:
            return
        pattern = self.mode == MODE_PATTERN
        frequency: MessageFrequency = stats.similar if pattern else stats.exact
        self.summary.setText(" · ".join((
            tr("Occurrences: {count}", count=format_count(frequency.count)),
            f"{frequency.per_hour:.2f}/h",
            tr("σ {deviation:.2f}/h", deviation=frequency.deviation))))
        self.summary.setToolTip(tr("Standard deviation: {deviation:.2f}/hour", deviation=frequency.deviation))
        self.regex.setText(stats.regex)
        self.regex.setCursorPosition(0)
        self.regex_row.setVisible(pattern)
        self.graph.set_series(stats.start_ms, stats.bucket_ms, frequency.series, self._marker_ms)
        self.footer.setText(tr("{start} – {end} · per {bucket}", start=format_ts(stats.start_ms),
                               end=format_ts(stats.end_ms), bucket=format_bucket(stats.bucket_ms)))

    def _expand_details(self, expanded: bool) -> None:
        self.raw.setVisible(expanded)
        self.toggle.setArrowType(Qt.DownArrow if expanded else Qt.RightArrow)

    def clear(self) -> None:
        self.raw.clear()
        self.details.clear()
        self.clear_statistics()

    def show_event(self, event: SyslogEvent) -> None:
        def value(text) -> str:
            return escape(str(text if text is not None else "–"))

        reported = event.reported_time_text or "–"
        if event.reported_time_utc is not None:
            reported += f" → {format_ts(event.reported_time_utc)} ({tr('local')})"
        rows = [
            ((tr("Source"), f"{event.source_ip}:{event.source_port}"),
             (tr("Reported host"), event.hostname)),
            ((tr("Application"), event.app_name), ("PID / MsgID", f"{event.procid or '–'} / {event.msgid or '–'}")),
            ((tr("Received"), format_ts(event.received_at)),
             (tr("Sender time"), reported)),
            ((tr("Severity"), f"{tr(severity_name(event.severity))} ({event.severity if event.severity is not None else '–'})"),
             (tr("Facility"), f"{facility_name(event.facility)} ({event.facility if event.facility is not None else '–'})")),
        ]
        table = "".join("<tr>" + "".join(
            f"<td><b>{value(label)}</b></td><td>{value(text)}</td>" for label, text in row)
            + "</tr>" for row in rows)
        notes = ", ".join(tr(ISSUE_LABELS.get(issue, issue)) for issue in event.issues) or tr("none")
        extra = f"<p><b>{tr('Structured Data')}:</b> {value(event.structured_data)}</p>" if event.structured_data else ""
        self.details.setHtml(
            "<style>p { margin-top: 3px; margin-bottom: 3px; }</style>"
            f"<table width='100%' cellspacing='0' cellpadding='1'>{table}</table>"
            f"<p><b>{tr('Format')}:</b> {value(event.format)} &nbsp; "
            f"<b>{tr('Parser notes')}:</b> {value(notes)}</p>"
            f"<p><b>{tr('Message')}:</b><br>{value(event.message).replace(chr(10), '<br>')}</p>"
            + extra +
            f"<small>{escape(tr('Raw data ({count} bytes)', count=len(event.raw)))}</small>")
        self.raw.setPlainText(event.raw.decode("utf-8", errors="backslashreplace"))

