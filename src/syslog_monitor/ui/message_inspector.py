"""Compact bottom panel for message details and frequency."""

from __future__ import annotations

import re
from html import escape

from PySide6.QtCore import QEvent, QPoint, QRectF, Qt, Signal
from PySide6.QtGui import QFont, QFontDatabase, QMouseEvent, QPainter, QPaintEvent, QPalette, QPen
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QSizePolicy, QSlider,
    QTextBrowser, QToolButton, QToolTip, QVBoxLayout, QWidget,
)

from syslog_monitor.analysis import DEFAULT_SIMILARITY, MIN_SIMILARITY
from syslog_monitor.events import SyslogEvent, facility_name, severity_name
from syslog_monitor.i18n import tr
from syslog_monitor.query import MessageFrequency, MessageStatistics
from syslog_monitor.ui.formatting import ISSUE_LABELS, format_count, format_ts
from syslog_monitor.ui.palette import is_dark

MODE_EXACT = "exact"
MODE_PATTERN = "pattern"
MODE_SIMILAR = "similar"
STATISTICS_MODES = (MODE_EXACT, MODE_PATTERN, MODE_SIMILAR)


def regex_error(pattern: str) -> str | None:
    try:
        re.compile(pattern)
    except re.error as exc:
        return str(exc)
    return None


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

    def event(self, event: QEvent) -> bool:
        # Bars show their own tooltip on mouse move; keep the parent's tooltip from appearing on top.
        if event.type() == QEvent.ToolTip:
            index = self.bucket_at(event.pos().x())
            if index is None:
                QToolTip.hideText()
            else:
                QToolTip.showText(event.globalPos() + QPoint(12, 12), self.bucket_tooltip(index), self)
            return True
        return super().event(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        index = self.bucket_at(event.position().x())
        if index is None:
            QToolTip.hideText()
        else:
            QToolTip.showText(event.globalPosition().toPoint() + QPoint(12, 12),
                              self.bucket_tooltip(index), self)


class MessageInspector(QWidget):
    mode_changed = Signal(str)
    regex_changed = Signal(object)  # str, or None for the automatic pattern
    similarity_changed = Signal(float)

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
                          (MODE_PATTERN, tr("Count messages matching the regex: only numbers may differ.")),
                          (MODE_SIMILAR, tr("Count messages whose words match at least {percent} % of this "
                                            "message.",
                                            percent=round(DEFAULT_SIMILARITY * 100)))):
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
        summary_row = QHBoxLayout()
        summary_row.setContentsMargins(0, 0, 0, 0)
        summary_row.addWidget(self.summary, 1)
        self.similarity_slider = QSlider(Qt.Horizontal)
        self.similarity_slider.setRange(round(MIN_SIMILARITY * 100), 100)
        self.similarity_slider.setSingleStep(5)
        self.similarity_slider.setPageStep(10)
        self.similarity_slider.setValue(round(DEFAULT_SIMILARITY * 100))
        self.similarity_slider.setFixedWidth(110)
        self.similarity_slider.setAccessibleName(tr("Similarity"))
        self.similarity_slider.setToolTip(tr("Minimum share of matching words for similar texts"))
        self.similarity_value = QLabel()
        self.similarity_value.setMinimumWidth(self.similarity_value.fontMetrics().horizontalAdvance("100 %"))
        self.similarity_value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.similarity_slider.valueChanged.connect(self._on_similarity_moved)
        summary_row.addWidget(self.similarity_slider)
        summary_row.addWidget(self.similarity_value)
        column.addLayout(summary_row)
        self.common = QLabel()
        self.common.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.common.setWordWrap(True)
        self.common.setTextFormat(Qt.PlainText)
        self.common.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.common.setToolTip(tr("Part shared by all similar messages; … marks differing words."))
        column.addWidget(self.common)
        regex_row = QHBoxLayout()
        self.regex = QLineEdit()
        self.regex.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.regex.setAccessibleName(tr("Regex pattern"))
        self.regex.setClearButtonEnabled(False)
        self._regex_tooltip = tr(
            "Editable Python regex (search; use ^ and $ for whole messages). Press Enter to apply.\n"
            "Automatic pattern: numbers are replaced by {number}; all other characters must match.",
            number=r"-?\d+(?:\.\d+)?")
        self.regex.setToolTip(self._regex_tooltip)
        self.regex.textEdited.connect(self._on_regex_edited)
        self.regex.returnPressed.connect(self._apply_regex)
        self.reset_regex = QToolButton()
        self.reset_regex.setText("↺")
        self.reset_regex.setToolTip(tr("Reset to the automatic pattern"))
        self.reset_regex.clicked.connect(self._reset_regex)
        self.copy_regex = QToolButton()
        self.copy_regex.setText(tr("Copy"))
        self.copy_regex.setToolTip(tr("Copy regex to the clipboard"))
        self.copy_regex.clicked.connect(lambda: QApplication.clipboard().setText(self.regex.text()))
        regex_row.addWidget(self.regex, 1)
        regex_row.addWidget(self.reset_regex)
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
        self._regex_dirty = False
        self._update_mode_labels()
        self.similarity_value.setText(f"{self.similarity_slider.value()} %")
        self._update_similarity_visibility()
        self.clear_statistics()
        return self.statistics

    def _on_regex_edited(self, text: str) -> None:
        self._regex_dirty = True
        error = regex_error(text)
        self.regex.setStyleSheet("" if error is None else "QLineEdit { border: 1px solid #d62728; }")
        self.regex.setToolTip(self._regex_tooltip if error is None
                              else tr("Invalid regex: {error}", error=error))
        self.reset_regex.setEnabled(True)

    def _apply_regex(self) -> None:
        text = self.regex.text()
        if regex_error(text) is not None:
            return
        self._regex_dirty = False
        self.regex_changed.emit(text if text else None)

    def _reset_regex(self) -> None:
        self._regex_dirty = False
        self.regex.setStyleSheet("")
        self.regex.setToolTip(self._regex_tooltip)
        self.regex_changed.emit(None)

    @property
    def similarity(self) -> float:
        return self.similarity_slider.value() / 100

    def set_similarity(self, value: float) -> None:
        self.similarity_slider.setValue(round(min(max(value, MIN_SIMILARITY), 1) * 100))

    def _on_similarity_moved(self, value: int) -> None:
        stepped = round(value / 5) * 5
        if stepped != value:
            self.similarity_slider.setValue(stepped)
            return
        self.similarity_value.setText(f"{value} %")
        self.similarity_changed.emit(value / 100)

    def _update_similarity_visibility(self) -> None:
        visible = self.mode == MODE_SIMILAR
        self.similarity_slider.setVisible(visible)
        self.similarity_value.setVisible(visible)

    @property
    def mode(self) -> str:
        return next((mode for mode, button in self.mode_buttons.items() if button.isChecked()), MODE_EXACT)

    def set_mode(self, mode: str) -> None:
        self.mode_buttons[mode if mode in STATISTICS_MODES else MODE_EXACT].setChecked(True)

    def _on_mode_toggled(self, _button, checked: bool) -> None:
        if checked:
            self._update_similarity_visibility()
            self._render_statistics()
            self.mode_changed.emit(self.mode)

    def _update_mode_labels(self) -> None:
        stats = self._stats
        for mode, title in ((MODE_EXACT, tr("Identical text")), (MODE_PATTERN, tr("Pattern (regex)")),
                            (MODE_SIMILAR, tr("Similar ({percent} %)", percent=round(
                                (stats.similarity if stats is not None else DEFAULT_SIMILARITY) * 100)))):
            if mode == MODE_PATTERN and stats is not None and stats.custom_regex:
                title = tr("Custom regex")
            if stats is not None:
                frequency = self._frequency(stats, mode)
                if frequency is not None:
                    title = f"{title} · {format_count(frequency.count)}"
            self.mode_buttons[mode].setText(title)

    @staticmethod
    def _frequency(stats: MessageStatistics, mode: str) -> MessageFrequency | None:
        return {MODE_EXACT: stats.exact, MODE_PATTERN: stats.similar, MODE_SIMILAR: stats.alike}[mode]

    def clear_statistics(self, message: str = "") -> None:
        self._stats = None
        self._update_mode_labels()
        self.summary.setText(message)
        self.regex.clear()
        self.regex.setStyleSheet("")
        self.regex.setToolTip(self._regex_tooltip)
        self._regex_dirty = False
        self.regex_row.hide()
        self.common.clear()
        self.common.hide()
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
        if not self.common.isHidden():
            parts.append(self.common.text())
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
        frequency = self._frequency(stats, self.mode) or stats.exact
        self.summary.setText(" · ".join((
            tr("Occurrences: {count}", count=format_count(frequency.count)),
            f"{frequency.per_hour:.2f}/h",
            tr("σ {deviation:.2f}/h", deviation=frequency.deviation))))
        self.summary.setToolTip(tr("Standard deviation: {deviation:.2f}/hour", deviation=frequency.deviation))
        if not self._regex_dirty:
            self.regex.setText(stats.regex)
            self.regex.setCursorPosition(0)
            self.reset_regex.setEnabled(stats.custom_regex)
        self.regex_row.setVisible(pattern)
        common = stats.common if self.mode == MODE_SIMILAR and stats.alike is not None else ""
        self.common.setText(tr("Common: {common}", common=common) if common else "")
        self.common.setVisible(bool(common))
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
        notes = ", ".join(tr(ISSUE_LABELS.get(issue, issue)) for issue in event.issues) or tr("none")
        # Related values are stacked in columns: sender, application, times.
        rows = [
            ((tr("Source"), f"{event.source_ip}:{event.source_port}"),
             (tr("Application"), event.app_name),
             (tr("Received"), format_ts(event.received_at))),
            ((tr("Reported host"), event.hostname),
             ("PID / MsgID", f"{event.procid or '–'} / {event.msgid or '–'}"),
             (tr("Sender time"), reported)),
            ((tr("Severity"), f"{tr(severity_name(event.severity))} ({event.severity if event.severity is not None else '–'})"),
             (tr("Facility"), f"{facility_name(event.facility)} ({event.facility if event.facility is not None else '–'})"),
             (tr("Format"), event.format)),
        ]
        spacer = "<td width='18'></td>"
        table = "".join("<tr>" + spacer.join(
            f"<td><b>{value(label)}</b>&nbsp;&nbsp;</td><td>{value(text)}</td>" for label, text in row)
            + "</tr>" for row in rows)
        extra = f"<p><b>{tr('Structured Data')}:</b> {value(event.structured_data)}</p>" if event.structured_data else ""
        self.details.setHtml(
            "<style>p { margin-top: 3px; margin-bottom: 3px; }</style>"
            f"<table cellspacing='0' cellpadding='1'>{table}</table>"
            f"<p><b>{tr('Parser notes')}:</b> {value(notes)}</p>"
            f"<p><b>{tr('Message')}:</b><br>{value(event.message).replace(chr(10), '<br>')}</p>"
            + extra +
            f"<small>{escape(tr('Raw data ({count} bytes)', count=len(event.raw)))}</small>")
        self.raw.setPlainText(event.raw.decode("utf-8", errors="backslashreplace"))

