"""Time minimap: stacked severity histogram with error markers.

Click jumps to a point in time, dragging selects a range to zoom into.
"""

from __future__ import annotations

import math

from PySide6.QtCore import QPoint, QRect, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QMouseEvent, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from syslog_monitor.events import SEVERITY_CLASS_LABELS, SeverityClass
from syslog_monitor.query import Histogram
from syslog_monitor.ui.formatting import format_count, format_ts
from syslog_monitor.ui.palette import HIGHLIGHT_COLOR

CLASS_COLORS = {
    SeverityClass.ERROR: QColor(214, 39, 40),
    SeverityClass.WARNING: QColor(245, 150, 20),
    SeverityClass.INFO: QColor(70, 130, 200),
    SeverityClass.DEBUG: QColor(160, 170, 180),
    SeverityClass.UNKNOWN: QColor(140, 110, 80),  # not purple: purple is reserved for highlights
}
# Drawing order bottom -> top: errors at the base so they are always visible.
STACK_ORDER = (SeverityClass.ERROR, SeverityClass.WARNING, SeverityClass.UNKNOWN,
               SeverityClass.INFO, SeverityClass.DEBUG)
ERROR_STRIP_PX = 5
HIGHLIGHT_STRIP_PX = 6
AXIS_PX = 14
PX_PER_BUCKET = 3
DRAG_THRESHOLD_PX = 4


def bar_height(count: int, max_count: int, available: float) -> float:
    """Square-root scale so single errors stay visible next to large bursts."""
    if count <= 0 or max_count <= 0:
        return 0.0
    return max(1.0, available * math.sqrt(count / max_count))


class MinimapWidget(QWidget):
    time_clicked = Signal("qlonglong")  # epoch ms
    range_selected = Signal("qlonglong", "qlonglong")  # start ms, end ms

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(70)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMouseTracking(True)
        self.setCursor(Qt.PointingHandCursor)
        self._hist: Histogram | None = None
        self._marker_ms: int | None = None
        self._press_x: int | None = None
        self._drag_x: int | None = None

    @property
    def histogram(self) -> Histogram | None:
        return self._hist

    def preferred_buckets(self) -> int:
        return max(10, self.width() // PX_PER_BUCKET)

    def set_histogram(self, hist: Histogram) -> None:
        self._hist = hist
        self.setMinimumHeight(70 + max(0, self._highlight_height(hist) - HIGHLIGHT_STRIP_PX))
        self.update()

    @staticmethod
    def _highlight_height(hist: Histogram) -> int:
        return max(HIGHLIGHT_STRIP_PX, len(hist.highlight_rules) * 3)

    def set_marker(self, time_ms: int | None) -> None:
        if time_ms != self._marker_ms:
            self._marker_ms = time_ms
            self.update()

    # --- geometry helpers -----------------------------------------------------
    def _plot_rect(self) -> QRect:
        return self.rect().adjusted(0, 0, -1, -AXIS_PX)

    def x_to_time(self, x: float) -> int:
        hist = self._hist
        if hist is None:
            return 0
        plot = self._plot_rect()
        frac = min(max((x - plot.left()) / max(plot.width(), 1), 0.0), 1.0)
        return int(hist.start_ms + frac * (hist.end_ms - hist.start_ms))

    def time_to_x(self, time_ms: int) -> float:
        hist = self._hist
        plot = self._plot_rect()
        if hist is None or hist.end_ms <= hist.start_ms:
            return plot.left()
        frac = (time_ms - hist.start_ms) / (hist.end_ms - hist.start_ms)
        return plot.left() + frac * plot.width()

    def bucket_at(self, x: float) -> int | None:
        if not self._hist or not self._hist.counts:
            return None
        plot = self._plot_rect()
        n = len(self._hist.counts)
        idx = math.floor((x - plot.left()) / max(plot.width(), 1) * n)
        return idx if 0 <= idx < n else None

    # --- painting -------------------------------------------------------------
    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(250, 250, 252))
        plot = self._plot_rect()
        painter.setPen(QColor(200, 200, 210))
        painter.drawRect(plot)
        hist = self._hist
        if hist and hist.counts:
            self._paint_bars(painter, plot, hist)
            self._paint_axis(painter, hist)
        else:
            painter.setPen(QColor(120, 120, 120))
            painter.drawText(plot, Qt.AlignCenter, "No data in this time range")
        self._paint_marker_and_selection(painter, plot)
        painter.end()

    def _paint_bars(self, painter: QPainter, plot: QRect, hist: Histogram) -> None:
        n = len(hist.counts)
        width = plot.width() / n
        max_total = max(sum(b) for b in hist.counts)
        available = plot.height() - ERROR_STRIP_PX - self._highlight_height(hist) - 3
        bottom = plot.bottom()
        painter.setPen(Qt.NoPen)
        for i, bucket in enumerate(hist.counts):
            total = sum(bucket)
            if not total:
                continue
            x = plot.left() + i * width
            total_h = bar_height(total, max_total, available)
            y = float(bottom)
            for cls in STACK_ORDER:
                if bucket[cls]:
                    h = max(1.0, total_h * bucket[cls] / total)
                    y -= h
                    painter.fillRect(QRectF(x, y, max(width - 0.5, 1.0), h), CLASS_COLORS[cls])
            if bucket[SeverityClass.ERROR]:
                painter.fillRect(QRectF(x, plot.top() + 1, max(width, 2.0), ERROR_STRIP_PX),
                                 CLASS_COLORS[SeverityClass.ERROR])
            if hist.highlights and hist.highlights[i]:
                top = plot.top() + ERROR_STRIP_PX + 2
                if hist.highlight_rules and hist.highlight_counts:
                    lane_height = self._highlight_height(hist) / len(hist.highlight_rules)
                    for j, rule in enumerate(hist.highlight_rules):
                        if hist.highlight_counts[i][j]:
                            painter.fillRect(QRectF(x, top + j * lane_height, max(width, 3.0),
                                                    lane_height), QColor(rule.color))
                else:
                    painter.fillRect(QRectF(x, top, max(width, 3.0), HIGHLIGHT_STRIP_PX),
                                     HIGHLIGHT_COLOR)

    def _paint_axis(self, painter: QPainter, hist: Histogram) -> None:
        painter.setPen(QColor(90, 90, 90))
        font = painter.font()
        font.setPointSizeF(max(font.pointSizeF() - 1, 7))
        painter.setFont(font)
        axis = QRect(2, self.height() - AXIS_PX, self.width() - 4, AXIS_PX)
        same_day = format_ts(hist.start_ms)[:10] == format_ts(hist.end_ms)[:10]
        painter.drawText(axis, Qt.AlignLeft | Qt.AlignVCenter, format_ts(hist.start_ms)[:19])
        painter.drawText(axis, Qt.AlignRight | Qt.AlignVCenter,
                         format_ts(hist.end_ms, with_date=not same_day)[: 8 if same_day else 19])

    def _paint_marker_and_selection(self, painter: QPainter, plot: QRect) -> None:
        if self._hist and self._marker_ms is not None:
            x = self.time_to_x(self._marker_ms)
            if plot.left() <= x <= plot.right():
                painter.setPen(QPen(QColor(20, 20, 20), 2))
                painter.drawLine(int(x), plot.top(), int(x), plot.bottom())
        if self._press_x is not None and self._drag_x is not None:
            left, right = sorted((self._press_x, self._drag_x))
            painter.fillRect(QRect(left, plot.top(), right - left, plot.height()), QColor(0, 120, 215, 60))

    # --- interaction ----------------------------------------------------------
    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton and self._hist:
            self._press_x = int(event.position().x())
            self._drag_x = None

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        x = int(event.position().x())
        if self._press_x is not None:
            if abs(x - self._press_x) >= DRAG_THRESHOLD_PX:
                self._drag_x = x
                self.update()
            return
        self._show_tooltip(x, event.globalPosition().toPoint())

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.LeftButton or self._press_x is None:
            return
        press, drag = self._press_x, self._drag_x
        self._press_x = self._drag_x = None
        self.update()
        if drag is None:
            self.time_clicked.emit(self.x_to_time(press))
        else:
            left, right = sorted((press, drag))
            self.range_selected.emit(self.x_to_time(left), self.x_to_time(right))

    def _show_tooltip(self, x: int, global_pos: QPoint) -> None:
        idx = self.bucket_at(x)
        if idx is None or self._hist is None:
            QToolTip.hideText()
            return
        hist = self._hist
        span = (hist.end_ms - hist.start_ms) / len(hist.counts)
        start = int(hist.start_ms + idx * span)
        bucket = hist.counts[idx]
        lines = [f"{format_ts(start)} – {format_ts(int(start + span), with_date=False)}"]
        lines += [f"{SEVERITY_CLASS_LABELS[c]}: {format_count(bucket[c])}" for c in SeverityClass if bucket[c]]
        if hist.highlights:
            lines.append(f"Highlight: {format_count(hist.highlights[idx])}")
        if hist.highlight_counts:
            lines += [f"{rule.text}: {format_count(hist.highlight_counts[idx][i])}"
                      for i, rule in enumerate(hist.highlight_rules) if hist.highlight_counts[idx][i]]
        lines.append("Click: jump · Drag: select time range")
        QToolTip.showText(global_pos, "\n".join(lines), self)
