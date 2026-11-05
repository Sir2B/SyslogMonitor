"""Application-wide UI zoom for fonts, widget constraints, layouts and headers."""

from __future__ import annotations

import math
import weakref

from PySide6.QtCore import QMargins, QObject, QEvent, QSize, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QHeaderView, QLayout, QSplitter, QWidget
from shiboken6 import isValid

MIN_ZOOM = 0.75
MAX_ZOOM = 2.0
ZOOM_STEP = 0.1


def _scaled_font(font: QFont, factor: float) -> QFont:
    result = QFont(font)
    if font.pointSizeF() > 0:
        result.setPointSizeF(max(1.0, font.pointSizeF() * factor))
    elif font.pixelSize() > 0:
        result.setPixelSize(max(1, round(font.pixelSize() * factor)))
    return result


def _scaled_dimension(value: int, factor: float) -> int:
    if value >= 1_000_000:
        return value
    return max(0, round(value * factor))


class ZoomController(QObject):
    zoom_changed = Signal(float)

    def __init__(self, app: QApplication, parent: QObject | None = None) -> None:
        super().__init__(parent or app)
        self._app = app
        self._zoom = 1.0
        self._widget_baselines: weakref.WeakKeyDictionary[QWidget, tuple[QFont, QSize, QSize]] = (
            weakref.WeakKeyDictionary())
        self._layout_baselines: weakref.WeakKeyDictionary[QLayout, tuple[QMargins, int]] = (
            weakref.WeakKeyDictionary())
        self._header_baselines: weakref.WeakKeyDictionary[QHeaderView, tuple[int, tuple[int, ...]]] = (
            weakref.WeakKeyDictionary())
        self._splitter_baselines: weakref.WeakKeyDictionary[QSplitter, int] = weakref.WeakKeyDictionary()
        self._app_font = QFont(app.font())
        self._applying = False
        app.installEventFilter(self)

    @property
    def factor(self) -> float:
        return self._zoom

    def set_zoom(self, factor: float) -> None:
        if not math.isfinite(factor):
            raise ValueError("Zoom factor must be finite")
        factor = round(min(MAX_ZOOM, max(MIN_ZOOM, factor)) * 10) / 10
        if factor == self._zoom:
            return
        self._capture_new_widgets()
        self._zoom = factor
        self._apply(capture_new=False, force=True)
        self.zoom_changed.emit(factor)

    def adjust(self, steps: int) -> None:
        self.set_zoom(self._zoom + steps * ZOOM_STEP)

    def eventFilter(self, watched, event) -> bool:
        if self._applying:
            return False
        if event.type() == QEvent.Type.Wheel and event.modifiers() & Qt.ControlModifier:
            delta = event.angleDelta().y()
            if delta:
                self.adjust(1 if delta > 0 else -1)
                event.accept()
                return True
        elif event.type() == QEvent.Type.Show:
            self._apply()
        return False

    def _apply(self, *, capture_new: bool = True, force: bool = False) -> None:
        if self._applying:
            return
        self._applying = True
        try:
            if capture_new:
                self._capture_new_widgets()
            if self._zoom == 1.0 and not force:
                return
            for widget, (font, minimum, maximum) in tuple(self._widget_baselines.items()):
                if not isValid(widget):
                    del self._widget_baselines[widget]
                    continue
                widget.setFont(_scaled_font(font, self._zoom))
                widget.setMinimumSize(self._scaled_size(minimum))
                widget.setMaximumSize(self._scaled_size(maximum))
            self._app.setFont(_scaled_font(self._app_font, self._zoom))
            for layout, (margins, spacing) in tuple(self._layout_baselines.items()):
                if not isValid(layout):
                    del self._layout_baselines[layout]
                    continue
                layout.setContentsMargins(*(_scaled_dimension(value, self._zoom)
                                             for value in (margins.left(), margins.top(),
                                                           margins.right(), margins.bottom())))
                if spacing >= 0:
                    layout.setSpacing(_scaled_dimension(spacing, self._zoom))
            for header, (default_size, sections) in tuple(self._header_baselines.items()):
                if not isValid(header):
                    del self._header_baselines[header]
                    continue
                header.setDefaultSectionSize(_scaled_dimension(default_size, self._zoom))
                for index, size in enumerate(sections):
                    if size > 0 and index < header.count():
                        header.resizeSection(index, _scaled_dimension(size, self._zoom))
            for splitter, handle_width in tuple(self._splitter_baselines.items()):
                if not isValid(splitter):
                    del self._splitter_baselines[splitter]
                    continue
                splitter.setHandleWidth(_scaled_dimension(handle_width, self._zoom))
        finally:
            self._applying = False

    def _capture_new_widgets(self) -> None:
        for widget in self._app.allWidgets():
            if not isValid(widget):
                continue
            if widget not in self._widget_baselines:
                self._widget_baselines[widget] = (
                    QFont(widget.font()), widget.minimumSize(), widget.maximumSize())
                if self._zoom != 1.0:
                    font, minimum, maximum = self._widget_baselines[widget]
                    self._widget_baselines[widget] = (
                        self._unscaled_font(font), self._unscaled_size(minimum),
                        self._unscaled_size(maximum))
            layout = widget.layout()
            if layout is not None and isValid(layout) and layout not in self._layout_baselines:
                margins = layout.contentsMargins()
                spacing = layout.spacing()
                if self._zoom != 1.0:
                    margins.setLeft(round(margins.left() / self._zoom))
                    margins.setTop(round(margins.top() / self._zoom))
                    margins.setRight(round(margins.right() / self._zoom))
                    margins.setBottom(round(margins.bottom() / self._zoom))
                    if spacing >= 0:
                        spacing = round(spacing / self._zoom)
                self._layout_baselines[layout] = (margins, spacing)
            if isinstance(widget, QHeaderView) and widget not in self._header_baselines:
                sizes = tuple(widget.sectionSize(index) for index in range(widget.count()))
                default_size = widget.defaultSectionSize()
                if self._zoom != 1.0:
                    sizes = tuple(round(size / self._zoom) for size in sizes)
                    default_size = round(default_size / self._zoom)
                self._header_baselines[widget] = (default_size, sizes)
            if isinstance(widget, QSplitter) and widget not in self._splitter_baselines:
                width = widget.handleWidth()
                self._splitter_baselines[widget] = (
                    round(width / self._zoom) if self._zoom != 1.0 else width)

    def _scaled_size(self, size: QSize) -> QSize:
        return QSize(_scaled_dimension(size.width(), self._zoom),
                     _scaled_dimension(size.height(), self._zoom))

    def _unscaled_size(self, size: QSize) -> QSize:
        return QSize(_scaled_dimension(size.width(), 1 / self._zoom),
                     _scaled_dimension(size.height(), 1 / self._zoom))

    def _unscaled_font(self, font: QFont) -> QFont:
        return _scaled_font(font, 1 / self._zoom)
