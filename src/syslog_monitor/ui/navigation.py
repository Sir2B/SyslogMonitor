"""Compact, keyboard-accessible navigation rail."""

from PySide6.QtCore import QEvent, QSize, Qt, Signal
from PySide6.QtGui import QAction, QActionGroup
from PySide6.QtWidgets import QScrollArea, QSizePolicy, QStyle, QToolButton, QVBoxLayout, QWidget

from syslog_monitor.i18n import tr
from syslog_monitor.ui.icons import navigation_icon


class NavigationButton(QToolButton):
    def __init__(self):
        super().__init__()
        self.expanded = False
        self._base_height = self.fontMetrics().height()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def sizeHint(self) -> QSize:
        scale = self.fontMetrics().height() / self._base_height
        height = round(44 * scale)
        if not self.expanded:
            return QSize(height, height)
        # Icon, gap and text fit exactly; the rail aligns all buttons to the widest one.
        text = self.text() or (self.defaultAction().text() if self.defaultAction() else "")
        width = self.iconSize().width() + self.fontMetrics().horizontalAdvance(text) + round(30 * scale)
        return QSize(width, height)

    def minimumSizeHint(self) -> QSize:
        return self.sizeHint()

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.FontChange:
            self.update_icon_size()

    def update_icon_size(self) -> None:
        size = round((26 if self.expanded else 20) * self.fontMetrics().height() / self._base_height)
        self.setIconSize(QSize(size, size))


class NavigationRail(QScrollArea):
    expanded_changed = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.expanded = False
        self.buttons: dict[str, NavigationButton] = {}
        self._group = QActionGroup(self)
        self._group.setExclusive(True)
        body = QWidget()
        self.setWidget(body)
        self._layout = QVBoxLayout(body)
        self._layout.setContentsMargins(6, 8, 6, 8)
        self._layout.setSpacing(6)
        self.toggle = NavigationButton()
        self.toggle.clicked.connect(lambda: self.set_expanded(not self.expanded))
        self._layout.addWidget(self.toggle)
        self.set_expanded(False)
        self.setStyleSheet(
            "NavigationRail, NavigationRail > QWidget > QWidget { background: palette(alternate-base); }"
            "QToolButton { padding: 8px; border: 1px solid transparent; border-radius: 6px; }"
            "QToolButton:hover { background: palette(midlight); }"
            "QToolButton:checked { background: palette(highlight); color: palette(highlighted-text); }")

    def add_item(self, name: str, action: QAction,
                 *, page: bool = True) -> QToolButton:
        button = NavigationButton()
        button.setDefaultAction(action)
        button.setAccessibleName(action.text())
        if page:
            action.setCheckable(True)
            self._group.addAction(action)
        self.buttons[name] = button
        self._layout.addWidget(button)
        self._style_button(button)
        if name == "receive":
            action.toggled.connect(self._refresh_icons)
        self._refresh_icons()
        return button

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.PaletteChange and hasattr(self, "buttons"):
            self._refresh_icons()

    def _refresh_icons(self) -> None:
        self.toggle.setIcon(navigation_icon("collapse" if self.expanded else "expand", self.palette()))
        for name, button in self.buttons.items():
            icon = ("stop" if button.isChecked() else "start") if name == "receive" else name
            button.defaultAction().setIcon(navigation_icon(icon, self.palette()))

    def add_stretch(self) -> None:
        self._layout.addStretch(1)

    def sizeHint(self) -> QSize:
        size = self.widget().sizeHint()
        width = size.width()
        if size.height() > self.viewport().height() > 0:
            width += self.style().pixelMetric(QStyle.PM_ScrollBarExtent)
        return QSize(width, size.height())

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if event.oldSize().height() != event.size().height():
            self.updateGeometry()  # the scrollbar may have appeared or disappeared

    def minimumSizeHint(self) -> QSize:
        return QSize(self.sizeHint().width(), 0)

    def _style_button(self, button: NavigationButton) -> None:
        button.expanded = self.expanded
        button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon if self.expanded else Qt.ToolButtonIconOnly)
        button.update_icon_size()
        button.updateGeometry()

    def set_expanded(self, expanded: bool) -> None:
        self.expanded = expanded
        title = tr("Collapse sidebar") if expanded else tr("Expand sidebar")
        self.toggle.setText(title)
        self.toggle.setToolTip(title)
        self.toggle.setAccessibleName(title)
        self._style_button(self.toggle)
        for button in self.buttons.values():
            self._style_button(button)
        self._refresh_icons()
        self._layout.invalidate()
        self.updateGeometry()
        self.expanded_changed.emit(expanded)
