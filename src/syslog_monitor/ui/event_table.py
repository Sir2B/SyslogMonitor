"""Message table with a full-width banner row for newer messages while autoscroll is off."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPalette
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QTableView, QWidget

from syslog_monitor.i18n import tr
from syslog_monitor.ui.formatting import format_count

NEWER_COUNT_LIMIT = 10_000


class NewerBanner(QWidget):
    """Pinned first "row" spanning all columns; deliberately not styled like a message."""

    latest_requested = Signal()
    autoscroll_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("newer_banner")
        self.count: int | None = None
        self.new: int | None = None
        self.label = QLabel()
        font = QFont(self.label.font())
        font.setBold(True)
        self.label.setFont(font)
        self.latest_button = QPushButton(tr("▲ Show newest"))
        self.latest_button.setToolTip(tr("Jump to the newest matching messages once (F5). Autoscroll stays off."))
        self.autoscroll_button = QPushButton(tr("Enable autoscroll"))
        self.autoscroll_button.setToolTip(tr("Jump to the newest messages and keep following new ones."))
        self.latest_button.clicked.connect(self.latest_requested)
        self.autoscroll_button.clicked.connect(self.autoscroll_requested)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 3, 8, 3)
        layout.setSpacing(6)
        layout.addStretch(1)
        layout.addWidget(self.label)
        layout.addSpacing(10)
        layout.addWidget(self.latest_button)
        layout.addWidget(self.autoscroll_button)
        layout.addStretch(1)
        self.set_count(None)

    def set_count(self, count: int | None, new: int | None = None) -> None:
        self.count, self.new = count, new
        text = "⏸ " + tr("Autoscroll off")
        if count == 0:
            text += " · " + tr("no newer messages")
        elif count is not None:
            shown = lambda n: format_count(n) + ("+" if n >= NEWER_COUNT_LIMIT else "")  # noqa: E731
            text += " · " + (tr("1 message above") if count == 1
                             else tr("{count} messages above", count=shown(count)))
            if new is not None:
                text += " · " + tr("{count} new since pausing", count=shown(new))
        self.label.setText(text)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        palette = self.palette()
        accent = palette.color(QPalette.Highlight)
        tint = QColor(accent)
        tint.setAlpha(45)
        painter.fillRect(self.rect(), palette.color(QPalette.Base))
        painter.fillRect(self.rect(), tint)
        painter.fillRect(0, self.height() - 2, self.width(), 2, accent)


class EventTable(QTableView):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.banner = NewerBanner(self)
        self.banner.hide()
        self._banner_visible = False

    @property
    def banner_visible(self) -> bool:
        return self._banner_visible

    def set_banner_visible(self, visible: bool) -> None:
        if visible == self._banner_visible:
            return
        self._banner_visible = visible
        self.banner.setVisible(visible)
        self.updateGeometries()

    def updateGeometries(self) -> None:  # noqa: N802 - Qt naming
        super().updateGeometries()
        if not self._banner_visible:
            return
        # QTableView resets the margins and places the header above the viewport; insert the banner between.
        margins = self.viewportMargins()
        header = self.horizontalHeader()
        header_height = header.height() if not header.isHidden() else 0
        height = self.banner.sizeHint().height()
        self.setViewportMargins(margins.left(), header_height + height, margins.right(), margins.bottom())
        contents = self.contentsRect()
        viewport = self.viewport().geometry()
        left, width = viewport.left(), viewport.width()
        if header_height:
            header.setGeometry(left, contents.top(), width, header_height)
        self.banner.setGeometry(left, contents.top() + header_height, width, height)
        self.banner.raise_()
