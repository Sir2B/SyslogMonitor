"""System tray integration: keep receiving while the window is hidden."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QMenu, QSystemTrayIcon, QWidget

from syslog_monitor import APP_DISPLAY_NAME
from syslog_monitor.i18n import tr
from syslog_monitor.stats import StatsSnapshot
from syslog_monitor.ui.formatting import format_count
from syslog_monitor.ui.icons import app_icon


class TrayController(QObject):
    open_requested = Signal()
    quit_requested = Signal()

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self._state = ""
        self._notified = False
        self.icon = QSystemTrayIcon(app_icon("stopped"), parent)
        menu = QMenu(parent)
        menu.addAction(tr("Open"), self.open_requested.emit)
        menu.addSeparator()
        menu.addAction(tr("Quit"), self.quit_requested.emit)
        self.icon.setContextMenu(menu)
        self.icon.activated.connect(self._on_activated)
        self.icon.messageClicked.connect(self.open_requested.emit)
        self.icon.show()

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.open_requested.emit()

    def update_status(self, snap: StatsSnapshot) -> None:
        if snap.listener_state != self._state:
            self._state = snap.listener_state
            self.icon.setIcon(app_icon(snap.listener_state))
        state = tr({"running": "receiving", "stopped": "stopped", "error": "ERROR"}[snap.listener_state])
        self.icon.setToolTip(
            f"{APP_DISPLAY_NAME} – {state} {snap.listener_display_address}\n"
            f"{tr('Stored: {count}', count=format_count(snap.persisted))}")

    def notify_hidden_once(self) -> None:
        if not self._notified:
            self._notified = True
            self.icon.showMessage(tr("{name} is still running", name=APP_DISPLAY_NAME),
                                  tr("Receiving and storage continue in the background. "
                                     "Quit from the tray menu."), QSystemTrayIcon.Information, 4000)

    def show_highlight(self, title: str, body: str) -> None:
        self.show_warning(title, body)

    def show_warning(self, title: str, body: str) -> None:
        self.icon.showMessage(title, body, QSystemTrayIcon.Warning, 10000)

    def hide(self) -> None:
        self.icon.hide()
