"""Run the firewall check off the GUI thread and report the result as a Qt signal."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from PySide6.QtCore import QObject, Signal

from syslog_monitor.config import ListenerEndpoint
from syslog_monitor.firewall import FirewallCheck, Level

log = logging.getLogger(__name__)

Checker = Callable[[str, tuple[ListenerEndpoint, ...]], FirewallCheck]


class FirewallMonitor(QObject):
    checked = Signal(object)  # FirewallCheck

    def __init__(self, checker: Checker, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._checker = checker
        self._lock = threading.Lock()
        self._running = False
        self._pending: tuple[str, tuple[ListenerEndpoint, ...]] | None = None

    def request(self, bind_host: str, endpoints: tuple[ListenerEndpoint, ...]) -> None:
        """Start a check; while one is running only the latest request is queued."""
        with self._lock:
            if self._running:
                self._pending = (bind_host, endpoints)
                return
            self._running = True
        threading.Thread(target=self._run, args=(bind_host, endpoints), name="firewall-check",
                         daemon=True).start()

    def _run(self, bind_host: str, endpoints: tuple[ListenerEndpoint, ...]) -> None:
        while True:
            try:
                result = self._checker(bind_host, endpoints)
            except Exception as exc:  # noqa: BLE001 - a broken check must never kill the app
                log.exception("Firewall check failed")
                result = FirewallCheck(Level.UNKNOWN, "Could not check the firewall", (str(exc),))
            try:
                self.checked.emit(result)
            except RuntimeError:  # window already destroyed during shutdown
                return
            with self._lock:
                if self._pending is None:
                    self._running = False
                    return
                bind_host, endpoints = self._pending
                self._pending = None
