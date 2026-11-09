"""Non-blocking, optional GitHub release check; never downloads or installs updates."""

from __future__ import annotations

import json
import logging
import re

from PySide6.QtCore import QObject, QTimer, QUrl, Signal
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest

from syslog_monitor import __version__

log = logging.getLogger(__name__)
RELEASES_URL = "https://api.github.com/repos/Sir2B/SyslogMonitor/releases/latest"
DOWNLOAD_URL = "https://github.com/Sir2B/SyslogMonitor/releases/latest"
MAX_RESPONSE_BYTES = 256 * 1024


def newer_release(payload: bytes, current: str = __version__) -> str | None:
    """Only stable semantic-version tags from the official latest-release endpoint."""
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("Invalid release response")
    if data.get("draft") is not False or data.get("prerelease") is not False:
        raise ValueError("Latest release is not a published stable release")
    tag = data.get("tag_name")
    if not isinstance(tag, str) or re.fullmatch(r"v\d+\.\d+\.\d+", tag) is None:
        raise ValueError("Invalid release version")
    if re.fullmatch(r"\d+\.\d+\.\d+", current) is None:
        raise ValueError("Invalid application version")
    version = tuple(map(int, tag[1:].split(".")))
    return tag if version > tuple(map(int, current.split("."))) else None


class UpdateChecker(QObject):
    available = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._manager = QNetworkAccessManager(self)
        self._reply: QNetworkReply | None = None
        self._timer = QTimer(self, singleShot=True, interval=1500)
        self._timer.timeout.connect(self._request)
        self._deadline = QTimer(self, singleShot=True, interval=10_000)
        self._deadline.timeout.connect(self._expire)
        self._enabled = False
        self._checked = False
        self._latest_tag: str | None = None

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        if not enabled:
            self._timer.stop()
            if self._reply is not None:
                self._reply.abort()
        elif self._latest_tag is not None:
            self.available.emit(self._latest_tag)
        elif not self._checked:
            self._timer.start()

    def _request(self) -> None:
        if not self._enabled or self._checked:
            return
        self._checked = True
        request = QNetworkRequest(QUrl(RELEASES_URL))
        request.setRawHeader(b"Accept", b"application/vnd.github+json")
        request.setRawHeader(b"User-Agent", f"SyslogMonitor/{__version__}".encode("ascii"))
        request.setTransferTimeout(10_000)
        request.setAttribute(QNetworkRequest.RedirectPolicyAttribute, QNetworkRequest.ManualRedirectPolicy)
        reply = self._manager.get(request)
        self._reply = reply
        reply.setReadBufferSize(MAX_RESPONSE_BYTES + 1)
        reply.readyRead.connect(self._check_size)
        reply.finished.connect(self._finished)
        self._deadline.start()

    def _expire(self) -> None:
        if self._reply is not None:
            log.warning("Update check exceeded its 10-second deadline")
            self._reply.abort()

    def _check_size(self) -> None:
        if self._reply is not None and self._reply.bytesAvailable() > MAX_RESPONSE_BYTES:
            log.warning("Update check response exceeds size limit")
            self._reply.abort()

    def _finished(self) -> None:
        reply = self._reply
        if reply is None:
            return
        self._deadline.stop()
        self._reply = None
        try:
            if not self._enabled:
                return
            if reply.error() != QNetworkReply.NoError:
                log.warning("Update check failed: %s", reply.errorString())
                return
            if reply.attribute(QNetworkRequest.HttpStatusCodeAttribute) != 200:
                log.warning("Update check returned an unexpected HTTP status")
                return
            payload = bytes(reply.readAll())
            if len(payload) > MAX_RESPONSE_BYTES:
                log.warning("Update check response exceeds size limit")
                return
            try:
                tag = newer_release(payload)
            except (ValueError, UnicodeError) as exc:
                log.warning("Invalid update check response: %s", exc)
                return
            if tag is not None:
                self._latest_tag = tag
                self.available.emit(tag)
        finally:
            reply.deleteLater()

    def shutdown(self) -> None:
        self.set_enabled(False)
