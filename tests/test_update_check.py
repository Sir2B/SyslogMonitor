import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from PySide6.QtCore import QByteArray, QObject, Signal
from PySide6.QtNetwork import QNetworkReply, QNetworkRequest
from PySide6.QtWidgets import QApplication

from syslog_monitor.config import Settings, load_settings, save_settings
from syslog_monitor.ui import update_check
from syslog_monitor.ui.settings_dialog import SettingsDialog
from syslog_monitor.ui.update_check import UpdateChecker, newer_release


def release(tag):
    return json.dumps({"tag_name": tag, "draft": False, "prerelease": False}).encode()


@pytest.mark.parametrize(("tag", "expected"), [
    ("v1.4.0", None), ("v1.3.9", None), ("v1.4.1", "v1.4.1"),
    ("v1.10.0", "v1.10.0"), ("v2.0.0", "v2.0.0"),
])
def test_newer_release_uses_numeric_versions(tag, expected):
    assert newer_release(release(tag), "1.4.0") == expected


@pytest.mark.parametrize("payload", [
    b"not json", b"[]", b"{}", release("v1.5.0-rc1"), release("<a>"),
    b'{"tag_name":"v2.0.0","draft":true,"prerelease":false}',
    b'{"tag_name":"v2.0.0","draft":false,"prerelease":true}',
])
def test_invalid_release_is_not_an_update(payload):
    with pytest.raises(ValueError):
        newer_release(payload)


@pytest.mark.parametrize(("body", "status", "expected"), [
    (release("v99.0.0"), 200, ["v99.0.0"]),
    (release("v1.0.0"), 200, []),
    (b"invalid", 200, []),
    (b"rate limit", 403, []),
    (release("v99.0.0"), 302, []),
    (b"x" * (update_check.MAX_RESPONSE_BYTES + 1), 200, []),
])
def test_background_check_is_once_per_session_and_no_popups(qtbot, monkeypatch, caplog,
                                                          body, status, expected):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(status)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(update_check, "RELEASES_URL", f"http://127.0.0.1:{server.server_port}/latest")
    checker = UpdateChecker()
    updates = []
    checker.available.connect(updates.append)
    try:
        checker.set_enabled(True)
        checker._timer.stop()
        checker._request()
        qtbot.waitUntil(lambda: checker._reply is None, timeout=5000)
        assert updates == expected
        assert len(requests) == 1
        assert QApplication.activeModalWidget() is None
        checker.set_enabled(True)
        assert not checker._timer.isActive()
        if expected:
            assert updates == expected * 2
        if status != 200 or body == b"invalid":
            assert caplog.records
    finally:
        checker.shutdown()
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_disabled_check_and_shutdown_cancel_startup(qtbot):
    checker = UpdateChecker()
    checker.set_enabled(False)
    checker._request()
    assert not checker._checked and checker._reply is None
    checker.set_enabled(True)
    assert checker._timer.isActive()
    checker.shutdown()
    assert not checker._timer.isActive()


class PendingReply(QObject):
    readyRead = Signal()
    finished = Signal()

    def __init__(self):
        super().__init__()
        self.code = QNetworkReply.NoError

    def setReadBufferSize(self, size):
        self.buffer_size = size

    def abort(self):
        self.code = QNetworkReply.OperationCanceledError
        self.finished.emit()

    def error(self):
        return self.code

    def errorString(self):
        return "simulated network failure"

    def attribute(self, attribute):
        return 200

    def readAll(self):
        return QByteArray(release("v99.0.0"))


def test_pending_request_is_cancelled_and_late_success_ignored(qtbot, monkeypatch):
    checker = UpdateChecker()
    reply = PendingReply()
    monkeypatch.setattr(checker._manager, "get", lambda request: reply)
    updates = []
    checker.available.connect(updates.append)
    checker.set_enabled(True)
    checker._timer.stop()
    checker._request()
    assert checker._deadline.isActive()
    checker.shutdown()
    assert not checker._deadline.isActive()
    assert reply.code == QNetworkReply.OperationCanceledError
    assert checker._reply is None
    reply.code = QNetworkReply.NoError
    reply.finished.emit()
    assert updates == []


def test_timeout_is_bounded_and_logged(qtbot, monkeypatch, caplog):
    checker = UpdateChecker()
    reply = PendingReply()
    requests = []

    def get(request):
        requests.append(request)
        return reply

    monkeypatch.setattr(checker._manager, "get", get)
    checker.set_enabled(True)
    checker._timer.stop()
    checker._request()
    assert requests[0].transferTimeout() == 10_000
    assert requests[0].attribute(QNetworkRequest.RedirectPolicyAttribute) == QNetworkRequest.ManualRedirectPolicy
    assert reply.buffer_size == update_check.MAX_RESPONSE_BYTES + 1
    assert checker._deadline.interval() == 10_000
    reply.code = QNetworkReply.TimeoutError
    reply.finished.emit()
    assert checker._reply is None
    assert "Update check failed" in caplog.text
    checker.shutdown()


def test_deadline_aborts_even_if_transfer_keeps_making_progress(qtbot, monkeypatch, caplog):
    checker = UpdateChecker()
    reply = PendingReply()
    monkeypatch.setattr(checker._manager, "get", lambda request: reply)
    checker.set_enabled(True)
    checker._timer.stop()
    checker._request()
    checker._deadline.start(1)
    qtbot.waitUntil(lambda: checker._reply is None)
    assert reply.code == QNetworkReply.OperationCanceledError
    assert checker._reply is None
    assert not checker._deadline.isActive()
    assert "10-second deadline" in caplog.text
    checker.shutdown()


def test_update_preference_round_trip_and_validation(qtbot, tmp_path):
    path = tmp_path / "settings.json"
    dialog = SettingsDialog(Settings())
    qtbot.addWidget(dialog)
    assert dialog.update_check.isChecked()
    dialog.update_check.setChecked(False)
    save_settings(path, dialog.result_settings())
    assert not load_settings(path).update_check_enabled
    assert "Update check setting must be true or false." in Settings(update_check_enabled="yes").validate()


def test_update_notice_opens_official_page_without_popup(window, monkeypatch):
    from syslog_monitor.ui.main_window import QDesktopServices

    urls = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: urls.append(url.toString()) or True)
    assert window.update_label.isHidden()
    window.update_checker.available.emit("v99.0.0")
    assert "Update available: v99.0.0" in window.update_label.text()
    assert not window.update_label.isHidden()
    window.update_label.linkActivated.emit("update")
    assert urls == [update_check.DOWNLOAD_URL]
    assert QApplication.activeModalWidget() is None


def test_disabling_updates_hides_notice_and_ignores_late_results(window, monkeypatch):
    from dataclasses import replace

    monkeypatch.setattr(window.service, "apply_settings",
                        lambda settings: setattr(window.service, "settings", settings) or True)
    window.update_checker.available.emit("v99.0.0")
    settings = replace(window.service.settings, update_check_enabled=False)
    window.apply_settings(settings)
    assert window.update_label.isHidden()
    window.update_checker.available.emit("v99.0.0")
    assert window.update_label.isHidden()
