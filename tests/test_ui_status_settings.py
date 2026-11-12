"""GUI integration tests: status settings."""

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication
from syslog_monitor.config import Settings
from syslog_monitor.service import CaptureService
from syslog_monitor.ui.main_window import MainWindow
from syslog_monitor.writer import WriterTuning
from ui_test_helpers import FAST, isolated_firewall_checker


def test_listener_toggle(qtbot, window):
    window.listen_action.trigger()
    assert not window.service.listening
    qtbot.waitUntil(lambda: "stopped" in window.listener_label.text(), timeout=2000)
    window.listen_action.trigger()
    assert window.service.listening


def test_firewall_status_is_shown_and_rechecked(qtbot, tmp_path):
    from syslog_monitor.firewall import FirewallCheck, Level

    calls = []
    results = [FirewallCheck(Level.WARNING, "UDP 514 is not allowed",
                             ("Private: no allow rule for UDP 514",)),
               FirewallCheck(Level.OK, "UDP 514 is allowed")]

    def checker(host, endpoints):
        calls.append((host, endpoints))
        return results[min(len(calls), len(results)) - 1]

    service = CaptureService(tmp_path / "data", Settings(bind_host="0.0.0.0", port=0))
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST, firewall_checker=checker)
    qtbot.addWidget(win)
    try:
        qtbot.waitUntil(lambda: "not allowed" in win.firewall_label.text(), timeout=3000)
        assert calls == [("0.0.0.0", (("UDP", 0),))]
        assert "Private: no allow rule" in win.firewall_label.toolTip()
        win.check_firewall()
        qtbot.waitUntil(lambda: "Firewall ✓" in win.firewall_label.text(), timeout=3000)
    finally:
        win.shutdown()
        service.shutdown()


def test_firewall_monitor_survives_broken_checker(qtbot):
    from syslog_monitor.firewall import Level
    from syslog_monitor.ui.firewall_status import FirewallMonitor

    def broken(host, endpoints):
        raise RuntimeError("boom")

    monitor = FirewallMonitor(broken)
    with qtbot.waitSignal(monitor.checked, timeout=3000) as blocker:
        monitor.request("0.0.0.0", (("UDP", 514),))
    assert blocker.args[0].level == Level.UNKNOWN
    assert "boom" in blocker.args[0].details[0]


def test_firewall_monitor_coalesces_requests(qtbot):
    import threading

    from syslog_monitor.firewall import FirewallCheck, Level
    from syslog_monitor.ui.firewall_status import FirewallMonitor

    gate = threading.Event()
    seen = []

    def slow(host, endpoints):
        gate.wait(3)
        port = endpoints[0][1]
        seen.append(port)
        return FirewallCheck(Level.OK, str(port))

    monitor = FirewallMonitor(slow)
    received = []
    monitor.checked.connect(lambda c: received.append(c.summary))
    for port in (1, 2, 3):
        monitor.request("0.0.0.0", (("UDP", port),))
    gate.set()
    qtbot.waitUntil(lambda: len(received) == 2, timeout=3000)
    qtbot.wait(100)
    assert seen == [1, 3] and received == ["1", "3"]


def test_mcp_status_details_and_settings(qtbot, tmp_path, monkeypatch):
    import json as json_module
    from dataclasses import replace

    from PySide6.QtCore import QTimer

    from syslog_monitor import mcp_server
    from syslog_monitor.mcp_tools import LogTools
    from syslog_monitor.ui import main_window as main_window_module
    from syslog_monitor.ui.settings_dialog import SettingsDialog

    settings = Settings(bind_host="127.0.0.1", port=0, mcp_port=0)
    service = CaptureService(tmp_path / "data", settings)
    mcp = mcp_server.McpService(LogTools(service.db_path))
    mcp.apply_async(settings).join(30)
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST, mcp=mcp,
                     firewall_checker=isolated_firewall_checker)
    qtbot.addWidget(win)
    try:
        assert f"MCP ✓ :{mcp.port}" in win.mcp_label.text()
        assert mcp.url in win.mcp_label.toolTip()
        assert "no authentication" in win.mcp_label.toolTip()

        details = []
        def click(text):
            box = QApplication.activeModalWidget()
            details.append(box.informativeText())
            next(b for b in box.buttons() if b.text() == text).click()

        QTimer.singleShot(0, lambda: click("Copy configuration"))
        win.show_mcp_details()
        copied = json_module.loads(QApplication.clipboard().text())
        assert copied["servers"]["syslog-monitor"]["url"] == mcp.url
        assert "unauthenticated" in details[0]
        assert "other local programs" in details[0]
        assert "external provider" in details[0]

        dialog = SettingsDialog(settings)
        assert dialog.mcp_enabled.isChecked() and dialog.boot_marker.text() == "Initializing system"
        assert "Other programs" in dialog.mcp_enabled.toolTip()
        dialog.mcp_enabled.setChecked(False)
        assert not dialog.mcp_port.isEnabled()
        dialog.boot_marker.setText(" booted; started ")
        new = dialog.result_settings()
        assert (new.mcp_enabled, new.boot_marker) == (False, "booted; started")

        class FakeDialog:
            def __init__(self, *_):
                pass

            def exec(self):
                return True

            def result_settings(self):
                return new

        monkeypatch.setattr(main_window_module, "SettingsDialog", FakeDialog)
        win.apply_settings(new)
        assert not mcp.running and mcp.tools.boot_marker == "booted; started"
        assert "MCP off" in win.mcp_label.text()

        new = replace(new, mcp_enabled=True)
        win.apply_settings(new)
        assert mcp.running and "MCP ✓" in win.mcp_label.text()
    finally:
        win.shutdown()
        mcp.stop()
        service.shutdown()


def test_without_mcp_the_status_label_is_hidden(window):
    assert window.mcp is None and window.mcp_label.isHidden()


def test_listener_settings_controls_and_validation(qtbot):
    from syslog_monitor.ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(Settings())
    qtbot.addWidget(dialog)
    assert dialog.udp_enabled.isChecked() and dialog.port.isEnabled()
    assert not dialog.tcp_enabled.isChecked() and not dialog.tcp_port.isEnabled()

    dialog.tcp_enabled.setChecked(True)
    dialog.tcp_port.setValue(6514)
    dialog.udp_enabled.setChecked(False)
    assert not dialog.port.isEnabled() and dialog.tcp_port.isEnabled()
    result = dialog.result_settings()
    assert not result.udp_enabled and result.tcp_enabled and result.tcp_port == 6514
    assert result.validate() == []

    dialog.tcp_enabled.setChecked(False)
    dialog.accept()
    assert "Enable at least one UDP, TCP or TLS listener" in dialog.error_label.text()
    assert not dialog.result()


def test_tls_settings_controls_check_certificate_files(qtbot, tls_certs):
    from syslog_monitor.ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(Settings())
    qtbot.addWidget(dialog)
    assert not dialog.tls_enabled.isChecked()
    assert not dialog.tls_port.isEnabled() and not dialog.tls_cert.isEnabled()
    dialog.tls_enabled.setChecked(True)
    assert dialog.tls_port.isEnabled() and dialog.tls_cert.isEnabled() and dialog.tls_ca.isEnabled()
    assert dialog.tls_port.value() == 6514

    dialog.accept()
    assert "TLS needs a certificate file" in dialog.error_label.text() and not dialog.result()
    dialog.tls_cert.setText(tls_certs.server_cert)
    dialog.tls_key.setText(tls_certs.rogue_key)
    dialog.accept()
    assert "Could not load TLS certificate" in dialog.error_label.text() and not dialog.result()

    dialog.tls_key.setText(f"  {tls_certs.server_key} ")
    dialog.tls_ca.setText(tls_certs.ca)
    dialog.tls_port.setValue(16514)
    dialog.accept()
    assert dialog.result()
    result = dialog.result_settings()
    assert result.tls_enabled and result.tls_port == 16514
    assert result.tls_files == (tls_certs.server_cert, tls_certs.server_key, tls_certs.ca)
    assert result.listener_endpoints == (("UDP", 514), ("TLS", 16514))


def test_gui_applies_tcp_settings_and_keeps_udp_running_on_error(qtbot, tmp_path, monkeypatch):
    import socket
    from dataclasses import replace

    from syslog_monitor.config import load_settings
    from syslog_monitor.ui import main_window as main_window_module

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        udp_port = probe.getsockname()[1]
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    tcp_port = blocker.getsockname()[1]
    settings = Settings(bind_host="127.0.0.1", port=udp_port)
    new = replace(settings, tcp_enabled=True, tcp_port=tcp_port)
    service = CaptureService(tmp_path / "data", settings, tuning=WriterTuning(flush_interval_s=0.05))
    assert service.start_listener()
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST, firewall_checker=isolated_firewall_checker)
    qtbot.addWidget(win)
    warnings = []
    monkeypatch.setattr(main_window_module.QMessageBox, "warning", lambda *args: warnings.append(args[2]))

    class FakeDialog:
        def __init__(self, *_):
            pass

        def exec(self):
            return True

        def result_settings(self):
            return new

    monkeypatch.setattr(main_window_module, "SettingsDialog", FakeDialog)
    try:
        win.show()
        win.apply_settings(new)
        assert load_settings(tmp_path / "settings.json") == new
        assert warnings and "TCP port" in warnings[0]
        assert service.bound_ports == {"UDP": udp_port}
        assert win.listen_action.isChecked()
        assert "Still receiving on UDP" in win.listener_label.text()

        blocker.close()
        win.listen_action.trigger()
        assert not service.listening
        win.listen_action.trigger()
        assert service.bound_ports == {"UDP": udp_port, "TCP": tcp_port}
        assert "UDP" in win.listener_label.text() and "TCP" in win.listener_label.text()

        with socket.create_connection(("127.0.0.1", tcp_port), timeout=3) as client:
            client.sendall(b"<14>1 - host app - - - tcp in the GUI\n")
            qtbot.waitUntil(lambda: win.model.rowCount() == 1, timeout=5000)
        assert win.model.row_at(0).message == "tcp in the GUI"
    finally:
        blocker.close()
        win.shutdown()
        service.shutdown()

def test_create_certificates_button_fills_tls_fields(qtbot, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QDialog
    from syslog_monitor.receiver import create_tls_context
    from syslog_monitor.ui import certificate_dialog
    from syslog_monitor.ui.settings_dialog import SettingsDialog

    def run(self):
        self.names.setText("syslog.example.test, 192.0.2.10")
        self.folder.setText(str(tmp_path / "certs"))
        self.mtls.setChecked(True)
        self.key_type.setCurrentIndex(self.key_type.findData("ecdsa-p256"))
        assert self.create() and self.stack.currentIndex() == 1
        out = tmp_path / "device"
        out.mkdir()
        monkeypatch.setattr(certificate_dialog.QFileDialog, "getExistingDirectory", lambda *a: str(out))
        monkeypatch.setattr(certificate_dialog.QDesktopServices, "openUrl", lambda url: True)
        assert self.save_device_files() == out
        assert {p.name for p in out.iterdir()} == {
            "syslog-ca.crt", "syslog-device.crt", "syslog-device-key.pem", "syslog-device.p12"}
        assert "syslog-device-key.pem" in self.mapping.text()
        self.accept()
        return QDialog.Accepted

    monkeypatch.setattr(certificate_dialog.CertificateDialog, "exec", run)
    dialog = SettingsDialog(Settings(tls_enabled=True))
    qtbot.addWidget(dialog)
    assert dialog.create_certificates_button.isEnabled()
    dialog.create_certificates()
    folder = tmp_path / "certs"
    assert dialog.tls_cert.text() == str(folder / "server-chain.crt")
    assert dialog.tls_key.text() == str(folder / "server.key")
    assert dialog.tls_ca.text() == str(folder / "ca.crt")
    assert {"ca.der", "client.p12", "rsyslog-tls.conf"} <= {p.name for p in folder.iterdir()}
    create_tls_context(*dialog.result_settings().tls_files)
