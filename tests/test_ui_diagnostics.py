import json
import socket
import ssl
import threading
from pathlib import Path

from cryptography import x509
import pytest
from PySide6.QtWidgets import QMessageBox
from PySide6.QtCore import QSettings

from syslog_monitor.i18n import set_language
from syslog_monitor.ui.diagnostics_dialog import DiagnosticsDialog
from syslog_monitor.diagnostics import CheckResult


@pytest.fixture(autouse=True)
def isolated_client_settings(tmp_path, monkeypatch):
    class TestSettings(QSettings):
        def __init__(self, *args):
            super().__init__(str(tmp_path / "client-checks.ini"), QSettings.IniFormat)
    monkeypatch.setattr("syslog_monitor.ui.diagnostics_dialog.QSettings", TestSettings)


def test_client_settings_round_trip_without_secrets_or_control_state(qtbot):
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    dialog.host.setText("127.0.0.1")
    dialog.client.setText("192.0.2.10")
    dialog.port.setValue(20514)
    dialog.case.setCurrentIndex(dialog.case.findData("tls_hostname"))
    dialog.format.setCurrentIndex(dialog.format.findData("rfc3164"))
    dialog.facility.setValue(17)
    dialog.severity.setValue(3)
    dialog.timeout.setValue(90)
    dialog.hostname.setText("device.example")
    dialog.ssh_enabled.setChecked(True)
    dialog.ssh_host.setText("device.example")
    dialog.ssh_user.setText("operator")
    dialog.ssh_port.setValue(2222)
    dialog.ssh_key.setText(r"~\.ssh\custom")
    dialog.ssh_password.setText("DO-NOT-STORE")
    dialog._baseline = dialog._key()
    original_token = dialog.token.text()
    dialog.shutdown()
    persisted = dialog._ui_state.value("diagnostics")
    assert "DO-NOT-STORE" not in persisted
    assert "password" not in persisted
    restored = DiagnosticsDialog()
    qtbot.addWidget(restored)
    try:
        assert restored._key() == dialog._key()
        assert restored.timeout.value() == 90
        assert restored.case.currentData() == "tls_hostname"
        assert restored.ssh_password.text() == ""
        assert restored.token.text() != original_token
        assert restored._baseline is None
        assert restored._certificates == {}
        assert restored.worker is None
    finally:
        restored.shutdown()


def test_invalid_saved_settings_are_reported(qtbot):
    # Use the same isolated factory as the dialog.
    from syslog_monitor.ui.diagnostics_dialog import QSettings as DialogSettings
    state = DialogSettings()
    state.setValue("diagnostics", '{"port": "invalid"}')
    state.sync()
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    assert "Could not restore" in dialog.status.text()
    assert dialog.port.value() == 18514
    dialog.shutdown()


def test_standard_syslog_port_is_forwarded_to_listener_and_remembered(qtbot, monkeypatch):
    observed = []
    def check(options, cancel, **kwargs):
        observed.append(options)
        return CheckResult(options.case, "inconclusive", "Test cancelled.")
    monkeypatch.setattr("syslog_monitor.ui.diagnostics_dialog.run_check", check)
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    try:
        assert dialog.port.minimum() == 1
        assert dialog.port.maximum() == 65535
        dialog.port.setValue(514)
        assert dialog.port.value() == 514
        dialog.client.setText("192.0.2.10")
        dialog.start_check()
        qtbot.waitUntil(lambda: dialog.worker is None)
        assert observed[0].port == 514
    finally:
        dialog.shutdown()
    restored = DiagnosticsDialog()
    qtbot.addWidget(restored)
    try:
        assert restored.port.value() == 514
    finally:
        restored.shutdown()


def test_tls_checks_require_certificates_and_positive_control(qtbot):
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    try:
        dialog.client.setText("127.0.0.1")
        dialog.hostname.setText("localhost")
        dialog.case.setCurrentIndex(dialog.case.findData("tls_hostname"))
        dialog.start_check()
        assert dialog.worker is None
        assert "test CA" in dialog.status.text()
    finally:
        dialog.shutdown()


def test_start_cancel_and_close_isolated_udp_check(qtbot):
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    dialog.client.setText("127.0.0.1")
    # Let the operating system allocate a free port for this test.
    dialog.port.setMinimum(0)
    dialog.port.setValue(0)
    dialog.start_check()
    qtbot.waitUntil(lambda: "Listening" in dialog.status.text())
    dialog.stop_check()
    qtbot.waitUntil(lambda: dialog.worker is None)
    assert "inconclusive" in dialog.status.text()
    assert dialog.report_button.isEnabled()
    dialog.reject()


def test_ca_export_tls_control_gating_and_report(qtbot, tmp_path, monkeypatch):
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    ca_path = tmp_path / "ca.pem"
    report_path = tmp_path / "report.json"
    monkeypatch.setattr("syslog_monitor.ui.diagnostics_dialog.QFileDialog.getSaveFileName",
                        lambda *args: (str(ca_path), ""))
    try:
        dialog.hostname.setText("localhost")
        dialog.client.setText("127.0.0.1")
        dialog.host.setText("127.0.0.1")
        dialog.port.setMinimum(0)
        dialog.port.setValue(0)
        dialog.export_ca()
        assert x509.load_pem_x509_certificate(ca_path.read_bytes())
        assert b"PRIVATE KEY" not in ca_path.read_bytes()
        dialog.case.setCurrentIndex(dialog.case.findData("tls_hostname"))
        dialog.start_check()
        assert dialog.worker is None
        assert "positive control" in dialog.status.text()
        dialog.case.setCurrentIndex(dialog.case.findData("tls_valid"))
        context = ssl.create_default_context(cafile=str(ca_path))

        def send(port):
            message = f"<134>1 2026-11-06T00:00:00Z client app - - - {dialog.token.text()}".encode()
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname="localhost") as tls:
                    tls.sendall(str(len(message)).encode() + b" " + message)
                    tls.recv(1)

        dialog.start_check()
        dialog.worker.ready.connect(send)
        qtbot.waitUntil(lambda: dialog.worker is None)
        assert dialog._baseline == dialog._key()
        monkeypatch.setattr("syslog_monitor.ui.diagnostics_dialog.QFileDialog.getSaveFileName",
                            lambda *args: (str(report_path), ""))
        dialog.export_report()
        report = json.loads(report_path.read_text())
        assert report["official_certification"] is False
        assert report["application_version"]
        assert report["checks"][0]["result"]["status"] == "passed"
        assert report["checks"][0]["checked_at"]
        assert any("Certificate SHA256" in entry
                   for entry in report["checks"][0]["result"]["evidence"])
        dialog.severity.setValue(3)
        dialog.case.setCurrentIndex(dialog.case.findData("tls_hostname"))
        dialog.start_check()
        assert dialog.worker is None
        assert "positive control" in dialog.status.text()
    finally:
        temporary = dialog._temporary.name
        dialog.shutdown()
        assert not Path(temporary).exists()


def test_german_diagnostic_labels(qtbot):
    set_language("de")
    try:
        dialog = DiagnosticsDialog()
        qtbot.addWidget(dialog)
        assert dialog.windowTitle() == "Syslog-Client prüfen"
        assert dialog.start_button.text() == "Prüfung starten"
        assert dialog.case.itemText(dialog.case.findData("tls_valid")) == "TLS-Positivtest"
        assert "keine offizielle Zertifizierung" in dialog.instructions.text()
        dialog.shutdown()
    finally:
        set_language("en")


def test_bind_error_is_displayed_and_recorded(qtbot):
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    try:
        dialog.host.setText("127.0.0.1")
        dialog.client.setText("127.0.0.1")
        dialog.case.setCurrentIndex(dialog.case.findData("tcp"))
        dialog.port.setMinimum(0)
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            dialog.port.setValue(occupied.getsockname()[1])
            dialog.start_check()
            qtbot.waitUntil(lambda: dialog.worker is None)
        assert "Check error" in dialog.status.text()
        assert dialog._report[0]["error"]
    finally:
        dialog.shutdown()


def test_close_immediately_after_worker_start_is_safe(qtbot):
    for _ in range(5):
        dialog = DiagnosticsDialog()
        qtbot.addWidget(dialog)
        dialog.client.setText("127.0.0.1")
        dialog.port.setMinimum(0)
        dialog.port.setValue(0)
        dialog.start_check()
        dialog.reject()
        assert dialog.worker is None
        qtbot.wait(1)


def configure_ssh(dialog):
    dialog.ssh_enabled.setChecked(True)
    dialog.ssh_host.setText("127.0.0.1")
    dialog.ssh_user.setText("tester")
    dialog.ssh_password.setText("secret")
    dialog.ssh_fingerprint.setText("SHA256:" + "A" * 43)
    dialog.host.setText("127.0.0.1")
    dialog.client.setText("127.0.0.1")
    dialog.port.setMinimum(0)
    dialog.port.setValue(0)


def test_ssh_triggers_after_listener_ready_and_report_has_no_credentials(qtbot, monkeypatch):
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    configure_ssh(dialog)
    started = threading.Event()
    release = threading.Event()

    def send(trigger, token, facility, severity, cancel):
        started.set()
        release.wait(2)

    monkeypatch.setattr("syslog_monitor.ui.diagnostics_dialog.SshTrigger.send", send)
    try:
        dialog.start_check()
        qtbot.waitUntil(started.is_set)
        assert "Listening" in dialog.status.text()
        release.set()
        qtbot.waitUntil(lambda: dialog.ssh_worker is None)
        assert dialog.ssh_send.isEnabled()
        assert "secret" not in json.dumps(dialog._report)
        assert "password" not in json.dumps(dialog._report)
        assert dialog._report[0]["ssh_trigger"]["completed"]
        dialog.stop_check()
        qtbot.waitUntil(lambda: dialog.worker is None)
    finally:
        release.set()
        dialog.shutdown()
    assert dialog.ssh_password.text() == ""


def test_ssh_failure_cancels_check_instead_of_claiming_delivery(qtbot, monkeypatch):
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    configure_ssh(dialog)
    def fail(*args):
        raise OSError("SSH unavailable")
    monkeypatch.setattr("syslog_monitor.ui.diagnostics_dialog.SshTrigger.send", fail)
    try:
        dialog.start_check()
        qtbot.waitUntil(lambda: dialog.worker is None)
        assert "SSH trigger failed" in dialog.output.toPlainText()
        assert dialog._report[0]["ssh_trigger"]["completed"] is False
        assert dialog._report[-1]["result"]["status"] == "inconclusive"
    finally:
        dialog.shutdown()


def test_received_message_waits_for_logger_exit_without_cancelling_ssh(qtbot, monkeypatch):
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    configure_ssh(dialog)
    dialog.port.setMinimum(1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as free:
        free.bind(("127.0.0.1", 0))
        dialog.port.setValue(free.getsockname()[1])
    port = dialog.port.value()
    release = threading.Event()
    def send(trigger, token, facility, severity, cancel):
        message = f"<134>1 2026-11-06T00:00:00Z client app - - - {token}".encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message, ("127.0.0.1", port))
        release.wait(3)
        assert not cancel.is_set()
    monkeypatch.setattr("syslog_monitor.ui.diagnostics_dialog.SshTrigger.send", send)
    try:
        dialog.start_check()
        qtbot.waitUntil(lambda: dialog.worker is not None and dialog.worker.isFinished())
        assert dialog.ssh_worker is not None
        release.set()
        qtbot.waitUntil(lambda: dialog.worker is None)
        assert dialog._report[0]["ssh_trigger"]["completed"]
        assert dialog._report[-1]["result"]["status"] == "passed"
    finally:
        release.set()
        dialog.shutdown()


@pytest.mark.parametrize("accepted", [False, True])
def test_first_host_confirmation_is_dispatched_on_gui_thread(qtbot, tmp_path, monkeypatch, accepted):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr("syslog_monitor.ssh_trigger.Path.home", lambda: tmp_path)
    dialog = DiagnosticsDialog()
    qtbot.addWidget(dialog)
    configure_ssh(dialog)
    dialog.ssh_fingerprint.clear()
    prompts = []
    def prompt(box):
        prompts.append(box.text())
        return QMessageBox.Yes if accepted else QMessageBox.No
    monkeypatch.setattr(QMessageBox, "exec", prompt)
    def send(trigger, token, facility, severity, cancel):
        assert trigger.client._policy.confirm("test-host", "ssh-ed25519", "SHA256:" + "A" * 43) == accepted
    monkeypatch.setattr("syslog_monitor.ui.diagnostics_dialog.SshTrigger.send", send)
    try:
        dialog.start_check()
        qtbot.waitUntil(lambda: bool(prompts) and dialog.ssh_worker is None)
        assert "test-host" in prompts[0]
        assert "SHA256:" in prompts[0]
        dialog.stop_check()
        qtbot.waitUntil(lambda: dialog.worker is None)
    finally:
        dialog.shutdown()
