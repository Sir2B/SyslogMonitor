"""Guided syslog checks on an isolated listener with an exportable evidence report."""

from __future__ import annotations

import json
import logging
import secrets
import tempfile
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import paramiko

from PySide6.QtCore import QThread, Signal, Slot, Qt, QTimer, QSettings
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QLabel, QLineEdit,
    QCheckBox, QHBoxLayout, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QVBoxLayout, QWidget,
)

from syslog_monitor.diagnostics import CheckOptions, CheckResult, generate_certificates, run_check
from syslog_monitor import __version__
from syslog_monitor.i18n import tr
from syslog_monitor.ssh_trigger import SshOptions, SshTrigger

log = logging.getLogger(__name__)
CASE_LABELS = {
    "udp": "UDP message",
    "tcp": "TCP message and framing",
    "tcp_reconnect": "TCP reconnect (two connections)",
    "tls_valid": "TLS positive control",
    "tls_untrusted": "TLS: untrusted CA",
    "tls_hostname": "TLS: wrong hostname",
    "tls_expired": "TLS: expired certificate",
    "tls_usage": "TLS: wrong certificate purpose",
}


class CheckThread(QThread):
    ready = Signal(int)

    def __init__(self, options: CheckOptions, certificate: Path | None, baseline: bool, parent):
        super().__init__(parent)
        self.options = options
        self.certificate = certificate
        self.baseline = baseline
        self.cancel = threading.Event()
        self.result: CheckResult | None = None
        self.error = ""

    def run(self) -> None:
        try:
            self.result = run_check(self.options, self.cancel, certificate=self.certificate,
                                    baseline_ok=self.baseline, ready=self.ready.emit)
        except (OSError, ValueError) as exc:
            log.exception("Syslog diagnostic failed")
            self.error = str(exc)


class SshThread(QThread):
    host_confirmation = Signal(str, str, str)

    def __init__(self, options: SshOptions, check: CheckOptions, parent):
        super().__init__(parent)
        self.check = check
        self.cancel = threading.Event()
        self.confirmed = threading.Event()
        self.accepted = False
        self.trigger = SshTrigger(options, self.confirm_host)
        self.error = ""

    def confirm_host(self, host: str, algorithm: str, fingerprint: str) -> bool:
        self.host_confirmation.emit(host, algorithm, fingerprint)
        for _ in range(300):
            if self.confirmed.wait(0.1):
                return self.accepted and not self.cancel.is_set()
            if self.cancel.is_set():
                return False
        return False

    def run(self) -> None:
        try:
            self.trigger.send(self.check.token, self.check.facility, self.check.severity, self.cancel)
        except (OSError, ValueError, paramiko.SSHException) as exc:
            log.warning("SSH test trigger failed: %s", exc)
            self.error = str(exc)
        finally:
            self.trigger.close()

    def stop(self) -> None:
        self.cancel.set()
        self.trigger.close()


class DiagnosticsDialog(QDialog):
    def __init__(self, parent=None, *, ui_state: QSettings | None = None):
        super().__init__(parent)
        self._ui_state = ui_state if ui_state is not None else QSettings("SyslogMonitor", "ClientChecks")
        self.setWindowTitle(tr("Syslog client checks"))
        self._temporary = tempfile.TemporaryDirectory(prefix="syslog-client-check-")
        self._certificates: dict[str, Path] = {}
        self._certificate_hostname = ""
        self._baseline: tuple | None = None
        self._report: list[dict] = []
        self.worker: CheckThread | None = None
        self.ssh_worker: SshThread | None = None
        self._ssh_options: SshOptions | None = None
        self.case = QComboBox()
        for value, label in CASE_LABELS.items():
            self.case.addItem(tr(label), value)
        self.host = QLineEdit("0.0.0.0")
        self.port = QSpinBox(minimum=1, maximum=65535, value=18514)
        self.port.setToolTip(tr(
            "Use the destination port configured on the device, e.g. 514. "
            "Stop normal reception first if it uses the same port and protocol."))
        self.client = QLineEdit(placeholderText="192.0.2.50")
        self.hostname = QLineEdit(placeholderText="syslog.example")
        self.format = QComboBox()
        self.format.addItem("RFC 5424", "rfc5424")
        self.format.addItem("RFC 3164", "rfc3164")
        self.facility = QSpinBox(minimum=0, maximum=23, value=16)
        self.severity = QSpinBox(minimum=0, maximum=7, value=6)
        self.timeout = QSpinBox(minimum=5, maximum=300, value=60, suffix=" s")
        self.token = QLineEdit("SYSLOG-CHECK-" + secrets.token_hex(6), readOnly=True)
        self.ssh_enabled = QCheckBox(tr("Trigger message via SSH (Linux logger)"))
        self.ssh_host = QLineEdit(placeholderText="192.0.2.50")
        self.ssh_port = QSpinBox(minimum=1, maximum=65535, value=22)
        self.ssh_user = QLineEdit()
        self.ssh_password = QLineEdit(echoMode=QLineEdit.Password)
        self.ssh_key = QLineEdit(placeholderText=tr("Empty: SSH agent and keys in ~/.ssh"))
        self.ssh_fingerprint = QLineEdit(placeholderText=tr("Optional: pin a verified SHA256 fingerprint"))
        self.ssh_send = QPushButton(tr("Send another message via SSH"), enabled=False)
        self.ssh_send.clicked.connect(self.send_ssh)
        form = QFormLayout()
        for label, widget in (
            ("Test:", self.case), ("Bind address:", self.host), ("Test port:", self.port),
            ("Client IPv4:", self.client), ("TLS server name:", self.hostname),
            ("Message format:", self.format), ("Expected facility:", self.facility),
            ("Expected severity:", self.severity), ("Timeout:", self.timeout),
            ("Send this text:", self.token),
        ):
            form.addRow(tr(label), widget)
        form.addRow(self.ssh_enabled)
        for label, widget in (
            ("SSH host:", self.ssh_host), ("SSH port:", self.ssh_port),
            ("SSH username:", self.ssh_user), ("SSH password / key passphrase:", self.ssh_password),
            ("SSH private key file:", self.ssh_key), ("SSH fingerprint (optional):", self.ssh_fingerprint),
        ):
            form.addRow(tr(label), widget)
        ssh_hint = QLabel(tr(
            "SSH runs Linux logger locally after the listener is ready. Configure syslog forwarding "
            "on the device yourself. Known SSH hosts are recognized automatically; "
            "new hosts require confirmation once. Changed host keys are rejected. "
            "Credentials are not saved. SSH cannot force your syslog daemon to reconnect."))
        ssh_hint.setWordWrap(True)
        self.instructions = QLabel(tr(
            "Configure your client to send to this PC's test port. Send the exact token above "
            "inside a syslog message with the selected format and PRI. For reconnect, send it "
            "on two separate connections. In manual mode, no commands are run on the client.\n"
            "For TLS, export and trust the temporary CA on the client, configure the server name "
            "above, then complete the positive control before negative tests. Keep client settings "
            "unchanged between TLS tests and reconnect for each test. TLS positive control requires "
            "octet-counted framing. Missing traffic is inconclusive.\n"
            "The normal receiver is unchanged. This is a guided check, not official certification."))
        self.instructions.setWordWrap(True)
        self.ca_button = QPushButton(tr("Create test CA and export"))
        self.ca_button.clicked.connect(self.export_ca)
        self.start_button = QPushButton(tr("Start check"))
        self.start_button.clicked.connect(self.start_check)
        self.stop_button = QPushButton(tr("Stop check"), enabled=False)
        self.stop_button.clicked.connect(self.stop_check)
        self.report_button = QPushButton(tr("Export report"), enabled=False)
        self.report_button.clicked.connect(self.export_report)
        self.status = QLabel()
        self.status.setTextFormat(Qt.PlainText)
        self.status.setWordWrap(True)
        self.output = QPlainTextEdit(readOnly=True)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.button(QDialogButtonBox.Close).setText(tr("Close"))
        buttons.rejected.connect(self.reject)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.addWidget(self.instructions)
        content_layout.addLayout(form)
        content_layout.addWidget(ssh_hint)
        content_layout.addWidget(self.ssh_send)
        content_layout.addWidget(self.ca_button)
        scroll = QScrollArea(widgetResizable=True)
        scroll.setWidget(content)
        layout = QVBoxLayout(self)
        layout.addWidget(scroll, 3)
        actions = QHBoxLayout()
        for widget in (self.start_button, self.stop_button, self.report_button):
            actions.addWidget(widget)
        layout.addLayout(actions)
        for widget in (self.status, self.output, buttons):
            layout.addWidget(widget)
        self.resize(650, 700)
        self._restore_settings()

    def _setting_widgets(self) -> dict:
        return {name: getattr(self, name) for name in (
            "case", "host", "port", "client", "hostname", "format", "facility", "severity",
            "timeout", "ssh_enabled", "ssh_host", "ssh_port", "ssh_user", "ssh_key", "ssh_fingerprint",
        )}

    def _save_settings(self) -> bool:
        values = {}
        for name, widget in self._setting_widgets().items():
            if isinstance(widget, QComboBox):
                values[name] = widget.currentData()
            elif isinstance(widget, QSpinBox):
                values[name] = widget.value()
            elif isinstance(widget, QCheckBox):
                values[name] = widget.isChecked()
            else:
                values[name] = widget.text()
        self._ui_state.setValue("diagnostics", json.dumps(values))
        self._ui_state.sync()
        if self._ui_state.status() != QSettings.NoError:
            self._error(OSError(tr("Could not save client check settings.")))
            return False
        return True

    def _restore_settings(self) -> None:
        stored = self._ui_state.value("diagnostics")
        if stored is None:
            return
        try:
            values = json.loads(stored)
            if not isinstance(values, dict):
                raise ValueError("Invalid client check settings")
            for name, widget in self._setting_widgets().items():
                if name not in values:
                    continue
                value = values[name]
                if isinstance(widget, QComboBox):
                    index = widget.findData(value)
                    if not isinstance(value, str) or index < 0:
                        raise ValueError(f"Invalid saved field: {name}")
                    widget.setCurrentIndex(index)
                elif isinstance(widget, QSpinBox):
                    if type(value) is not int or not widget.minimum() <= value <= widget.maximum():
                        raise ValueError(f"Invalid saved field: {name}")
                    widget.setValue(value)
                elif isinstance(widget, QCheckBox):
                    if type(value) is not bool:
                        raise ValueError(f"Invalid saved field: {name}")
                    widget.setChecked(value)
                else:
                    if not isinstance(value, str):
                        raise ValueError(f"Invalid saved field: {name}")
                    widget.setText(value)
        except (TypeError, ValueError) as exc:
            log.warning("Could not restore client check settings: %s", exc)
            self.status.setText(tr("Could not restore some client check settings; check the fields."))

    def _key(self) -> tuple:
        return (self.host.text().strip(), self.port.value(), self.client.text().strip(),
                self.hostname.text().strip(), self.format.currentData(),
                self.facility.value(), self.severity.value(), self.ssh_enabled.isChecked(),
                self.ssh_host.text().strip(), self.ssh_port.value(), self.ssh_user.text().strip(),
                self.ssh_fingerprint.text().strip(), self.ssh_key.text().strip())

    def _error(self, exc: Exception) -> None:
        log.warning("Syslog diagnostic: %s", exc)
        self.status.setText(tr("Check error: {error}", error=tr(str(exc))))

    def export_ca(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(self, tr("Export test CA"), "syslog-test-ca.pem",
                                                 "PEM (*.pem)")
        if not filename:
            return
        try:
            self._baseline = None
            self._certificates = {}
            certificates = generate_certificates(Path(self._temporary.name),
                                                  self.hostname.text().strip())
            Path(filename).write_bytes(certificates["ca"].read_bytes())
            self._certificates = certificates
            self._certificate_hostname = self.hostname.text().strip()
        except (OSError, ValueError) as exc:
            self._error(exc)
            return
        self.status.setText(tr("Trust this test CA on the client; remove it after testing."))

    def start_check(self) -> None:
        if self.worker is not None:
            return
        if not self._save_settings():
            return
        options = CheckOptions(self.case.currentData(), self.host.text().strip(), self.port.value(),
                               self.client.text().strip(), self.token.text(), self.format.currentData(),
                               self.facility.value(), self.severity.value(), self.timeout.value())
        try:
            options.validate()
            self._ssh_options = None
            if self.ssh_enabled.isChecked():
                self._ssh_options = SshOptions(
                    self.ssh_host.text().strip(), self.ssh_port.value(), self.ssh_user.text().strip(),
                    self.ssh_fingerprint.text().strip(), self.ssh_password.text(),
                    self.ssh_key.text().strip())
                self._ssh_options.validate()
            if options.case.startswith("tls_") and (
                    not self._certificates or self._certificate_hostname != self.hostname.text().strip()):
                raise ValueError(tr("Create and export a test CA for this server name first."))
            if options.case.startswith("tls_") and options.case != "tls_valid" and self._baseline != self._key():
                raise ValueError(tr("Complete the TLS positive control with these settings first."))
        except ValueError as exc:
            self._error(exc)
            return
        if options.case == "tls_valid":
            self._baseline = None
        worker = CheckThread(options, self._certificates.get(options.case),
                             self._baseline == self._key(), self)
        self.worker = worker
        self._running(True)
        self.status.setText(tr("Starting isolated test listener…"))
        worker.ready.connect(self._ready, Qt.QueuedConnection)
        worker.finished.connect(self._finished, Qt.QueuedConnection)
        worker.start()

    @Slot(int)
    def _ready(self, port: int) -> None:
        if self.worker is not None and not self.worker.cancel.is_set():
            self.status.setText(tr("Listening on test port {port}. Send the test message now.", port=port))
            if self._ssh_options is not None:
                self.send_ssh()

    @Slot()
    def send_ssh(self) -> None:
        if (self.worker is None or not self.worker.isRunning() or self.worker.cancel.is_set()
                or self.ssh_worker is not None or self._ssh_options is None):
            return
        try:
            worker = SshThread(self._ssh_options, self.worker.options, self)
        except (OSError, ValueError, paramiko.SSHException) as exc:
            self._error(exc)
            self.worker.cancel.set()
            return
        self.ssh_worker = worker
        self.ssh_send.setEnabled(False)
        worker.finished.connect(self._ssh_finished, Qt.QueuedConnection)
        worker.host_confirmation.connect(self._confirm_ssh_host, Qt.QueuedConnection)
        worker.start()

    @Slot(str, str, str)
    def _confirm_ssh_host(self, host: str, algorithm: str, fingerprint: str) -> None:
        worker = self.ssh_worker
        if worker is None or worker is not self.sender() or worker.cancel.is_set():
            return
        box = QMessageBox(self)
        box.setWindowTitle(tr("Trust SSH host?"))
        box.setTextFormat(Qt.PlainText)
        box.setText(tr("This SSH host is not known yet:\n{host}\n{algorithm}\n{fingerprint}",
                       host=host, algorithm=algorithm, fingerprint=fingerprint))
        box.setInformativeText(tr(
            "Compare the fingerprint with the device through a trusted channel. "
            "Accept and remember this host? Changed keys will be blocked."))
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        timer = QTimer(box)
        timer.setSingleShot(True)
        timer.timeout.connect(box.reject)
        timer.start(30000)
        worker.accepted = box.exec() == QMessageBox.Yes
        worker.confirmed.set()

    @Slot()
    def _ssh_finished(self) -> None:
        worker = self.ssh_worker
        if worker is None or (isinstance(self.sender(), SshThread) and self.sender() is not worker):
            return
        worker.wait()
        message = (tr("SSH trigger failed: {error}", error=tr(worker.error)) if worker.error
                   else tr("SSH logger completed; this does not prove syslog delivery."))
        for warning in worker.trigger.client.key_load_warnings:
            self.output.appendPlainText(tr("SSH key warning: {warning}", warning=warning))
        self.output.appendPlainText(message)
        self._report.append({
            "ssh_trigger": {"host": worker.trigger.options.host, "port": worker.trigger.options.port,
                            "username": worker.trigger.options.username,
                            "host_fingerprint": worker.trigger.verified_fingerprint,
                            "token": worker.check.token, "error": worker.error,
                            "key_warnings": list(worker.trigger.client.key_load_warnings),
                            "completed": not bool(worker.error)},
            "checked_at": datetime.now(timezone.utc).isoformat(),
        })
        if worker.error:
            self.status.setText(message)
            if self.worker is not None:
                self.worker.cancel.set()
        self.ssh_worker = None
        worker.deleteLater()
        self.ssh_send.setEnabled(self.worker is not None and self.worker.isRunning()
                                 and not self.worker.cancel.is_set())
        self.report_button.setEnabled(self.worker is None and bool(self._report))
        if self.worker is not None and self.worker.isFinished():
            self._finished()

    def _running(self, running: bool) -> None:
        for widget in (self.case, self.host, self.port, self.client, self.hostname, self.format,
                       self.facility, self.severity, self.timeout, self.ca_button, self.start_button,
                       self.ssh_enabled, self.ssh_host, self.ssh_port, self.ssh_user,
                       self.ssh_password, self.ssh_key, self.ssh_fingerprint):
            widget.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.report_button.setEnabled(not running and bool(self._report))

    def stop_check(self) -> None:
        if self.ssh_worker is not None:
            self.ssh_worker.stop()
        if self.worker is not None:
            self.worker.cancel.set()
            self.status.setText(tr("Stopping check…"))

    @Slot()
    def _finished(self) -> None:
        worker = self.worker
        if worker is None or (isinstance(self.sender(), CheckThread) and self.sender() is not worker):
            return
        # The listener can receive the marker before the remote logger reports its exit status.
        if self.ssh_worker is not None:
            return
        worker.wait()
        if worker.error:
            self._error(ValueError(worker.error))
            self._report.append({"options": asdict(worker.options), "error": worker.error,
                                 "checked_at": datetime.now(timezone.utc).isoformat()})
        elif worker.result is not None:
            result = worker.result
            if result.case == "tls_valid" and result.status == "passed":
                self._baseline = self._key()
            self._report.append({"options": asdict(worker.options), "result": asdict(result),
                                 "checked_at": datetime.now(timezone.utc).isoformat()})
            summary = f"{tr(CASE_LABELS[result.case])}: {tr(result.status)} — {tr(result.reason)}"
            self.status.setText(summary)
            self.output.appendPlainText(summary + "\n" + "\n".join(result.evidence))
        self.worker = None
        self._ssh_options = None
        self.ssh_send.setEnabled(False)
        self._running(False)
        worker.deleteLater()

    def export_report(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(self, tr("Export report"), "syslog-checks.json",
                                                 "JSON (*.json)")
        if filename:
            try:
                Path(filename).write_text(json.dumps({
                    "type": "syslog-conformance-check", "official_certification": False,
                    "application_version": __version__,
                    "limitations": [
                        "Guided observations, not exhaustive RFC certification.",
                        "A certificate alert does not prove the precise rejection cause.",
                        "No traffic or generic connection errors are inconclusive.",
                        "Positive control requires the same client configuration throughout TLS checks.",
                        "UDP observations do not prove reliability, authentication, or security.",
                    ],
                    "checks": self._report,
                }, indent=2), encoding="utf-8")
            except OSError as exc:
                self._error(exc)

    def shutdown(self) -> None:
        self._save_settings()
        if self.ssh_worker is not None:
            self.ssh_worker.stop()
            self.ssh_worker.wait()
            self._ssh_finished()
        if self.worker is not None:
            self.worker.cancel.set()
            self.worker.wait()
            self._finished()
        self._temporary.cleanup()
        self._ssh_options = None
        self.ssh_password.clear()

    def reject(self) -> None:
        self.shutdown()
        super().reject()
