"""Guided creation of a CA, server and optional client certificate for TLS reception."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox, QPushButton, QSpinBox, QStackedWidget, QStyle, QToolButton,
    QVBoxLayout, QWidget,
)

from syslog_monitor.config import default_config_dir
from syslog_monitor.i18n import tr
from syslog_monitor.tls_test import DEFAULT_KEY_TYPE, KEY_TYPES, create_certificates, device_snippets, local_names

KEY_TYPE_HINTS = {
    "rsa-2048": "Recommended – works with practically every device.",
    "rsa-3072": "Stronger RSA – supported by most devices.",
    "rsa-4096": "Strongest RSA – slower, very old devices may not support it.",
    "ecdsa-p256": "Modern and fast – needs a reasonably current device.",
    "ecdsa-p384": "Modern, stronger elliptic curve – needs a current device.",
    "ed25519": "Newest type – many syslog devices do not support it yet.",
}


class CertificateDialog(QDialog):
    """Two steps: choose options, then save the created files; ``paths`` holds them after creation."""

    def __init__(self, port: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Create TLS certificates"))
        self.port = port
        self.paths: dict[str, Path] = {}
        self.stack = QStackedWidget()
        self.stack.addWidget(self._options_page())
        self.stack.addWidget(self._result_page())
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Ok).setText(tr("Create"))
        self.buttons.accepted.connect(self._ok)
        self.buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(self.stack)
        layout.addWidget(self.buttons)
        self.resize(600, self.sizeHint().height())

    def _info(self, title: str, text: str) -> QToolButton:
        button = QToolButton()
        button.setIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
        button.setAutoRaise(True)
        button.setToolTip(text)
        button.clicked.connect(lambda: QMessageBox.information(self, title, text))
        return button

    def _row(self, widget: QWidget, title: str, info: str) -> QHBoxLayout:
        row = QHBoxLayout()
        row.addWidget(widget, 1)
        row.addWidget(self._info(title, info))
        return row

    def _options_page(self) -> QWidget:
        page = QWidget()
        intro = QLabel(tr("Devices can send their logs encrypted (TLS). For this, Syslog Monitor needs a "
                          "certificate, and the devices need to trust it. This assistant creates everything "
                          "that is needed – no prior knowledge required."))
        intro.setWordWrap(True)
        self.names = QLineEdit(", ".join(local_names()))
        self.key_type = QComboBox()
        for key, label in KEY_TYPES.items():
            self.key_type.addItem(label, key)
            self.key_type.setItemData(self.key_type.count() - 1, tr(KEY_TYPE_HINTS[key]), 3)
        self.key_type.setCurrentIndex(list(KEY_TYPES).index(DEFAULT_KEY_TYPE))
        self.key_hint = QLabel()
        self.key_hint.setWordWrap(True)
        self.key_type.currentIndexChanged.connect(self._update_key_hint)
        self._update_key_hint()
        self.days = QSpinBox(minimum=1, maximum=3650, value=825, suffix=tr(" days"))
        self.mtls = QCheckBox(tr("Only accept devices with their own certificate"))
        self.folder = QLineEdit(str(default_config_dir() / "certificates"))
        browse = QPushButton(tr("Browse…"))
        browse.clicked.connect(self._browse)
        folder_row = QHBoxLayout()
        folder_row.addWidget(self.folder, 1)
        folder_row.addWidget(browse)
        form = QFormLayout()
        form.addRow(tr("Address of this PC:"), self._row(self.names, tr("Address of this PC"), tr(
            "Enter the names or IP addresses the devices use to reach this computer, separated by commas. "
            "The certificate is only valid for these addresses – if a device uses another address, "
            "it rejects the connection. The suggestions were detected automatically.")))
        form.addRow(tr("Key type:"), self._row(self.key_type, tr("Key type"), tr(
            "The key type determines the encryption method. If unsure, keep RSA 2048: it works "
            "with practically every device. ECDSA is more modern and faster, Ed25519 is the newest "
            "type but not supported by many devices yet.")))
        form.addRow("", self.key_hint)
        form.addRow(tr("Valid for:"), self._row(self.days, tr("Validity"), tr(
            "After this time the certificates expire and must be created again. Some devices "
            "(for example Apple devices) reject certificates valid for more than 825 days.")))
        form.addRow("", self._row(self.mtls, tr("Device certificate"), tr(
            "Optional, for more security: Syslog Monitor then only accepts devices that present a "
            "certificate created here (mutual TLS). Each device then needs the device certificate "
            "in addition to the CA certificate. Leave it off if unsure.")))
        form.addRow(tr("Save in:"), folder_row)
        hint = QLabel(tr("A new certificate authority is created each time, so devices must trust "
                         "the new CA certificate afterwards. Files with the same names in the folder are replaced."))
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(mid);")
        layout = QVBoxLayout(page)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(hint)
        layout.addStretch(1)
        return page

    def _result_page(self) -> QWidget:
        page = QWidget()
        self.result_label = QLabel()
        self.result_label.setWordWrap(True)
        device = QGroupBox(tr("For the devices (clients)"))
        device_layout = QVBoxLayout(device)
        self.save_device_button = QPushButton(tr("Save device files…"))
        self.save_device_button.clicked.connect(self.save_device_files)
        device_layout.addLayout(self._row(self.save_device_button, tr("Device files"), tr(
            "Saves all files a device may need into one folder. The CA certificate contains no secret; "
            "the device key is secret – only copy it to your own devices. Which file goes into which "
            "field on the device is shown in the table below.")))
        self.mapping = QLabel()
        self.mapping.setWordWrap(True)
        self.mapping.setTextInteractionFlags(Qt.TextSelectableByMouse)
        device_layout.addWidget(self.mapping)
        server = QGroupBox(tr("For Syslog Monitor (server)"))
        server_layout = QVBoxLayout(server)
        done = QLabel("✓ " + tr("Already entered in the settings – nothing else to do."))
        done.setWordWrap(True)
        server_layout.addWidget(done)
        self.save_server_button = QPushButton(tr("Save server certificate…"))
        self.save_server_button.clicked.connect(self.save_server)
        server_layout.addLayout(self._row(self.save_server_button, tr("Server certificate"), tr(
            "Syslog Monitor uses this certificate to identify itself to the devices. It is only needed "
            "if you want to run another syslog server with it. It contains a private key – keep it secret.")))
        open_button = QPushButton(tr("Open folder"))
        open_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(self.folder.text())))
        open_row = QHBoxLayout()
        open_row.addStretch(1)
        open_row.addWidget(open_button)
        layout = QVBoxLayout(page)
        layout.addWidget(self.result_label)
        layout.addWidget(device)
        layout.addWidget(server)
        layout.addLayout(open_row)
        layout.addStretch(1)
        return page

    def _update_key_hint(self) -> None:
        self.key_hint.setText(tr(KEY_TYPE_HINTS[self.key_type.currentData()]))

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, tr("Choose folder"), self.folder.text())
        if path:
            self.folder.setText(path)

    def _ok(self) -> None:
        if self.stack.currentIndex() == 0:
            self.create()
        else:
            self.accept()

    def create(self) -> bool:
        names = [name.strip() for name in self.names.text().replace(";", ",").split(",") if name.strip()]
        folder = Path(self.folder.text().strip())
        if not names or not self.folder.text().strip():
            QMessageBox.warning(self, self.windowTitle(), tr("Enter at least one address and a folder."))
            return False
        mtls = self.mtls.isChecked()
        try:
            self.paths = create_certificates(folder, names, mtls=mtls, days=self.days.value(),
                                             key_type=self.key_type.currentData())
            for name, text in device_snippets(names[0], self.port, mtls).items():
                (folder / name).write_text(text, encoding="utf-8", newline="\n")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, self.windowTitle(), str(exc))
            return False
        self.result_label.setText(tr("The certificates were created. Now give the devices the files "
                                     "they need:"))
        self.mapping.setText(self._mapping_html(mtls))
        self.buttons.button(QDialogButtonBox.Ok).setText(tr("Done"))
        self.buttons.button(QDialogButtonBox.Cancel).hide()
        self.stack.setCurrentIndex(1)
        return True

    def _save(self, title: str, default: str, choices: list[tuple[str, bytes]]) -> Path | None:
        filters = ";;".join(label for label, _ in choices)
        path, chosen = QFileDialog.getSaveFileName(self, title, str(Path.home() / default), filters)
        if not path:
            return None
        data = dict(choices).get(chosen, choices[0][1])
        try:
            Path(path).write_bytes(data)
        except OSError as exc:
            QMessageBox.warning(self, title, str(exc))
            return None
        return Path(path)

    def _read(self, *keys: str) -> bytes:
        return b"".join(self.paths[key].read_bytes() for key in keys)

    def device_files(self) -> dict[str, tuple[str, bytes]]:
        files = {"ca": ("syslog-ca.crt", self._read("ca_crt"))}
        if self.mtls.isChecked():
            files.update({
                "cert": ("syslog-device.crt", self._read("client_crt")),
                "key": ("syslog-device-key.pem", self._read("client_key")),
                "p12": ("syslog-device.p12", self._read("client_p12")),
            })
        return files

    def _mapping_html(self, mtls: bool) -> str:
        rows = [(tr("CA certificate, CA crt, trusted / root certificate"), "syslog-ca.crt")]
        if mtls:
            rows += [(tr("Certificate, client / device certificate (.crt)"), "syslog-device.crt"),
                     (tr("Private key, key (.pem / .key)"), "syslog-device-key.pem"),
                     (tr("Only one file (PKCS#12, .p12 / .pfx)"), "syslog-device.p12")]
        else:
            rows.append((tr("Certificate and key"), tr("not needed – the device only checks the server")))
        body = "".join(f"<tr><td>{field}</td><td>&nbsp;→&nbsp;</td><td><b>{name}</b></td></tr>"
                       for field, name in rows)
        note = tr("The file extension does not matter: .pem, .crt and .key are all text files in PEM format.")
        return (f"<p>{tr('The device asks for … → use:')}</p><table>{body}</table>"
                + (f"<p>{note}</p>" if mtls else ""))

    def save_device_files(self) -> Path | None:
        path = QFileDialog.getExistingDirectory(self, tr("Save device files"), str(Path.home()))
        if not path:
            return None
        try:
            for name, data in self.device_files().values():
                (Path(path) / name).write_bytes(data)
        except OSError as exc:
            QMessageBox.warning(self, tr("Save device files"), str(exc))
            return None
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        return Path(path)

    def save_server(self) -> Path | None:
        return self._save(tr("Save server certificate"), "syslog-server.pem", [
            (tr("Certificate chain and key as text") + " (*.pem)", self._read("server")),
            (tr("Certificate chain only") + " (*.crt)", self._read("server_chain")),
            (tr("Key only") + " (*.key)", self._read("server_key"))])
