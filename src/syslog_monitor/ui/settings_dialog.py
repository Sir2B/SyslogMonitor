"""Settings dialog for listener, retention, storage and the MCP server."""

from __future__ import annotations

from dataclasses import replace

from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from syslog_monitor.config import MAX_RETENTION_DAYS, MIN_STORAGE_MB, Settings


class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self._original = settings

        self.host = QLineEdit(settings.bind_host)
        self.host.setToolTip("0.0.0.0 = all network interfaces; 127.0.0.1 = local only")
        self.udp_enabled = QCheckBox("Enable UDP reception")
        self.udp_enabled.setChecked(settings.udp_enabled)
        self.port = QSpinBox(minimum=1, maximum=65535, value=settings.port)
        self.port.setEnabled(settings.udp_enabled)
        self.udp_enabled.toggled.connect(self.port.setEnabled)
        self.tcp_enabled = QCheckBox("Enable TCP reception (no TLS)")
        self.tcp_enabled.setChecked(settings.tcp_enabled)
        self.tcp_port = QSpinBox(minimum=1, maximum=65535, value=settings.tcp_port)
        self.tcp_port.setEnabled(settings.tcp_enabled)
        self.tcp_enabled.toggled.connect(self.tcp_port.setEnabled)
        self.retention = QSpinBox(minimum=1, maximum=MAX_RETENTION_DAYS, value=settings.retention_days,
                                  suffix=" days")
        self.budget = QSpinBox(minimum=MIN_STORAGE_MB, maximum=10_000_000, value=settings.max_storage_mb,
                               suffix=" MiB", singleStep=512)
        self.data_dir = QLineEdit(settings.data_dir)
        self.data_dir.setPlaceholderText("Default (%LOCALAPPDATA%\\SyslogMonitor\\data)")
        browse = QPushButton("…")
        browse.clicked.connect(self._browse)
        dir_row = QHBoxLayout()
        dir_row.addWidget(self.data_dir)
        dir_row.addWidget(browse)
        self.autostart = QCheckBox("Start receiving automatically when the application starts")
        self.autostart.setChecked(settings.autostart_listener)

        form = QFormLayout()
        form.addRow("Listen address (IPv4):", self.host)
        form.addRow("", self.udp_enabled)
        form.addRow("UDP port:", self.port)
        form.addRow("", self.tcp_enabled)
        form.addRow("TCP port:", self.tcp_port)
        form.addRow("Retention:", self.retention)
        form.addRow("Storage budget:", self.budget)
        form.addRow("Data directory:", dir_row)
        form.addRow("", self.autostart)

        self.mcp_enabled = QCheckBox("MCP server for AI assistants (local only, read-only)")
        self.mcp_enabled.setToolTip(
            "Local access requires no authentication. Other programs on this computer can also "
            "read stored messages.")
        self.mcp_enabled.setChecked(settings.mcp_enabled)
        self.mcp_port = QSpinBox(minimum=1, maximum=65535, value=settings.mcp_port)
        self.mcp_port.setToolTip("TCP port on 127.0.0.1, URL: http://127.0.0.1:<port>/mcp")
        self.mcp_port.setEnabled(settings.mcp_enabled)
        self.mcp_enabled.toggled.connect(self.mcp_port.setEnabled)
        self.boot_marker = QLineEdit(settings.boot_marker)
        self.boot_marker.setToolTip(
            "Text marker(s) used to detect a device reboot (separate multiple markers with ;),\n"
            "e.g. for the AI query “messages since the last reboot”")
        form.addRow("", self.mcp_enabled)
        form.addRow("MCP port:", self.mcp_port)
        form.addRow("Boot marker:", self.boot_marker)

        hint = QLabel(
            "Oldest messages are deleted when either the retention period or storage budget "
            "is exceeded, whichever comes first.\n"
            "Port < 1024 (e.g. 514) and the Windows Firewall may require elevated permission.\n"
            "UDP and TCP are unencrypted and unauthenticated; use trusted networks only.\n"
            "A changed data directory takes effect after restarting the application.")
        hint.setWordWrap(True)
        self.error_label = QLabel(styleSheet="color: #b00020")
        self.error_label.setWordWrap(True)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(hint)
        layout.addWidget(self.error_label)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose data directory", self.data_dir.text())
        if path:
            self.data_dir.setText(path)

    def result_settings(self) -> Settings:
        return replace(
            self._original,
            bind_host=self.host.text().strip(),
            port=self.port.value(),
            udp_enabled=self.udp_enabled.isChecked(),
            tcp_enabled=self.tcp_enabled.isChecked(),
            tcp_port=self.tcp_port.value(),
            retention_days=self.retention.value(),
            max_storage_mb=self.budget.value(),
            data_dir=self.data_dir.text().strip(),
            autostart_listener=self.autostart.isChecked(),
            mcp_enabled=self.mcp_enabled.isChecked(),
            mcp_port=self.mcp_port.value(),
            boot_marker=self.boot_marker.text().strip(),
        )

    def accept(self) -> None:
        errors = self.result_settings().validate()
        if errors:
            self.error_label.setText("\n".join(errors))
            return
        super().accept()
