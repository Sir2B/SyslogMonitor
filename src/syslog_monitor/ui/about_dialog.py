"""About dialog with application version and project information."""

from __future__ import annotations

import platform

from PySide6.QtCore import Qt, qVersion
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QVBoxLayout, QWidget

from syslog_monitor import APP_DISPLAY_NAME, __version__


class AboutDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_DISPLAY_NAME}")
        self.setWindowModality(Qt.WindowModal)

        self.version_label = QLabel(f"<h2>{APP_DISPLAY_NAME}</h2><p>Version {__version__}</p>")
        self.version_label.setTextFormat(Qt.RichText)
        self.details_label = QLabel(
            "<p>Receive syslog messages over UDP, TCP, and TLS. Store, search, filter, "
            "and inspect messages locally.</p>"
            "<p>Copyright © 2026 Tobias Obermayer · MIT License<br>"
            f"Python {platform.python_version()} · Qt {qVersion()}</p>"
            '<a href="https://github.com/Sir2B/SyslogMonitor">Project website</a>'
            '&nbsp;·&nbsp;'
            '<a href="https://github.com/Sir2B/SyslogMonitor/issues">Report an issue</a>')
        self.details_label.setTextFormat(Qt.RichText)
        self.details_label.setWordWrap(True)
        self.details_label.setOpenExternalLinks(True)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(self.version_label)
        layout.addWidget(self.details_label)
        layout.addWidget(buttons)
