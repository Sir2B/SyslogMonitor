"""About dialog with application version and project information."""

from __future__ import annotations

import platform

from PySide6.QtCore import Qt, qVersion
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QVBoxLayout, QWidget

from syslog_monitor import APP_DISPLAY_NAME, __version__
from syslog_monitor.i18n import tr


class AboutDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("About {name}", name=APP_DISPLAY_NAME))
        self.setWindowModality(Qt.WindowModal)

        self.version_label = QLabel(f"<h2>{APP_DISPLAY_NAME}</h2><p>{tr('Version {version}', version=__version__)}</p>")
        self.version_label.setTextFormat(Qt.RichText)
        self.details_label = QLabel(
            f"<p>{tr('Receive syslog messages over UDP, TCP, and TLS. Store, search, filter, and inspect messages locally.')}</p>"
            f"<p>{tr('Copyright © 2026 Tobias Obermayer · MIT License')}<br>"
            f"Python {platform.python_version()} · Qt {qVersion()}</p>"
            f'<a href="https://github.com/Sir2B/SyslogMonitor">{tr("Project website")}</a>'
            '&nbsp;·&nbsp;'
            f'<a href="https://github.com/Sir2B/SyslogMonitor/issues">{tr("Report an issue")}</a>')
        self.details_label.setTextFormat(Qt.RichText)
        self.details_label.setWordWrap(True)
        self.details_label.setOpenExternalLinks(True)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(self.version_label)
        layout.addWidget(self.details_label)
        layout.addWidget(buttons)
