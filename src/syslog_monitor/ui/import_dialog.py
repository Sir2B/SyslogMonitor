"""Import messages from files with a cancellable background worker."""

from __future__ import annotations

import csv
import json
import logging
import sqlite3
import time
from pathlib import Path
from threading import Event

from PySide6.QtCore import QDateTime, QThread, Signal, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHeaderView,
    QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from syslog_monitor.events import facility_name, severity_name
from syslog_monitor.i18n import tr
from syslog_monitor.importer import (
    FORMAT_CSV, FORMAT_JSONL, FORMAT_LINES, FORMAT_TABBED, FORMATS, ImportCancelled, ImportResult,
    import_file, preview,
)
from syslog_monitor.ui.palette import status_color

log = logging.getLogger(__name__)
PREVIEW_ROWS = 20
PREVIEW_COLUMNS = ("Time", "Sender", "Facility", "Severity", "Host", "Application", "Message")


def format_label(kind: str) -> str:
    return {
        FORMAT_CSV: tr("CSV export"),
        FORMAT_JSONL: tr("JSONL export"),
        FORMAT_TABBED: tr("tab-separated syslog server log"),
        FORMAT_LINES: tr("one message per line"),
    }.get(kind, kind)


class ImportThread(QThread):
    progress = Signal("qlonglong")

    def __init__(self, db_path: Path, source: Path, kind: str, parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("import-worker")
        self.db_path = db_path
        self.source = source
        self.kind = kind
        self.cancel = Event()
        self.result: ImportResult | None = None
        self.cancelled_after = 0
        self.error = ""
        self.now_ms = time.time_ns() // 1_000_000

    def run(self) -> None:
        try:
            self.result = import_file(self.db_path, self.source, now_ms=self.now_ms,
                                      cancel=self.cancel, progress=self.progress.emit,
                                      kind=self.kind)
        except ImportCancelled as exc:
            self.cancelled_after = exc.args[0] if exc.args else 0
        except (OSError, sqlite3.Error, ValueError, csv.Error, json.JSONDecodeError) as exc:
            log.exception("Log import failed")
            self.error = str(exc)


class ImportDialog(QDialog):
    imported = Signal()

    def __init__(self, db_path: Path, parent: QWidget | None = None, *, embedded: bool = False) -> None:
        super().__init__(parent)
        self._embedded = embedded
        if embedded:
            self.setWindowFlags(Qt.Widget)
        self.setWindowTitle(tr("Import messages"))
        self._db_path = db_path
        self.worker: ImportThread | None = None
        self._valid = False
        hint = QLabel(tr(
            "Adds messages from a file to the stored log. The format is detected automatically:\n"
            "• CSV or JSONL files exported by Syslog Monitor (with raw_base64 the original packets "
            "are restored exactly)\n"
            "• tab-separated logs of syslog servers (sender, time, version, facility, severity, tag, message)\n"
            "• text files with one syslog message per line, with or without <PRI> (e.g. /var/log/syslog)\n\n"
            "Imported messages keep their original time where available. Messages older than the "
            "retention period in Settings are removed by the next cleanup. "
            "Importing the same file twice adds the messages twice."))
        hint.setWordWrap(True)
        self.source: Path | None = None
        self.file_label = QLabel(tr("No file selected."))
        self.file_label.setWordWrap(True)
        self.format = QComboBox()
        for kind in FORMATS:
            self.format.addItem(format_label(kind), kind)
        self.format.setToolTip(tr("Detected automatically. Change it if the preview looks wrong."))
        self.format.currentIndexChanged.connect(self._format_changed)
        form = QFormLayout()
        form.addRow(tr("File:"), self.file_label)
        form.addRow(tr("Format:"), self.format)
        self.preview = QTableWidget(0, len(PREVIEW_COLUMNS))
        self.preview.setHorizontalHeaderLabels([tr(label) for label in PREVIEW_COLUMNS])
        self.preview.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.preview.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.preview.verticalHeader().setVisible(False)
        self.preview.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.preview.horizontalHeader().setStretchLastSection(True)
        self.preview.setMinimumHeight(320)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.choose_button = self.buttons.addButton(tr("Choose file…"), QDialogButtonBox.ActionRole)
        self.choose_button.clicked.connect(lambda: self.choose_file())
        self.import_button = self.buttons.addButton(tr("Import"), QDialogButtonBox.AcceptRole)
        self.import_button.clicked.connect(self.start_import)
        self.buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(hint)
        layout.addLayout(form)
        layout.addWidget(QLabel(tr("Preview (first {count} messages as they will be stored):",
                                   count=PREVIEW_ROWS)))
        layout.addWidget(self.preview)
        layout.addWidget(self.status)
        layout.addWidget(self.buttons)
        self._set_running(False)

    def choose_file(self, path: str | None = None) -> None:
        if not path:
            path, _ = QFileDialog.getOpenFileName(
                self, tr("Import messages"), "",
                tr("Log files (*.csv *.jsonl *.json *.log *.txt);;All files (*)"))
        if not path:
            return
        self.source = Path(path)
        self.file_label.setText(str(self.source))
        self._load_preview(None)

    def _format_changed(self) -> None:
        if self.source is not None and self.worker is None:
            self._load_preview(self.format.currentData())

    def _load_preview(self, kind: str | None) -> None:
        self.preview.setRowCount(0)
        self.status.setStyleSheet("")
        try:
            kind, events = preview(self.source, time.time_ns() // 1_000_000, kind, PREVIEW_ROWS)
        except (OSError, ValueError, csv.Error, json.JSONDecodeError, AttributeError) as exc:
            self._valid = False
            self.status.setStyleSheet(f"color: {status_color('#b00020')}")
            self.status.setText(tr("The file cannot be read in this format: {message}", message=exc))
            self._set_running(False)
            return
        self.format.blockSignals(True)
        self.format.setCurrentIndex(self.format.findData(kind))
        self.format.blockSignals(False)
        self.preview.setRowCount(len(events))
        for row, event in enumerate(events):
            values = (
                QDateTime.fromMSecsSinceEpoch(event.received_at).toString("yyyy-MM-dd HH:mm:ss"),
                event.source_ip, facility_name(event.facility), severity_name(event.severity),
                event.hostname or "", event.app_name or "", event.message,
            )
            for column, value in enumerate(values):
                self.preview.setItem(row, column, QTableWidgetItem(value))
        self._valid = bool(events)
        self.status.setText(tr("Detected format: {kind}. Check the preview, then click Import.",
                               kind=format_label(kind)) if events else tr("The file contains no messages."))
        self._set_running(False)

    def start_import(self) -> None:
        if self.source is None or not self._valid:
            return
        self.status.setStyleSheet("")
        self.status.setText(tr("Importing…"))
        self._set_running(True)
        self.worker = ImportThread(self._db_path, self.source, self.format.currentData(), self)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._finished)
        self.worker.start()

    def _set_running(self, running: bool) -> None:
        self.buttons.button(QDialogButtonBox.Cancel).setEnabled(running or not self._embedded)
        self.import_button.setEnabled(not running and self.source is not None and self._valid)
        self.choose_button.setEnabled(not running)
        self.format.setEnabled(not running and self.source is not None)

    def _progress(self, count: int) -> None:
        self.status.setText(tr("Importing… {count} messages added", count=f"{count:,}"))

    def _finished(self) -> None:
        worker = self.worker
        if worker is None:
            return
        self._set_running(False)
        if worker.error:
            self.status.setStyleSheet(f"color: {status_color('#b00020')}")
            self.status.setText(tr("Import failed: {message}", message=worker.error))
        elif worker.result is not None:
            self.status.setText(tr("Imported {count} messages from {path} ({kind}).",
                                   count=f"{worker.result.rows:,}", path=worker.source,
                                   kind=format_label(worker.result.format)))
        else:
            self.status.setText(tr("Import cancelled after {count} messages.",
                                   count=f"{worker.cancelled_after:,}"))
        self.worker = None
        worker.deleteLater()
        self.imported.emit()

    def reject(self) -> None:
        if self.worker is not None:
            self.status.setText(tr("Cancelling import…"))
            self.worker.cancel.set()
        elif not self._embedded:
            super().reject()

    def shutdown(self) -> None:
        if self.worker is not None:
            self.worker.cancel.set()
            self.worker.wait()
