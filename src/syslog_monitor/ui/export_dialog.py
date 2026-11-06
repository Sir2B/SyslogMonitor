"""Export options and a cancellable background export."""

from __future__ import annotations

import csv
import logging
import sqlite3
import time
from pathlib import Path
from threading import Event

from PySide6.QtCore import QDateTime, QThread, Signal, Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDateTimeEdit, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGridLayout, QGroupBox, QLabel, QVBoxLayout, QWidget,
)

from syslog_monitor.export import (
    DEFAULT_EXPORT_COLUMNS, EXPORT_COLUMNS, ExportCancelled, ExportOptions, ExportResult, export_events,
)
from syslog_monitor.i18n import tr
from syslog_monitor.query import EventFilter
from syslog_monitor.ui.palette import status_color

log = logging.getLogger(__name__)
DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss"


class ExportThread(QThread):
    progress = Signal("qlonglong")

    def __init__(self, db_path: Path, destination: Path, options: ExportOptions,
                 parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("export-worker")
        self.db_path = db_path
        self.destination = destination
        self.options = options
        self.cancel = Event()
        self.result: ExportResult | None = None
        self.error = ""
        self.now_ms = time.time_ns() // 1_000_000

    def run(self) -> None:
        try:
            self.result = export_events(
                self.db_path, self.destination, self.options, now_ms=self.now_ms,
                cancel=self.cancel, progress=self.progress.emit)
        except ExportCancelled:
            pass
        except (OSError, sqlite3.Error, ValueError, csv.Error) as exc:
            log.exception("Log export failed")
            self.error = str(exc)


class ExportDialog(QDialog):
    def __init__(self, db_path: Path, boot_marker: str, filters: EventFilter,
                 parent: QWidget | None = None, *, embedded: bool = False) -> None:
        super().__init__(parent)
        self._embedded = embedded
        if embedded:
            self.setWindowFlags(Qt.Widget)
        self.setWindowTitle(tr("Export messages"))
        self._db_path = db_path
        self._boot_marker = boot_marker
        self._filters = filters
        self.worker: ExportThread | None = None
        self._closing = False
        self.period = QComboBox()
        for label, value in ((tr("Since last reboot (per sender)"), "boot"),
                             (tr("Last 24 hours"), "24h"), (tr("From / To"), "custom")):
            self.period.addItem(label, value)
        self.format = QComboBox()
        self.format.addItem(tr("CSV (Excel / spreadsheets)"), "csv")
        self.format.addItem(tr("JSONL (lossless, one JSON object per line)"), "jsonl")
        now = QDateTime.currentDateTime()
        self.start = QDateTimeEdit(now.addDays(-1), calendarPopup=True, displayFormat=DATETIME_FORMAT)
        self.end = QDateTimeEdit(now, calendarPopup=True, displayFormat=DATETIME_FORMAT)
        self.use_filters = QCheckBox(tr("Apply current severity, facility and filter rules"))
        self.use_filters.setToolTip(tr("The export period replaces the main window's time range and zoom.\n"
                                      "Search navigation and highlights do not restrict the export."))
        form = QFormLayout()
        form.addRow(tr("Period:"), self.period)
        form.addRow(tr("From (inclusive):"), self.start)
        form.addRow(tr("To (includes this second):"), self.end)
        form.addRow(tr("Format:"), self.format)
        form.addRow("", self.use_filters)
        self.columns_group = QGroupBox(tr("Columns to export"))
        columns_layout = QGridLayout(self.columns_group)
        self.column_checks: dict[str, QCheckBox] = {}
        for index, column in enumerate(EXPORT_COLUMNS):
            check = QCheckBox(tr(column) if column != "raw_base64"
                              else tr("raw_base64 (original packet)"))
            check.setChecked(column in DEFAULT_EXPORT_COLUMNS)
            self.column_checks[column] = check
            columns_layout.addWidget(check, index // 3, index % 3)
        self.column_checks["raw_base64"].setToolTip(
            tr("Include the original packet bytes encoded as Base64. Off by default."))
        hint = QLabel(
            tr("Exports all stored messages in the chosen period, not just loaded rows.\n"
            "Reboot means the last configured boot marker per sender, not this PC's restart. "
            "Senders without a stored boot marker are excluded and reported after export.\n"
            "Times use the reception time. Dates are entered in local time; exported timestamps are UTC.\n"
            "CSV protects spreadsheet formula-like text with an apostrophe. JSONL preserves text exactly."))
        hint.setWordWrap(True)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.export_button = self.buttons.addButton(tr("Export…"), QDialogButtonBox.ActionRole)
        self.export_button.clicked.connect(self.start_export)
        self.buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.columns_group)
        layout.addWidget(hint)
        layout.addWidget(self.status)
        layout.addWidget(self.buttons)
        self.period.currentIndexChanged.connect(self._period_changed)
        self._set_running(False)

    def _period_changed(self) -> None:
        custom = self.period.currentData() == "custom"
        self.start.setEnabled(custom)
        self.end.setEnabled(custom)

    def options(self) -> ExportOptions:
        filters = self._filters if self.use_filters.isChecked() else EventFilter()
        filters = filters.with_time(
            self.start.dateTime().toMSecsSinceEpoch() // 1000 * 1000,
            self.end.dateTime().toMSecsSinceEpoch() // 1000 * 1000 + 1000)
        options = ExportOptions(
            self.period.currentData(), self.format.currentData(), filters, self._boot_marker,
            columns=tuple(column for column, check in self.column_checks.items() if check.isChecked()))
        options.validate()
        return options

    def start_export(self) -> None:
        try:
            options = self.options()
        except ValueError as exc:
            self._show_error(str(exc))
            return
        extension = options.format
        destination, _ = QFileDialog.getSaveFileName(
            self, tr("Export messages"), f"syslog-export.{extension}",
            f"{extension.upper()} files (*.{extension})")
        if not destination:
            return
        self.status.setStyleSheet("")
        self.status.setText(tr("Exporting…"))
        self._set_running(True)
        self.worker = ExportThread(self._db_path, Path(destination), options, self)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._finished)
        self.worker.start()

    def _set_running(self, running: bool) -> None:
        self.buttons.button(QDialogButtonBox.Cancel).setEnabled(running or not self._embedded)
        for widget in (self.period, self.format, self.use_filters, self.columns_group, self.export_button):
            widget.setEnabled(not running)
        if running:
            self.start.setEnabled(False)
            self.end.setEnabled(False)
        else:
            self._period_changed()

    def _progress(self, count: int) -> None:
        if not self._closing:
            self.status.setText(tr("Exporting… {count} messages written", count=f"{count:,}"))

    def _show_error(self, message: str) -> None:
        self.status.setStyleSheet(f"color: {status_color('#b00020')}")
        self.status.setText(tr("Export failed: {message}", message=message))

    def _finished(self) -> None:
        worker = self.worker
        if worker is None:
            return
        self._set_running(False)
        if worker.error:
            self._show_error(worker.error)
        elif worker.result is not None:
            result = worker.result
            self.status.setText(
                tr("Exported {count} messages to {path}.",
                   count=f"{result.rows:,}", path=worker.destination)
                + (tr("\nExcluded {count} sender(s) without a stored boot marker.",
                      count=result.skipped_devices)
                   if result.skipped_devices else ""))
        else:
            self.status.setText(tr("Export cancelled. The destination was not changed."))
        self.worker = None
        worker.deleteLater()
        if self._closing:
            super().reject()

    def reject(self) -> None:
        if self.worker is not None:
            self._closing = not self._embedded
            self.status.setText(tr("Cancelling export…"))
            self.worker.cancel.set()
        elif not self._embedded:
            super().reject()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.reject()
        if self.worker is not None:
            event.ignore()
        else:
            event.accept()

    def shutdown(self) -> None:
        if self.worker is not None:
            self.worker.cancel.set()
            self.worker.wait()
