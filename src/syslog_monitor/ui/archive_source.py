"""Data source selector: the live database or one archive file.

An archive file is unpacked into a temporary database so the log view, filters,
search and minimap work unchanged. Receiving continues into the live database.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import threading
from pathlib import Path

from PySide6.QtCore import QThread, QTimer, Signal
from PySide6.QtWidgets import QComboBox, QProgressDialog, QWidget

from syslog_monitor.archive import ArchiveFile, archive_dir, load_into_database, read_index
from syslog_monitor.i18n import tr
from syslog_monitor.storage import EVENT_COLUMNS, db_path, insert_rows, open_database
from syslog_monitor.ui.formatting import format_bytes, format_count, format_ts

log = logging.getLogger(__name__)

VIEW_DIR_PREFIX = "syslog-archive-view-"
LOAD_SHARE = 70  # percent of the progress bar for reading; the rest is indexing


def archive_label(entry: ArchiveFile) -> str:
    return tr("Archive {start} – {end}", start=format_ts(entry.first_ms)[:16],
              end=format_ts(entry.last_ms)[:16])


class ArchiveLoader(QThread):
    progressed = Signal(int)  # percent

    def __init__(self, source: Path, target_dir: Path, parent=None) -> None:
        super().__init__(parent)
        self.source = source
        self.target_dir = target_dir
        self.error = ""
        self.count = 0
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def _progress(self, done: int, total: int) -> bool:
        self.progressed.emit(int(LOAD_SHARE * done / total) if total else LOAD_SHARE)
        return not self._cancel.is_set()

    def run(self) -> None:
        try:
            conn = open_database(self.target_dir)
            try:
                conn.execute("PRAGMA synchronous=OFF")
                # Building the full-text index once at the end is about 3x faster.
                conn.execute("DROP TRIGGER events_ai")
                self.count = load_into_database(self.source, conn, EVENT_COLUMNS,
                                                insert=insert_rows, progress=self._progress)
                if not self._cancel.is_set():
                    conn.execute("INSERT INTO events_fts(events_fts) VALUES('rebuild')")
                    self.progressed.emit(100)
            finally:
                conn.close()
        except Exception as exc:  # report in the GUI, never crash the thread
            log.exception("Could not load archive %s", self.source)
            self.error = str(exc)


class _RefreshingCombo(QComboBox):
    about_to_show = Signal()

    def showPopup(self) -> None:
        self.about_to_show.emit()
        super().showPopup()


class SourceSelector(_RefreshingCombo):
    """Combo box listing "Live" and the archive files (newest first).

    ``source_changed(db_path, label)`` is emitted after the selection is ready;
    the label is empty for the live database.
    """

    source_changed = Signal(object, str)

    def __init__(self, live_db: Path, data_dir: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._live_db = live_db
        self._archive_dir = archive_dir(data_dir)
        self._active = ""  # archive file name, "" = live
        self._view_dir: Path | None = None
        self._stale_dirs: list[Path] = []
        self._loader: ArchiveLoader | None = None
        self._progress: QProgressDialog | None = None
        self.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.setToolTip(tr("Show live data or an archive of older messages.\n"
                           "Messages are still received and stored while an archive is shown."))
        self.about_to_show.connect(self.refresh)
        self.activated.connect(self._activated)
        self.refresh()
        remove_stale_view_dirs()

    @property
    def showing_archive(self) -> bool:
        return bool(self._active)

    def refresh(self) -> None:
        files = read_index(self._archive_dir)
        self.blockSignals(True)
        self.clear()
        self.addItem(tr("Live data"), "")
        for entry in reversed(files):
            self.addItem(f"{archive_label(entry)}  ({format_count(entry.count)}, "
                         f"{format_bytes(entry.size)})", entry.name)
            self.setItemData(self.count() - 1, entry, role=0x0101)  # Qt.UserRole + 1
        index = self.findData(self._active)
        self.setCurrentIndex(max(0, index))
        self.blockSignals(False)

    def select_live(self) -> None:
        if self._active:
            self._switch_to("", self._live_db, "")
        self.setCurrentIndex(0)

    def _activated(self, index: int) -> None:
        name = self.itemData(index) or ""
        if name == self._active or self._loader is not None:
            self.setCurrentIndex(max(0, self.findData(self._active)))
            return
        if not name:
            self.select_live()
            return
        entry: ArchiveFile = self.itemData(index, 0x0101)
        target = Path(tempfile.mkdtemp(prefix=VIEW_DIR_PREFIX))
        self._loader = ArchiveLoader(self._archive_dir / name, target, self)
        progress = QProgressDialog(tr("Loading {label}…", label=archive_label(entry)), tr("Cancel"),
                                   0, 100, self.window())
        progress.setWindowTitle(tr("Archive"))
        progress.setMinimumDuration(300)
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.canceled.connect(self._loader.cancel)
        self._loader.progressed.connect(progress.setValue)
        self._loader.finished.connect(lambda: self._loaded(name, entry, target))
        self._progress = progress
        self._loader.start()

    def _loaded(self, name: str, entry: ArchiveFile, target: Path) -> None:
        loader, self._loader = self._loader, None
        failed = loader is None or loader.cancelled or bool(loader.error)
        if self._progress is not None:
            self._progress.canceled.disconnect()  # closing the dialog emits canceled
            self._progress.close()
            self._progress.deleteLater()
            self._progress = None
        if failed:
            if loader is not None and loader.error:
                self.window().statusBar().showMessage(
                    tr("Could not load archive: {message}", message=loader.error), 10000)
            self._discard(target)
            self.setCurrentIndex(max(0, self.findData(self._active)))
            if loader is not None:
                loader.deleteLater()
            return
        loader.deleteLater()
        self._switch_to(name, db_path(target), archive_label(entry), target)

    def _switch_to(self, name: str, path: Path, label: str, view_dir: Path | None = None) -> None:
        old, self._view_dir = self._view_dir, view_dir
        self._active = name
        self.source_changed.emit(path, label)
        if old is not None:
            self._discard(old)

    def _discard(self, directory: Path) -> None:
        self._stale_dirs.append(directory)
        # Query threads close their connection asynchronously; delete a little later.
        QTimer.singleShot(2000, self._remove_stale)

    def _remove_stale(self) -> None:
        remaining = []
        for directory in self._stale_dirs:
            shutil.rmtree(directory, ignore_errors=True)
            if directory.exists():
                remaining.append(directory)
        self._stale_dirs = remaining

    def shutdown(self) -> None:
        """Call after all query clients have stopped."""
        if self._loader is not None:
            self._loader.cancel()
            self._loader.wait()
        if self._view_dir is not None:
            self._stale_dirs.append(self._view_dir)
            self._view_dir = None
        self._remove_stale()


def remove_stale_view_dirs() -> None:
    """Remove viewer databases left behind by a crash."""
    for directory in Path(tempfile.gettempdir()).glob(VIEW_DIR_PREFIX + "*"):
        shutil.rmtree(directory, ignore_errors=True)
