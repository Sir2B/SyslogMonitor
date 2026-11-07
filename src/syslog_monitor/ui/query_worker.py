"""Runs database queries on a background thread and delivers results to the GUI.

Every request belongs to a *generation*. Starting a new generation (e.g. after a
filter change) interrupts the running query and silently discards results of
older generations, so stale data never reaches the view.
"""

from __future__ import annotations

import itertools
import logging
import sqlite3
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QObject, QThread, Signal, Slot

from syslog_monitor.query import QueryRunner

log = logging.getLogger(__name__)

QueryFunc = Callable[[QueryRunner], Any]


class _Worker(QObject):
    finished = Signal(int, object)
    failed = Signal(int, str)

    def __init__(self, db_file: Path) -> None:
        super().__init__()
        self._db_file = db_file
        self._runner: QueryRunner | None = None
        self.latest_generation = 0  # written by the GUI thread, read here

    @property
    def runner(self) -> QueryRunner:
        if self._runner is None:
            self._runner = QueryRunner(self._db_file)
        return self._runner

    def interrupt(self) -> None:
        if self._runner is not None:
            self._runner.interrupt()

    @Slot(int, int, object)
    def run(self, request_id: int, generation: int, func: QueryFunc) -> None:
        if generation < self.latest_generation:
            self.failed.emit(request_id, "")  # skipped, stale
            return
        try:
            result = func(self.runner)
        except sqlite3.OperationalError as exc:
            self.failed.emit(request_id, "" if "interrupt" in str(exc) else str(exc))
            return
        except Exception as exc:  # report, never kill the worker thread
            log.exception("Query failed")
            self.failed.emit(request_id, str(exc))
            return
        self.finished.emit(request_id, result)

    @Slot()
    def close(self) -> None:
        if self._runner is not None:
            self._runner.close()
            self._runner = None


class QueryClient(QObject):
    """GUI-side handle; all methods must be called from the GUI thread."""

    error = Signal(str)
    _submit = Signal(int, int, object)

    def __init__(self, db_file: Path, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread = QThread()
        self._thread.setObjectName("query-worker")
        self._worker = _Worker(db_file)
        self._worker.moveToThread(self._thread)
        self._submit.connect(self._worker.run)
        self._thread.finished.connect(self._worker.close)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._ids = itertools.count(1)
        self._pending: dict[int, tuple[int, Callable[[Any], None]]] = {}
        self.generation = 0
        self._thread.start()

    @property
    def busy(self) -> bool:
        return bool(self._pending)

    def new_generation(self) -> None:
        self.generation += 1
        self._worker.latest_generation = self.generation
        self._worker.interrupt()

    def submit(self, func: QueryFunc, on_result: Callable[[Any], None]) -> int:
        request_id = next(self._ids)
        self._pending[request_id] = (self.generation, on_result)
        self._submit.emit(request_id, self.generation, func)
        return request_id

    def is_pending(self, request_id: int | None) -> bool:
        return request_id is not None and request_id in self._pending

    def shutdown(self) -> None:
        self.new_generation()
        self._thread.quit()
        if not self._thread.wait(5000):
            log.error("Query thread did not stop in time; waiting for a safe shutdown")
            self._thread.wait()
        self._pending.clear()

    @Slot(int, object)
    def _on_finished(self, request_id: int, result: Any) -> None:
        generation, callback = self._pending.pop(request_id, (None, None))
        if callback is not None and generation == self.generation:
            callback(result)

    @Slot(int, str)
    def _on_failed(self, request_id: int, message: str) -> None:
        generation, _callback = self._pending.pop(request_id, (None, None))
        if message and generation == self.generation:
            self.error.emit(message)
