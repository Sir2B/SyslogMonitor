"""Single database writer thread with batching, retries and retention."""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from syslog_monitor.events import SyslogEvent
from syslog_monitor.receiver import now_ms
from syslog_monitor.stats import Stats
from syslog_monitor.storage import StorageUsage

log = logging.getLogger(__name__)


class Store(Protocol):
    def insert(self, events: list[SyslogEvent]) -> int: ...
    def apply_retention(self, now_ms: int, retention_days: int, budget_bytes: int) -> int: ...
    def usage(self) -> StorageUsage: ...
    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class WriterTuning:
    batch_max: int = 500
    flush_interval_s: float = 0.5
    retry_delays_s: tuple[float, ...] = (0.5, 1.0, 2.0, 4.0, 8.0)
    maintenance_interval_s: float = 60.0
    usage_interval_s: float = 5.0


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    retention_days: int
    budget_bytes: int


class EventWriter:
    """Drains the event queue into the store.

    A batch that still fails after all retries is dropped and counted in
    ``dropped_write_error`` so losses are never silent.
    """

    def __init__(
        self,
        in_queue: queue.Queue,
        store: Store,
        stats: Stats,
        policy: RetentionPolicy,
        tuning: WriterTuning = WriterTuning(),
    ) -> None:
        self._queue = in_queue
        self._store = store
        self._stats = stats
        self._policy = policy
        self._tuning = tuning
        self._stop = threading.Event()
        self._maintenance_requested = threading.Event()
        self._maintenance_requested.set()  # run once at start
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="db-writer", daemon=True)
        self._thread.start()

    def set_policy(self, policy: RetentionPolicy) -> None:
        self._policy = policy
        self._maintenance_requested.set()

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait until every queued event has been written or dropped."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks:
            if time.monotonic() > deadline:
                return False
            time.sleep(0.01)
        return True

    def stop(self, timeout: float = 30.0) -> None:
        """Write remaining queued events, then close the store."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
            if self._thread.is_alive():
                log.error("Database writer did not stop in time")
                return
            self._thread = None
        self._store.close()

    def _run(self) -> None:
        next_maintenance = time.monotonic() + self._tuning.maintenance_interval_s
        next_usage = 0.0
        while True:
            batch = self._collect_batch()
            if batch:
                self._write(batch)
            elif self._stop.is_set() and self._queue.empty():
                break
            now = time.monotonic()
            if self._maintenance_requested.is_set() or now >= next_maintenance:
                self._maintenance_requested.clear()
                self._maintain()
                next_maintenance = now + self._tuning.maintenance_interval_s
                next_usage = 0.0
            if now >= next_usage:
                self._update_usage()
                next_usage = now + self._tuning.usage_interval_s

    def _collect_batch(self) -> list[SyslogEvent]:
        batch: list[SyslogEvent] = []
        deadline = time.monotonic() + self._tuning.flush_interval_s
        while len(batch) < self._tuning.batch_max:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or (self._stop.is_set() and self._queue.empty()):
                break
            try:
                batch.append(self._queue.get(timeout=min(remaining, 0.1)))
            except queue.Empty:
                if batch:
                    break
        return batch

    def _write(self, batch: list[SyslogEvent]) -> None:
        delays = self._tuning.retry_delays_s
        try:
            for attempt in range(len(delays) + 1):
                try:
                    self._store.insert(batch)
                except Exception as exc:  # sqlite3.Error, OSError, ...
                    self._stats.add("write_failures")
                    self._stats.set(writer_error=f"Write failed: {exc}")
                    log.warning("Could not write %d events (attempt %d): %s",
                                len(batch), attempt + 1, exc)
                    if attempt < len(delays):
                        time.sleep(delays[attempt])
                    continue
                self._stats.add("persisted", len(batch))
                self._stats.set(writer_error="")
                return
            self._stats.add("dropped_write_error", len(batch))
            log.error("Dropped %d events after repeated write failures", len(batch))
        finally:
            for _ in batch:
                self._queue.task_done()

    def _maintain(self) -> None:
        policy = self._policy
        try:
            deleted = self._store.apply_retention(now_ms(), policy.retention_days, policy.budget_bytes)
        except Exception:
            log.exception("Could not apply retention/storage budget")
            return
        if deleted:
            self._stats.add("retention_deleted", deleted)

    def _update_usage(self) -> None:
        try:
            usage = self._store.usage()
        except Exception:
            log.exception("Could not determine storage usage")
            return
        self._stats.set(
            storage_bytes=usage.file_bytes,
            storage_budget_exceeded=usage.file_bytes > self._policy.budget_bytes,
        )
