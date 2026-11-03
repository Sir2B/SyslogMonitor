"""Capture pipeline: UDP receiver -> bounded queue -> database writer.

Independent of Qt so it can be tested and reused headless.
"""

from __future__ import annotations

import logging
import queue
from pathlib import Path

from syslog_monitor.config import Settings
from syslog_monitor.receiver import UdpReceiver
from syslog_monitor.stats import Stats, StatsSnapshot
from syslog_monitor.storage import EventStore
from syslog_monitor.writer import EventWriter, RetentionPolicy, WriterTuning

log = logging.getLogger(__name__)

DEFAULT_QUEUE_SIZE = 20_000


class CaptureService:
    def __init__(
        self,
        data_dir: Path,
        settings: Settings,
        *,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        tuning: WriterTuning = WriterTuning(),
    ) -> None:
        self.data_dir = data_dir
        self.settings = settings
        self.stats = Stats()
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._store = EventStore(data_dir)  # raises StorageError
        self._writer = EventWriter(self._queue, self._store, self.stats, self._policy(), tuning)
        self._receiver: UdpReceiver | None = None
        self._writer.start()

    @property
    def db_path(self) -> Path:
        return self._store.path

    @property
    def listening(self) -> bool:
        return self._receiver is not None and self._receiver.running

    @property
    def bound_port(self) -> int | None:
        return self._receiver.bound_port if self.listening else None

    def _policy(self) -> RetentionPolicy:
        return RetentionPolicy(self.settings.retention_days, self.settings.max_storage_bytes)

    def start_listener(self) -> bool:
        """Start receiving; on failure the error is recorded in the stats."""
        if self.listening:
            return True
        host, port = self.settings.bind_host, self.settings.port
        receiver = UdpReceiver(host, port, self._queue, self.stats)
        try:
            receiver.start()
        except OSError as exc:
            log.error("Could not open UDP %s:%d: %s", host, port, exc)
            self.stats.set(listener_state="error", listener_address=f"{host}:{port}",
                           listener_error=f"Port {port} is unavailable: {exc}")
            return False
        self._receiver = receiver
        self.stats.set(listener_state="running", listener_error="",
                       listener_address=f"{host}:{receiver.bound_port}")
        return True

    def stop_listener(self) -> None:
        if self._receiver:
            self._receiver.stop()
            self._receiver = None
        self.stats.set(listener_state="stopped")

    def apply_settings(self, settings: Settings) -> bool:
        """Apply new settings at runtime. ``data_dir`` changes need a restart.

        Returns False if the listener had to be restarted and failed.
        """
        listener_changed = (settings.bind_host, settings.port) != (
            self.settings.bind_host, self.settings.port)
        self.settings = settings
        self._writer.set_policy(self._policy())
        if listener_changed and (self.listening or self.stats.snapshot().listener_state == "error"):
            self.stop_listener()
            return self.start_listener()
        return True

    def flush(self, timeout: float = 10.0) -> bool:
        return self._writer.flush(timeout)

    def snapshot(self) -> StatsSnapshot:
        return self.stats.snapshot(queued=self._queue.qsize())

    def shutdown(self) -> None:
        """Stop receiving, write everything still queued, close the database."""
        self.stop_listener()
        self._writer.stop()
        log.info("Capture stopped: %s", self.snapshot())
