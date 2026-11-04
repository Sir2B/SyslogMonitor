"""Capture pipeline: UDP/TCP/TLS receivers -> bounded queue -> database writer.

Independent of Qt so it can be tested and reused headless.
"""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import replace
from pathlib import Path

from syslog_monitor.config import Settings, Transport
from syslog_monitor.receiver import TcpReceiver, TlsConfigError, TlsReceiver, UdpReceiver, create_tls_context
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
        self._receivers: dict[Transport, UdpReceiver | TcpReceiver] = {}
        self._receiver_configs: dict[Transport, tuple] = {}
        self._listener_lock = threading.RLock()
        self._writer.start()

    @property
    def db_path(self) -> Path:
        return self._store.path

    @property
    def listening(self) -> bool:
        with self._listener_lock:
            return any(receiver.running for receiver in self._receivers.values())

    @property
    def bound_port(self) -> int | None:
        ports = self.bound_ports
        return ports.get("UDP", ports.get("TCP", ports.get("TLS")))

    @property
    def bound_ports(self) -> dict[Transport, int]:
        with self._listener_lock:
            return {protocol: receiver.bound_port for protocol, receiver in self._receivers.items()
                    if receiver.running}

    def _policy(self) -> RetentionPolicy:
        return RetentionPolicy(self.settings.retention_days, self.settings.max_storage_bytes)

    def start_listener(self) -> bool:
        """Start enabled listeners; a failure does not stop the other transport."""
        with self._listener_lock:
            return self._sync_listeners()

    def _receiver_config(self, protocol: Transport, port: int) -> tuple:
        tls = self.settings.tls_files if protocol == "TLS" else ()
        return self.settings.bind_host, port, tls

    def _sync_listeners(self) -> bool:
        host = self.settings.bind_host
        desired = dict(self.settings.listener_endpoints)
        for protocol, receiver in tuple(self._receivers.items()):
            if (protocol not in desired or not receiver.running
                    or self._receiver_configs.get(protocol) != self._receiver_config(protocol, desired[protocol])):
                receiver.stop()
                del self._receivers[protocol]
                self._receiver_configs.pop(protocol, None)

        errors: list[str] = []
        if not desired:
            errors.append("Enable at least one UDP, TCP or TLS listener in Settings.")
        for protocol, port in desired.items():
            if protocol in self._receivers:
                continue
            receiver: UdpReceiver | TcpReceiver
            if protocol == "TLS":
                try:
                    context = create_tls_context(*self.settings.tls_files)
                except TlsConfigError as exc:
                    log.error("Could not start TLS listener: %s", exc)
                    errors.append(f"TLS listener: {exc}")
                    continue
                receiver = TlsReceiver(host, port, self._queue, self.stats, context)
            else:
                receiver_type = UdpReceiver if protocol == "UDP" else TcpReceiver
                receiver = receiver_type(host, port, self._queue, self.stats)
            try:
                receiver.start()
            except OSError as exc:
                log.error("Could not open %s %s:%d: %s", protocol, host, port, exc)
                errors.append(f"{protocol} port {port} is unavailable: {exc}")
                continue
            except RuntimeError as exc:
                log.error("Could not start %s listener: %s", protocol, exc)
                errors.append(f"Could not start {protocol} listener: {exc}")
                continue
            self._receivers[protocol] = receiver
            self._receiver_configs[protocol] = self._receiver_config(protocol, port)

        self.stats.set(listener_state="error" if errors else "running",
                       listener_error="; ".join(errors))
        return not errors

    def stop_listener(self) -> None:
        with self._listener_lock:
            for receiver in self._receivers.values():
                receiver.stop()
            self._receivers.clear()
            self._receiver_configs.clear()
            self.stats.set(listener_state="stopped", listener_address="", listener_error="")

    def apply_settings(self, settings: Settings) -> bool:
        """Apply new settings at runtime. ``data_dir`` changes need a restart.

        Returns False if the listener had to be restarted and failed.
        """
        with self._listener_lock:
            listener_changed = (settings.bind_host, settings.listener_endpoints, settings.tls_files) != (
                self.settings.bind_host, self.settings.listener_endpoints, self.settings.tls_files)
            was_active = bool(self._receivers) or self.stats.snapshot().listener_state == "error"
            self.settings = settings
            self._writer.set_policy(self._policy())
            if listener_changed and was_active:
                return self._sync_listeners()
            return True

    def flush(self, timeout: float = 10.0) -> bool:
        return self._writer.flush(timeout)

    def snapshot(self) -> StatsSnapshot:
        with self._listener_lock:
            snap = self.stats.snapshot(queued=self._queue.qsize())
            endpoints = tuple(
                (protocol, receiver.host, receiver.bound_port)
                for protocol, receiver in self._receivers.items() if receiver.running)
            stopped = [protocol for protocol, receiver in self._receivers.items() if not receiver.running]
            if stopped and snap.listener_state == "running":
                snap = replace(snap, listener_state="error",
                               listener_error=f"{', '.join(stopped)} listener stopped unexpectedly")
            primary = next((endpoint for endpoint in endpoints if endpoint[0] == "UDP"),
                           endpoints[0] if endpoints else None)
            if primary is not None:
                address = f"{primary[1]}:{primary[2]}"
            elif snap.listener_state == "error" and self.settings.listener_endpoints:
                address = f"{self.settings.bind_host}:{self.settings.listener_endpoints[0][1]}"
            else:
                address = ""
            return replace(snap, listener_address=address, listener_endpoints=endpoints)

    def shutdown(self) -> None:
        """Stop receiving, write everything still queued, close the database."""
        self.stop_listener()
        self._writer.stop()
        log.info("Capture stopped: %s", self.snapshot())
