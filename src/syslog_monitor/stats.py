"""Thread-safe runtime counters shared by receiver, writer and GUI."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class StatsSnapshot:
    received: int = 0
    parse_issues: int = 0
    dropped_queue_full: int = 0
    persisted: int = 0
    write_failures: int = 0
    dropped_write_error: int = 0
    retention_deleted: int = 0
    queued: int = 0
    listener_state: str = "stopped"  # stopped | running | error
    listener_address: str = ""
    listener_error: str = ""
    writer_error: str = ""
    storage_bytes: int = 0
    storage_budget_exceeded: bool = False
    dropped_tcp_framing: int = 0
    tcp_connections_rejected: int = 0
    tls_handshake_failures: int = 0
    listener_endpoints: tuple[tuple[str, str, int], ...] = ()

    @property
    def listener_display_address(self) -> str:
        if self.listener_endpoints:
            return ", ".join(f"{protocol} {host}:{port}" for protocol, host, port in self.listener_endpoints)
        return self.listener_address


@dataclass(frozen=True, slots=True)
class CounterRates:
    received: float = 0.0
    persisted: float = 0.0
    dropped: float = 0.0


class RateTracker:
    """Calculate non-negative per-second rates from successive counter snapshots."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._previous: tuple[float, int, int, int] | None = None

    def update(self, snapshot: StatsSnapshot) -> CounterRates:
        now = self._clock()
        dropped = snapshot.dropped_queue_full + snapshot.dropped_write_error + snapshot.dropped_tcp_framing
        current = (now, snapshot.received, snapshot.persisted, dropped)
        previous, self._previous = self._previous, current
        if previous is None:
            return CounterRates()
        elapsed = now - previous[0]
        if elapsed <= 0:
            return CounterRates()
        return CounterRates(
            received=max(0, snapshot.received - previous[1]) / elapsed,
            persisted=max(0, snapshot.persisted - previous[2]) / elapsed,
            dropped=max(0, dropped - previous[3]) / elapsed,
        )


class Stats:
    """Mutable counters guarded by a lock; read via :meth:`snapshot`."""

    _COUNTERS = (
        "received",
        "parse_issues",
        "dropped_queue_full",
        "dropped_tcp_framing",
        "tcp_connections_rejected",
        "tls_handshake_failures",
        "persisted",
        "write_failures",
        "dropped_write_error",
        "retention_deleted",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, object] = {name: 0 for name in self._COUNTERS}
        self._values.update(
            listener_state="stopped",
            listener_address="",
            listener_error="",
            writer_error="",
            storage_bytes=0,
            storage_budget_exceeded=False,
        )

    def add(self, name: str, amount: int = 1) -> None:
        if name not in self._COUNTERS:
            raise KeyError(name)
        with self._lock:
            self._values[name] += amount  # type: ignore[operator]

    def set(self, **values: object) -> None:
        with self._lock:
            for key, value in values.items():
                if key not in self._values:
                    raise KeyError(key)
                self._values[key] = value

    def snapshot(self, queued: int = 0) -> StatsSnapshot:
        with self._lock:
            return StatsSnapshot(queued=queued, **self._values)  # type: ignore[arg-type]
