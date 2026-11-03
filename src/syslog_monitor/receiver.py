"""UDP syslog listener running in its own thread."""

from __future__ import annotations

import logging
import queue
import socket
import threading
import time

from syslog_monitor.parser import parse_datagram
from syslog_monitor.stats import Stats

log = logging.getLogger(__name__)

MAX_DATAGRAM = 65535  # larger than any IPv4 UDP payload, so nothing is truncated
RECV_BUFFER_BYTES = 4 * 1024 * 1024
POLL_TIMEOUT_S = 0.25


def now_ms() -> int:
    return time.time_ns() // 1_000_000


class UdpReceiver:
    """Receives datagrams, parses them and hands events to a bounded queue.

    If the queue is full the event is dropped and counted; the receiver never
    blocks, so the OS socket buffer keeps draining.
    """

    def __init__(self, host: str, port: int, out_queue: queue.Queue, stats: Stats) -> None:
        self.host = host
        self.port = port
        self._queue = out_queue
        self._stats = stats
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def bound_port(self) -> int:
        """Actual port (useful when constructed with port 0)."""
        return self._sock.getsockname()[1] if self._sock else self.port

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Bind and start receiving. Raises ``OSError`` if binding fails."""
        if self.running:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECV_BUFFER_BYTES)
            except OSError:
                log.warning("Could not increase UDP receive buffer")
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((self.host, self.port))
            sock.settimeout(POLL_TIMEOUT_S)
        except OSError:
            sock.close()
            raise
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="udp-receiver", daemon=True)
        self._thread.start()
        log.info("UDP listener started on %s:%d", self.host, self.bound_port)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        if self._sock:
            self._sock.close()
            self._sock = None
            log.info("UDP listener stopped")

    def _run(self) -> None:
        assert self._sock is not None
        sock = self._sock
        while not self._stop.is_set():
            try:
                data, (ip, port) = sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except ConnectionResetError:
                # Windows reports ICMP "port unreachable" on UDP sockets; harmless here.
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    log.exception("UDP receive loop failed")
                    self._stats.set(listener_state="error", listener_error=str(exc))
                return
            self._handle(data, ip, port)

    def _handle(self, data: bytes, ip: str, port: int) -> None:
        self._stats.add("received")
        event = parse_datagram(data, ip, port, now_ms())
        if event.issues:
            self._stats.add("parse_issues")
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._stats.add("dropped_queue_full")
