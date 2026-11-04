"""UDP and TCP syslog listeners feeding the same bounded queue."""

from __future__ import annotations

import logging
import queue
import selectors
import socket
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field

from syslog_monitor.parser import parse_datagram
from syslog_monitor.stats import Stats

log = logging.getLogger(__name__)

MAX_DATAGRAM = 65535  # larger than any IPv4 UDP payload, so nothing is truncated
RECV_BUFFER_BYTES = 4 * 1024 * 1024
POLL_TIMEOUT_S = 0.25
MAX_TCP_MESSAGE_BYTES = 1024 * 1024
MAX_TCP_CLIENTS = 128
TCP_READ_BYTES = 64 * 1024


def now_ms() -> int:
    return time.time_ns() // 1_000_000


class _Receiver(ABC):
    protocol: str

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

    @abstractmethod
    def _run(self) -> None:
        ...

    def _start_thread(self, sock: socket.socket) -> None:
        self._sock = sock
        self._stop.clear()
        try:
            self._thread = threading.Thread(target=self._run, name=f"{self.protocol.lower()}-receiver",
                                            daemon=True)
            self._thread.start()
        except (OSError, RuntimeError):
            self._thread = None
            self._sock = None
            sock.close()
            raise

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                error = f"{self.protocol} receiver did not stop"
                log.error(error)
                self._stats.set(listener_state="error", listener_error=error)
                raise RuntimeError(error)
            self._thread = None
        if self._sock:
            self._sock.close()
            self._sock = None
            log.info("%s listener stopped", self.protocol)

    def _handle(self, data: bytes, ip: str, port: int) -> None:
        self._stats.add("received")
        event = parse_datagram(data, ip, port, now_ms())
        if event.issues:
            self._stats.add("parse_issues")
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._stats.add("dropped_queue_full")

    def _record_failure(self, exc: OSError | ValueError) -> None:
        if not self._stop.is_set():
            log.exception("%s receive loop failed", self.protocol)
            self._stats.set(listener_state="error",
                            listener_error=f"{self.protocol} receive loop failed: {exc}")


class UdpReceiver(_Receiver):
    """Receive datagrams without blocking when the event queue is full."""

    protocol = "UDP"

    def start(self) -> None:
        """Bind and start receiving. Raises ``OSError`` if binding fails."""
        if self.running:
            return
        if self._sock is not None:
            self.stop()
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
        self._start_thread(sock)
        log.info("UDP listener started on %s:%d", self.host, self.bound_port)

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
                self._record_failure(exc)
                return
            self._handle(data, ip, port)


class TcpFramingError(ValueError):
    """A TCP message is too large or its octet-counted frame is incomplete."""


class TcpFramer:
    """Decode RFC 6587 octet counts and LF/NUL-delimited messages incrementally."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._mode = "detect"
        self._scan_from = 0
        self._expected = 0

    @property
    def pending(self) -> bool:
        return bool(self._buffer) or self._mode == "octets"

    def feed(self, data: bytes) -> Iterator[bytes]:
        self._buffer.extend(data)
        while self._buffer:
            if self._mode == "detect":
                if 49 <= self._buffer[0] <= 57:
                    while (self._scan_from < len(self._buffer)
                           and 48 <= self._buffer[self._scan_from] <= 57):
                        self._scan_from += 1
                    if self._scan_from == len(self._buffer):
                        if len(self._buffer) > MAX_TCP_MESSAGE_BYTES:
                            raise TcpFramingError("message exceeds the TCP size limit")
                        return
                    if self._buffer[self._scan_from] == 32:
                        if self._scan_from > len(str(MAX_TCP_MESSAGE_BYTES)):
                            raise TcpFramingError("octet count exceeds the TCP size limit")
                        self._expected = int(self._buffer[:self._scan_from])
                        if self._expected > MAX_TCP_MESSAGE_BYTES:
                            raise TcpFramingError("octet count exceeds the TCP size limit")
                        del self._buffer[:self._scan_from + 1]
                        self._mode = "octets"
                        self._scan_from = 0
                    else:
                        self._mode = "line"
                        self._scan_from = 0
                else:
                    self._mode = "line"
                    self._scan_from = 0

            if self._mode == "octets":
                if len(self._buffer) < self._expected:
                    return
                message = bytes(self._buffer[:self._expected])
                del self._buffer[:self._expected]
            else:
                lf = self._buffer.find(b"\n", self._scan_from)
                nul = self._buffer.find(b"\x00", self._scan_from)
                ends = [pos for pos in (lf, nul) if pos >= 0]
                if not ends:
                    self._scan_from = len(self._buffer)
                    extra_cr = (len(self._buffer) == MAX_TCP_MESSAGE_BYTES + 1
                                and self._buffer[-1] == 13)
                    if len(self._buffer) > MAX_TCP_MESSAGE_BYTES and not extra_cr:
                        raise TcpFramingError("message exceeds the TCP size limit")
                    return
                end = min(ends)
                message_end = end - 1 if self._buffer[end] == 10 and end and self._buffer[end - 1] == 13 else end
                if message_end > MAX_TCP_MESSAGE_BYTES:
                    raise TcpFramingError("message exceeds the TCP size limit")
                message = bytes(self._buffer[:message_end])
                del self._buffer[:end + 1]

            self._mode = "detect"
            self._scan_from = 0
            self._expected = 0
            yield message

    def finish(self) -> bytes | None:
        if self._mode == "octets":
            raise TcpFramingError("connection closed before the octet-counted message was complete")
        if not self._buffer:
            return None
        if len(self._buffer) > MAX_TCP_MESSAGE_BYTES:
            raise TcpFramingError("message exceeds the TCP size limit")
        message = bytes(self._buffer)
        self._buffer.clear()
        return message


@dataclass(slots=True)
class _TcpClient:
    sock: socket.socket
    address: tuple[str, int]
    framer: TcpFramer = field(default_factory=TcpFramer)


class TcpReceiver(_Receiver):
    """Receive framed messages from multiple TCP clients on one selector thread."""

    protocol = "TCP"

    def start(self) -> None:
        if self.running:
            return
        if self._sock is not None:
            self.stop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(MAX_TCP_CLIENTS)
            sock.setblocking(False)
        except OSError:
            sock.close()
            raise
        self._start_thread(sock)
        log.info("TCP listener started on %s:%d", self.host, self.bound_port)

    def _run(self) -> None:
        assert self._sock is not None
        clients: dict[socket.socket, _TcpClient] = {}
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self._sock, selectors.EVENT_READ)
                try:
                    while not self._stop.is_set():
                        for key, _ in selector.select(POLL_TIMEOUT_S):
                            if self._stop.is_set():
                                break
                            if key.data is None:
                                self._accept(selector, clients)
                            else:
                                self._read_client(selector, clients, key.data)
                finally:
                    for client in tuple(clients.values()):
                        if client.framer.pending:
                            self._stats.add("dropped_tcp_framing")
                            log.warning("Discarding unfinished TCP message from %s:%d: listener closed",
                                        *client.address)
                        self._close_client(selector, clients, client)
        except (OSError, ValueError) as exc:
            self._record_failure(exc)

    def _accept(self, selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient]) -> None:
        assert self._sock is not None
        try:
            sock, address = self._sock.accept()
        except BlockingIOError:
            return
        except (ConnectionAbortedError, ConnectionResetError) as exc:
            self._stats.add("tcp_connections_rejected")
            log.warning("Could not accept TCP client: %s", exc)
            return
        if len(clients) >= MAX_TCP_CLIENTS:
            self._stats.add("tcp_connections_rejected")
            log.warning("Rejecting TCP client %s:%d: connection limit reached", *address)
            sock.close()
            return
        try:
            sock.setblocking(False)
            client = _TcpClient(sock, address)
            selector.register(sock, selectors.EVENT_READ, client)
            clients[sock] = client
        except (OSError, ValueError) as exc:
            self._stats.add("tcp_connections_rejected")
            log.warning("Could not register TCP client %s:%d: %s", *address, exc)
            sock.close()

    def _read_client(self, selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient],
                     client: _TcpClient) -> None:
        try:
            data = client.sock.recv(TCP_READ_BYTES)
        except BlockingIOError:
            return
        except OSError as exc:
            if client.framer.pending:
                self._stats.add("dropped_tcp_framing")
                log.warning("TCP client %s:%d disconnected with an unfinished message: %s",
                            *client.address, exc)
            else:
                log.warning("TCP client %s:%d disconnected: %s", *client.address, exc)
            self._close_client(selector, clients, client)
            return
        try:
            if data:
                for message in client.framer.feed(data):
                    self._handle(message, *client.address)
            else:
                message = client.framer.finish()
                if message is not None:
                    self._handle(message, *client.address)
                self._close_client(selector, clients, client)
        except TcpFramingError as exc:
            self._stats.add("dropped_tcp_framing")
            log.warning("Discarding TCP message from %s:%d: %s", *client.address, exc)
            self._close_client(selector, clients, client)

    @staticmethod
    def _close_client(selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient],
                      client: _TcpClient) -> None:
        selector.unregister(client.sock)
        del clients[client.sock]
        client.sock.close()
