"""UDP, TCP and TLS syslog listeners feeding the same bounded queue."""

from __future__ import annotations

import logging
import queue
import selectors
import socket
import ssl
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
TLS_HANDSHAKE_TIMEOUT_S = 10.0
TLS_SHUTDOWN_TIMEOUT_S = 10.0


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
        self._last_framing: str | None = None

    @property
    def last_framing(self) -> str | None:
        """Framing of the most recently yielded message, for diagnostic evidence."""
        return self._last_framing

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

            self._last_framing = "octets" if self._mode == "octets" else "delimiter"
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
        self._last_framing = "eof"
        return message


@dataclass(slots=True)
class _TcpClient:
    sock: socket.socket
    address: tuple[str, int]
    framer: TcpFramer = field(default_factory=TcpFramer)
    events: int = selectors.EVENT_READ
    handshake_deadline: float | None = None
    shutdown_deadline: float | None = None


class _ClientClosed(Exception):
    """The client was already handled and must be closed without further logging."""


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
        log.info("%s listener started on %s:%d", self.protocol, self.host, self.bound_port)

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
                        self._expire_clients(selector, clients)
                finally:
                    for client in tuple(clients.values()):
                        if client.framer.pending:
                            self._stats.add("dropped_tcp_framing")
                            log.warning("Discarding unfinished %s message from %s:%d: listener closed",
                                        self.protocol, *client.address)
                        self._close_on_stop(selector, clients, client)
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
            log.warning("Could not accept %s client: %s", self.protocol, exc)
            return
        if len(clients) >= MAX_TCP_CLIENTS:
            self._stats.add("tcp_connections_rejected")
            log.warning("Rejecting %s client %s:%d: connection limit reached", self.protocol, *address)
            sock.close()
            return
        try:
            sock.setblocking(False)
            client = self._new_client(sock, address)
        except (OSError, ValueError) as exc:
            self._stats.add("tcp_connections_rejected")
            log.warning("Could not set up %s client %s:%d: %s", self.protocol, *address, exc)
            sock.close()
            return
        try:
            selector.register(client.sock, client.events, client)
            clients[client.sock] = client
        except (OSError, ValueError) as exc:
            self._stats.add("tcp_connections_rejected")
            log.warning("Could not register %s client %s:%d: %s", self.protocol, *address, exc)
            client.sock.close()

    def _new_client(self, sock: socket.socket, address: tuple[str, int]) -> _TcpClient:
        return _TcpClient(sock, address)

    def _receive(self, selector: selectors.BaseSelector, client: _TcpClient) -> bytes | None:
        """Read available bytes; ``None`` means nothing is available yet."""
        return client.sock.recv(TCP_READ_BYTES)

    def _expire_clients(self, selector: selectors.BaseSelector,
                        clients: dict[socket.socket, _TcpClient]) -> None:
        pass

    def _read_client(self, selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient],
                     client: _TcpClient) -> None:
        try:
            data = self._receive(selector, client)
        except BlockingIOError:
            return
        except _ClientClosed:
            self._close_client(selector, clients, client)
            return
        except OSError as exc:
            if client.framer.pending:
                self._stats.add("dropped_tcp_framing")
                log.warning("%s client %s:%d disconnected with an unfinished message: %s",
                            self.protocol, *client.address, exc)
            else:
                log.warning("%s client %s:%d disconnected: %s", self.protocol, *client.address, exc)
            self._close_client(selector, clients, client)
            return
        if data is None:
            return
        try:
            if data:
                for message in client.framer.feed(data):
                    self._handle(message, *client.address)
            else:
                message = client.framer.finish()
                if message is not None:
                    self._handle(message, *client.address)
                self._close_after_eof(selector, clients, client)
        except TcpFramingError as exc:
            self._stats.add("dropped_tcp_framing")
            log.warning("Discarding %s message from %s:%d: %s", self.protocol, *client.address, exc)
            if data:
                self._close_client(selector, clients, client)
            else:
                self._close_after_eof(selector, clients, client)

    def _close_after_eof(self, selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient],
                         client: _TcpClient) -> None:
        self._close_client(selector, clients, client)

    def _close_on_stop(self, selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient],
                       client: _TcpClient) -> None:
        self._close_client(selector, clients, client)

    @staticmethod
    def _close_client(selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient],
                      client: _TcpClient) -> None:
        selector.unregister(client.sock)
        del clients[client.sock]
        client.sock.close()


class TlsConfigError(ValueError):
    """The TLS certificate, private key or CA file cannot be used."""


def _no_key_password() -> str:
    raise TlsConfigError("encrypted private keys are not supported")


def create_tls_context(cert_file: str, key_file: str = "", ca_file: str = "") -> ssl.SSLContext:
    """Build a TLS 1.2+ server context; with ``ca_file`` clients must present a certificate."""
    if not cert_file:
        raise TlsConfigError("no TLS certificate file is configured")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(cert_file, key_file or None, password=_no_key_password)
    except TlsConfigError as exc:
        raise TlsConfigError(f"Could not load TLS private key: {exc}") from exc
    except (OSError, ValueError) as exc:
        raise TlsConfigError(f"Could not load TLS certificate or private key: {exc}") from exc
    if ca_file:
        try:
            context.load_verify_locations(cafile=ca_file)
        except (OSError, ValueError) as exc:
            raise TlsConfigError(f"Could not load TLS client CA file: {exc}") from exc
        context.verify_mode = ssl.CERT_REQUIRED
    return context


class TlsReceiver(TcpReceiver):
    """Receive RFC 5425 syslog over TLS; framing is shared with :class:`TcpReceiver`."""

    protocol = "TLS"

    def __init__(self, host: str, port: int, out_queue: queue.Queue, stats: Stats,
                 context: ssl.SSLContext) -> None:
        super().__init__(host, port, out_queue, stats)
        self._context = context

    def _new_client(self, sock: socket.socket, address: tuple[str, int]) -> _TcpClient:
        tls_sock = self._context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False,
                                             suppress_ragged_eofs=False)
        return _TcpClient(tls_sock, address, handshake_deadline=time.monotonic() + TLS_HANDSHAKE_TIMEOUT_S)

    @staticmethod
    def _watch(selector: selectors.BaseSelector, client: _TcpClient, events: int) -> None:
        if client.events != events:
            selector.modify(client.sock, events, client)
            client.events = events

    def _read_client(self, selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient],
                     client: _TcpClient) -> None:
        if client.shutdown_deadline is not None:
            self._close_after_eof(selector, clients, client)
        else:
            super()._read_client(selector, clients, client)

    def _receive(self, selector: selectors.BaseSelector, client: _TcpClient) -> bytes | None:
        sock = client.sock
        assert isinstance(sock, ssl.SSLSocket)
        try:
            if client.handshake_deadline is not None:
                try:
                    sock.do_handshake()
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    raise
                except OSError as exc:
                    self._stats.add("tls_handshake_failures")
                    log.warning("TLS handshake with %s:%d failed: %s", *client.address, exc)
                    raise _ClientClosed from exc
                client.handshake_deadline = None
                log.info("TLS client %s:%d connected (%s)", *client.address, sock.version())
            data = sock.recv(TCP_READ_BYTES)
            # Decrypted bytes of the current record are not visible to the selector.
            while data and sock.pending():
                more = sock.recv(TCP_READ_BYTES)
                if not more:
                    break
                data += more
        except ssl.SSLWantReadError:
            self._watch(selector, client, selectors.EVENT_READ)
            return None
        except ssl.SSLWantWriteError:
            self._watch(selector, client, selectors.EVENT_WRITE)
            return None
        self._watch(selector, client, selectors.EVENT_READ)
        return data

    def _close_after_eof(self, selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient],
                         client: _TcpClient) -> None:
        sock = client.sock
        assert isinstance(sock, ssl.SSLSocket)
        if client.shutdown_deadline is None:
            client.shutdown_deadline = time.monotonic() + TLS_SHUTDOWN_TIMEOUT_S
        try:
            sock.unwrap()
        except ssl.SSLWantReadError:
            self._watch(selector, client, selectors.EVENT_READ)
            return
        except ssl.SSLWantWriteError:
            self._watch(selector, client, selectors.EVENT_WRITE)
            return
        except OSError as exc:
            log.warning("TLS shutdown with %s:%d failed: %s", *client.address, exc)
        self._close_client(selector, clients, client)

    def _close_on_stop(self, selector: selectors.BaseSelector, clients: dict[socket.socket, _TcpClient],
                       client: _TcpClient) -> None:
        sock = client.sock
        assert isinstance(sock, ssl.SSLSocket)
        if client.handshake_deadline is None:
            try:
                sock.unwrap()
            except ssl.SSLWantReadError:
                pass  # The close notification was sent; the peer has not replied yet.
            except OSError as exc:
                log.warning("Could not send TLS close notification to %s:%d: %s", *client.address, exc)
        self._close_client(selector, clients, client)

    def _expire_clients(self, selector: selectors.BaseSelector,
                        clients: dict[socket.socket, _TcpClient]) -> None:
        now = time.monotonic()
        for client in tuple(clients.values()):
            if client.handshake_deadline is not None and now >= client.handshake_deadline:
                self._stats.add("tls_handshake_failures")
                log.warning("TLS handshake with %s:%d timed out", *client.address)
                self._close_client(selector, clients, client)
            elif client.shutdown_deadline is not None and now >= client.shutdown_deadline:
                log.warning("TLS shutdown with %s:%d timed out", *client.address)
                self._close_client(selector, clients, client)
