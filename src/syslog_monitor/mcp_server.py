"""Embedded MCP server (Streamable HTTP on 127.0.0.1) exposing :class:`LogTools`.

Runs inside the GUI process on its own thread/event loop, so AI assistants
such as GitHub Copilot can query the stored syslog messages whenever the
Syslog Monitor app is running. Strictly read-only and bound to loopback only.
"""

import asyncio
import logging
import socket
import threading
from typing import Annotated, Any

from syslog_monitor import APP_DISPLAY_NAME, __version__
from syslog_monitor.config import MCP_HOST, Settings
from syslog_monitor.mcp_tools import DEFAULT_LIMIT, MAX_LIMIT, LogTools

# No ``from __future__ import annotations``: the tool signatures inside build_server()
# use local Annotated aliases that pydantic must see as real objects.

log = logging.getLogger(__name__)

MCP_PATH = "/mcp"
SERVER_NAME = "syslog-monitor"
_START_TIMEOUT_S = 10.0

INSTRUCTIONS = f"""\
Read-only access to syslog messages captured by the local {APP_DISPLAY_NAME} app (UDP/TCP/TLS
syslog receivers with long-term storage). Typical workflow for an embedded device that was
restarted: call logs_since_boot (optionally with 'device'), then get_context /
search_logs for details. Use summarize or error_timeline for an overview of longer
periods and wait_for_message to wait for a device to come back after a reboot.
Times are returned as local ISO 8601; time parameters accept ISO 8601 or relative
values like '30m', '2h', '1d'. 'device' matches a full sender IP exactly, otherwise
host name or partial address as substring.
Severity names: emergency, alert, critical, error, warning, notice, info, debug.
Results are bounded; follow 'next_after' to page through long result sets."""


def client_config(port: int) -> dict[str, Any]:
    """VS Code ``.vscode/mcp.json`` / user ``mcp.json`` snippet for this server."""
    return {"servers": {SERVER_NAME: {"type": "http", "url": server_url(port)}}}


def server_url(port: int) -> str:
    return f"http://{MCP_HOST}:{port}{MCP_PATH}"


def _call(fn, *args) -> dict[str, Any]:
    """Report invalid arguments to the AI (other exceptions stay server-side)."""
    from mcp.server.mcpserver.exceptions import ToolError
    try:
        return fn(*args)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc


def build_server(tools: LogTools):
    """Create the MCP server object with all tools registered (imports the SDK lazily)."""
    from mcp.server.mcpserver import MCPServer
    from mcp.types import ToolAnnotations
    from pydantic import Field

    Device = Annotated[str | None, Field(
        description="Sender IP (exact) or host name / partial address (substring); empty = all")]
    Since = Annotated[str | None, Field(description="Start time: ISO 8601 or relative like '30m', '2h', '1d'")]
    Until = Annotated[str | None, Field(description="End time (exclusive): ISO 8601 or relative; empty = now")]
    MinSeverity = Annotated[str | None, Field(
        description="Only this severity or worse, e.g. 'warning' or 'error'; empty = all")]
    Limit = Annotated[int, Field(ge=1, le=MAX_LIMIT, description="Maximum number of messages")]

    server = MCPServer(name=SERVER_NAME, title=APP_DISPLAY_NAME, version=__version__,
                       instructions=INSTRUCTIONS, log_level="WARNING")
    read_only = ToolAnnotations(read_only_hint=True, open_world_hint=False)

    @server.tool(annotations=read_only)
    def status() -> dict[str, Any]:
        """Receiver state, stored message count and time span, boot marker and devices active in the last 24 h."""
        return _call(tools.status)

    @server.tool(annotations=read_only)
    def list_devices(since: Since = "7d",
                     limit: Annotated[int, Field(ge=1, le=500)] = 50) -> dict[str, Any]:
        """Devices (sender IPs) that sent messages since the given time, most recently active first."""
        return _call(tools.list_devices, since or "7d", limit)

    @server.tool(annotations=read_only)
    def logs_since_boot(
        device: Device = None,
        boot: Annotated[int, Field(ge=0, description="0 = latest boot, 1 = the boot before, ...")] = 0,
        min_severity: MinSeverity = None,
        limit: Limit = DEFAULT_LIMIT,
        marker: Annotated[str | None, Field(
            description="Override the configured boot marker text(s), ';'-separated")] = None,
    ) -> dict[str, Any]:
        """Messages of one device from its last (or an earlier) restart onwards, oldest first.

        A restart is detected by the configured boot marker text. Without 'device' the device
        with the most recent restart is used. Includes counts per severity for the whole boot.
        If 'truncated' is true, continue with get_logs(device=<ip>, after=<next_after>).
        """
        return _call(tools.logs_since_boot, device, boot, min_severity, limit, marker)

    @server.tool(annotations=read_only)
    def get_logs(device: Device = None, since: Since = None, until: Until = None,
                 min_severity: MinSeverity = None, limit: Limit = DEFAULT_LIMIT,
                 after: Annotated[str | None, Field(
                     description="Paging cursor 'next_after' from a previous result")] = None,
                 ) -> dict[str, Any]:
        """Messages in a time range, oldest first, with paging via 'next_after'."""
        return _call(tools.get_logs, device, since, until, min_severity, limit, after)

    @server.tool(annotations=read_only)
    def search_logs(
        query: Annotated[str, Field(description="Text to search for")],
        device: Device = None, since: Since = None, until: Until = None,
        min_severity: MinSeverity = None,
        mode: Annotated[str, Field(description="'substring' (literal text) or 'words' (all words, prefix match)")
                        ] = "substring",
        limit: Annotated[int, Field(ge=1, le=MAX_LIMIT)] = 100,
    ) -> dict[str, Any]:
        """Search message text, host and app name. Returns the newest matches (listed oldest first) and the total count."""
        return _call(tools.search_logs, query, device, since, until, min_severity, mode, limit)

    @server.tool(annotations=read_only)
    def get_context(event_id: Annotated[int, Field(description="Message id from another result")],
                    before: Annotated[int, Field(ge=0, le=200)] = 20,
                    after: Annotated[int, Field(ge=0, le=200)] = 20,
                    same_device: bool = True) -> dict[str, Any]:
        """Messages around one message (default: same device only), chronological, anchor included."""
        return _call(tools.get_context, event_id, before, after, same_device)

    @server.tool(annotations=read_only)
    def summarize(device: Device = None, since: Since = "24h", until: Until = None) -> dict[str, Any]:
        """Overview of a period: counts per severity, restarts, most frequent errors/warnings (grouped ignoring numbers)."""
        return _call(tools.summarize, device, since or "24h", until)

    @server.tool(annotations=read_only)
    def error_timeline(device: Device = None, since: Since = "24h", until: Until = None,
                       buckets: Annotated[int, Field(ge=1, le=200)] = 24) -> dict[str, Any]:
        """Errors, warnings, totals and restarts per time bucket, to see when problems started."""
        return _call(tools.error_timeline, device, since or "24h", until, buckets)

    @server.tool(annotations=read_only)
    def wait_for_message(
        text: Annotated[str, Field(description="Text(s) to wait for, ';'-separated (case-insensitive)")],
        device: Device = None,
        timeout_s: Annotated[int, Field(ge=1, le=600)] = 120,
    ) -> dict[str, Any]:
        """Wait until a NEW message containing the text arrives, e.g. the boot marker after triggering a reboot."""
        return _call(tools.wait_for_message, text, device, timeout_s)

    return server


class McpServerThread:
    """Runs the MCP HTTP server on a daemon thread; ``start``/``stop`` are idempotent."""

    def __init__(self, tools: LogTools, port: int, host: str = MCP_HOST) -> None:
        logging.getLogger("mcp").setLevel(logging.WARNING)  # per-request INFO noise
        self.tools = tools
        self.host = host
        self.port = port
        self.error = ""
        self._server = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self.error

    @property
    def url(self) -> str:
        return server_url(self.port)

    def start(self) -> bool:
        """Bind and start serving; on failure ``error`` describes the problem."""
        if self.running:
            return True
        self.error = ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((self.host, self.port))
            sock.listen(64)
        except OSError as exc:
            sock.close()
            self.error = f"Port {self.port} is unavailable: {exc}"
            log.error("MCP-Server: %s", self.error)
            return False
        self.port = sock.getsockname()[1]
        try:
            import uvicorn
            app = build_server(self.tools).streamable_http_app(
                streamable_http_path=MCP_PATH, stateless_http=True, json_response=True, host=self.host)
            config = uvicorn.Config(app, log_config=None, log_level="warning", access_log=False,
                                    loop="asyncio", http="h11", ws="none", lifespan="on",
                                    timeout_graceful_shutdown=2)
            server = uvicorn.Server(config)
        except Exception as exc:  # missing/broken dependency must not break the viewer
            sock.close()
            self.error = f"MCP server is unavailable: {exc}"
            log.exception("Could not create MCP server")
            return False
        self.tools.stopping.clear()
        self._server = server
        self._thread = threading.Thread(target=self._serve, args=(server, sock), name="mcp-server",
                                        daemon=True)
        self._thread.start()
        if not self._wait_started(server):
            self.stop()
            self.error = self.error or "MCP server did not start."
            return False
        log.info("MCP server is running at %s", self.url)
        return True

    def _wait_started(self, server) -> bool:
        pause = threading.Event()
        for _ in range(int(_START_TIMEOUT_S / 0.05)):
            if server.started:
                return True
            if self._thread is None or not self._thread.is_alive():
                return False
            pause.wait(0.05)
        return server.started

    def _serve(self, server, sock: socket.socket) -> None:
        try:
            asyncio.run(server.serve(sockets=[sock]))
        except BaseException as exc:  # noqa: BLE001 - uvicorn may raise SystemExit
            self.error = f"MCP server was interrupted: {exc}"
            log.exception("MCP server was interrupted")
        finally:
            sock.close()

    def stop(self, timeout: float = 5.0) -> None:
        self.tools.stopping.set()
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout)
            if self._thread.is_alive():
                log.warning("MCP server thread did not stop in time")
        self._server = None
        self._thread = None


class McpService:
    """Keeps the MCP server in line with the settings (enabled, port, boot marker).

    Thread-safe: the first start runs in the background (importing the MCP SDK
    takes a few seconds), later changes come from the GUI thread.
    """

    def __init__(self, tools: LogTools) -> None:
        self.tools = tools
        self.enabled = False
        self.starting = False
        self.error = ""
        self.port: int | None = None
        self._requested_port: int | None = None
        self._thread: McpServerThread | None = None
        self._lock = threading.RLock()

    @property
    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.running

    @property
    def url(self) -> str | None:
        port = self.port
        return server_url(port) if self.running and port else None

    def apply(self, settings: Settings) -> bool:
        """Start, stop or restart as needed; returns False if the server should run but cannot."""
        with self._lock:
            self.tools.boot_marker = settings.boot_marker
            self.enabled = settings.mcp_enabled
            if not self.enabled:
                self._stop()
                return True
            if self.running and self._requested_port == settings.mcp_port:
                return True
            self._stop()
            thread = McpServerThread(self.tools, settings.mcp_port)
            self._requested_port = settings.mcp_port
            ok = thread.start()
            self._thread = thread if ok else None
            self.port = thread.port if ok else None
            self.error = thread.error
            return ok

    def apply_async(self, settings: Settings) -> threading.Thread:
        """Like :meth:`apply` without blocking the caller; watch ``starting``/``running``."""
        self.enabled = settings.mcp_enabled
        self.starting = settings.mcp_enabled

        def run() -> None:
            try:
                if not self.apply(settings):
                    log.warning("MCP server did not start: %s", self.error)
            finally:
                self.starting = False

        worker = threading.Thread(target=run, name="mcp-start", daemon=True)
        worker.start()
        return worker

    def stop(self) -> None:
        with self._lock:
            self._stop()

    def _stop(self) -> None:
        if self._thread is not None:
            self._thread.stop()
        self._thread = None
        self.port = None
        self.error = ""