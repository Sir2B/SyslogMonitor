"""End-to-end tests of the embedded MCP HTTP server."""

import json
import socket
import urllib.error
import urllib.request

import pytest
from conftest import make_event

from syslog_monitor.config import Settings
from syslog_monitor.mcp_server import McpServerThread, McpService, client_config, server_url
from syslog_monitor.mcp_tools import LogTools

PROTOCOL = "2025-06-18"


def rpc(url: str, method: str, params: dict | None = None, *, host: str | None = None) -> dict:
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               "MCP-Protocol-Version": PROTOCOL}
    if host:
        headers["Host"] = host
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def call_tool(url: str, name: str, **arguments) -> dict:
    return rpc(url, "tools/call", {"name": name, "arguments": arguments})["result"]


@pytest.fixture
def server(store):
    store.insert([make_event(0, message="Initializing system"),
                  make_event(1000, severity=3, message="disk failed")])
    thread = McpServerThread(LogTools(store.path), 0)
    assert thread.start(), thread.error
    yield thread
    thread.stop()


def test_initialize_list_and_call_tools(server):
    assert server.running and server.url == server_url(server.port)
    init = rpc(server.url, "initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                          "clientInfo": {"name": "test", "version": "1"}})
    assert init["result"]["serverInfo"]["name"] == "syslog-monitor"
    assert "logs_since_boot" in init["result"]["instructions"]

    tools = {t["name"]: t for t in rpc(server.url, "tools/list")["result"]["tools"]}
    assert set(tools) == {"status", "list_devices", "logs_since_boot", "get_logs", "search_logs",
                          "get_context", "summarize", "error_timeline", "wait_for_message"}
    assert all(t["annotations"]["readOnlyHint"] for t in tools.values())
    assert "device" in tools["logs_since_boot"]["inputSchema"]["properties"]

    result = call_tool(server.url, "logs_since_boot")
    assert not result["isError"]
    assert [e["message"] for e in result["structuredContent"]["events"]] == [
        "Initializing system", "disk failed"]


def test_invalid_arguments_are_reported_to_the_client(server):
    result = call_tool(server.url, "get_logs", since="gestern")
    assert result["isError"]
    assert "ISO 8601" in result["content"][0]["text"]


def test_foreign_host_header_is_rejected(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        rpc(server.url, "tools/list", host="evil.example:80")
    assert exc.value.code in (403, 421)


def test_busy_port_is_reported(store):
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        thread = McpServerThread(LogTools(store.path), blocker.getsockname()[1])
        assert not thread.start()
        assert "unavailable" in thread.error and not thread.running


def test_stop_releases_port(store):
    thread = McpServerThread(LogTools(store.path), 0)
    assert thread.start()
    port = thread.port
    thread.stop()
    assert not thread.running
    again = McpServerThread(LogTools(store.path), port)
    assert again.start(), again.error
    again.stop()


def test_service_follows_settings(store):
    service = McpService(LogTools(store.path))
    try:
        assert service.apply(Settings(mcp_enabled=False))
        assert not service.running and service.url is None
        assert service.apply(Settings(mcp_port=0, boot_marker="boot ok"))
        assert service.running and service.tools.boot_marker == "boot ok"
        url = service.url
        assert service.apply(Settings(mcp_port=0, boot_marker="other"))  # no restart needed
        assert service.url == url and service.tools.boot_marker == "other"
        assert rpc(url, "tools/list")["result"]["tools"]
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free_port = probe.getsockname()[1]
        assert service.apply(Settings(mcp_port=free_port))
        assert service.port == free_port
        with pytest.raises(urllib.error.URLError):
            rpc(url, "tools/list")
        assert service.apply(Settings(mcp_enabled=False))
        assert not service.running
    finally:
        service.stop()


def test_client_config_snippet():
    assert client_config(8514) == {
        "servers": {"syslog-monitor": {"type": "http", "url": "http://127.0.0.1:8514/mcp"}}}
