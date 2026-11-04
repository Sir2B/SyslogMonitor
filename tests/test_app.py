"""Smoke tests for the application entry point (startup, lock, shutdown)."""

import json
import logging
import logging.handlers
import os
import socket
import sqlite3
import subprocess
import sys
import textwrap
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QLockFile

from syslog_monitor import app as app_module
from syslog_monitor.config import load_settings
from syslog_monitor.stats import StatsSnapshot


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_tcp_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_settings(cfg, **extra) -> None:
    data = {"bind_host": "127.0.0.1", "port": free_udp_port(), "mcp_port": free_tcp_port(), **extra}
    (cfg / "settings.json").write_text(json.dumps(data))


@pytest.fixture
def config_dir(tmp_path, monkeypatch, qapp):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)  # main() installs its own hook
    cfg = tmp_path / "SyslogMonitor"
    cfg.mkdir()
    write_settings(cfg)
    messages = []
    monkeypatch.setattr(app_module.QMessageBox, "warning", lambda *a: messages.append(a[2]))
    monkeypatch.setattr(app_module.QMessageBox, "critical", lambda *a: messages.append(a[2]))
    yield SimpleNamespace(path=cfg, messages=messages)
    root = logging.getLogger()
    for handler in list(root.handlers):
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            root.removeHandler(handler)
            handler.close()


def test_main_creates_its_config_directory_without_modifying_other_directories(tmp_path, monkeypatch, qapp):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    other_dir = tmp_path / "other-application"
    other_dir.mkdir()
    marker = other_dir / "settings.json"
    marker.write_text("unchanged", encoding="utf-8")
    run_dirs = []
    monkeypatch.setattr(app_module, "setup_logging", lambda path: None)
    monkeypatch.setattr(app_module, "_run", lambda app, path: run_dirs.append(path) or 0)

    assert app_module.main([]) == 0
    assert run_dirs == [tmp_path / "SyslogMonitor"]
    assert run_dirs[0].is_dir()
    assert marker.read_text(encoding="utf-8") == "unchanged"


def test_start_receive_and_quit(tmp_path):
    # Runs in a separate process: after QApplication.exec() has returned, Qt does not
    # deliver cross-thread events reliably anymore, which would break later GUI tests.
    cfg = tmp_path / "SyslogMonitor"
    cfg.mkdir()
    write_settings(cfg)
    settings = json.loads((cfg / "settings.json").read_text())
    port, mcp_port = settings["port"], settings["mcp_port"]
    script = textwrap.dedent(f"""
        import json, socket, sys, threading, time, urllib.request
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from syslog_monitor.app import main

        app = QApplication([])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        QTimer.singleShot(500, lambda: sock.sendto(b"<11>1 - host app - - - smoke test", ("127.0.0.1", {port})))
        started, answers = time.monotonic(), []

        def ask_mcp():  # the MCP server starts in the background and must answer
            body = json.dumps({{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {{"name": "search_logs", "arguments": {{"query": "smoke"}}}}}}).encode()
            request = urllib.request.Request("http://127.0.0.1:{mcp_port}/mcp", data=body, headers={{
                "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}})
            for _ in range(300):
                try:
                    if time.monotonic() - started > 1.5:
                        answers.append(json.loads(urllib.request.urlopen(request, timeout=5).read()))
                        return
                except OSError:
                    pass
                time.sleep(0.1)
            answers.append(None)

        threading.Thread(target=ask_mcp, daemon=True).start()
        timer = QTimer()
        timer.timeout.connect(lambda: answers and app.quit())
        timer.start(100)
        exit_code = main([])
        print("MCP-ANSWER", json.dumps(answers[0]))
        sys.exit(exit_code)
    """)
    env = {**os.environ, "LOCALAPPDATA": str(tmp_path), "QT_QPA_PLATFORM": "offscreen",
           "PYTHONPATH": str(Path(app_module.__file__).parents[1])}
    result = subprocess.run([sys.executable, "-c", script], env=env, timeout=90,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    with closing(sqlite3.connect(cfg / "data" / "syslog.sqlite3")) as conn:
        assert conn.execute("SELECT message FROM events").fetchall() == [("smoke test",)]
    answer = json.loads(result.stdout.split("MCP-ANSWER", 1)[1])
    assert answer["result"]["structuredContent"]["total_matches"] == 1, result.stdout
    log_text = (cfg / "logs" / "syslog_monitor.log").read_text(encoding="utf-8")
    assert "MCP server is running" in log_text and "stopped" in log_text


def test_autostart_tcp_only_receives_messages(tmp_path):
    cfg = tmp_path / "SyslogMonitor"
    cfg.mkdir()
    port = free_tcp_port()
    write_settings(cfg, udp_enabled=False, tcp_enabled=True, tcp_port=port, mcp_enabled=False)
    script = textwrap.dedent(f"""
        import socket, sys
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from syslog_monitor.app import main

        app = QApplication([])
        def send():
            with socket.create_connection(("127.0.0.1", {port}), timeout=5) as client:
                message = b"<14>1 - host app - - - tcp octets"
                client.sendall(b"<14>1 - host app - - - tcp line\\n"
                               + str(len(message)).encode() + b" " + message)
        QTimer.singleShot(500, send)
        QTimer.singleShot(1800, app.quit)
        sys.exit(main([]))
    """)
    env = {**os.environ, "LOCALAPPDATA": str(tmp_path), "QT_QPA_PLATFORM": "offscreen",
           "PYTHONPATH": str(Path(app_module.__file__).parents[1])}
    result = subprocess.run([sys.executable, "-c", script], env=env, timeout=30,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    with closing(sqlite3.connect(cfg / "data" / "syslog.sqlite3")) as conn:
        assert {row[0] for row in conn.execute("SELECT message FROM events")} == {"tcp line", "tcp octets"}
    log_text = (cfg / "logs" / "syslog_monitor.log").read_text(encoding="utf-8")
    assert "TCP listener started" in log_text and "UDP listener started" not in log_text


def test_autostart_tls_only_receives_messages(tmp_path, tls_certs):
    cfg = tmp_path / "SyslogMonitor"
    cfg.mkdir()
    port = free_tcp_port()
    write_settings(cfg, udp_enabled=False, tls_enabled=True, tls_port=port,
                   tls_cert_file=tls_certs.server_cert, tls_key_file=tls_certs.server_key,
                   mcp_enabled=False)
    script = textwrap.dedent(f"""
        import socket, ssl, sys
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from syslog_monitor.app import main

        app = QApplication([])
        def send():
            context = ssl.create_default_context(cafile={tls_certs.ca!r})
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            with socket.create_connection(("127.0.0.1", {port}), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as client:
                    message = b"<14>1 - host app - - - tls autostart"
                    client.sendall(str(len(message)).encode() + b" " + message)
                    with client.unwrap():
                        pass
        QTimer.singleShot(500, send)
        QTimer.singleShot(1800, app.quit)
        sys.exit(main([]))
    """)
    env = {**os.environ, "LOCALAPPDATA": str(tmp_path), "QT_QPA_PLATFORM": "offscreen",
           "PYTHONPATH": str(Path(app_module.__file__).parents[1])}
    result = subprocess.run([sys.executable, "-c", script], env=env, timeout=30,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    with closing(sqlite3.connect(cfg / "data" / "syslog.sqlite3")) as conn:
        assert conn.execute("SELECT message FROM events").fetchall() == [("tls autostart",)]
    log_text = (cfg / "logs" / "syslog_monitor.log").read_text(encoding="utf-8")
    assert "TLS listener started" in log_text and "UDP listener started" not in log_text


def test_mcp_receiver_status_keeps_primary_address_and_lists_transports():
    snap = StatsSnapshot(listener_state="running", listener_address="127.0.0.1:514",
                         listener_endpoints=(("UDP", "127.0.0.1", 514), ("TCP", "127.0.0.1", 6514)),
                         dropped_queue_full=1, dropped_write_error=2, dropped_tcp_framing=3,
                         tcp_connections_rejected=4, tls_handshake_failures=5)
    status = app_module.receiver_status(snap)
    assert status["address"] == "127.0.0.1:514"
    assert status["listeners"] == [{"protocol": "UDP", "address": "127.0.0.1:514"},
                                   {"protocol": "TCP", "address": "127.0.0.1:6514"}]
    assert status["dropped_since_start"] == 6
    assert status["tcp_connections_rejected_since_start"] == 4
    assert status["tls_handshake_failures_since_start"] == 5


def test_second_instance_is_refused(config_dir):
    lock = QLockFile(str(config_dir.path / "instance.lock"))
    assert lock.tryLock(100)
    try:
        assert app_module.main([]) == 1
        assert "is already running" in config_dir.messages[0]
    finally:
        lock.unlock()


def test_unusable_data_dir_reports_error(config_dir, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    write_settings(config_dir.path, data_dir=str(blocker))
    assert load_settings(config_dir.path / "settings.json").data_dir == str(blocker)
    assert app_module.main([]) == 2
    assert "is unavailable" in config_dir.messages[0]


def test_app_user_model_id_is_project_specific():
    assert app_module.APP_USER_MODEL_ID == "SyslogMonitor.Desktop"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows taskbar identity")
def test_windows_app_id_is_set_for_taskbar_icon():
    script = textwrap.dedent("""
        import ctypes
        from ctypes import wintypes
        from syslog_monitor.app import APP_USER_MODEL_ID, set_windows_app_id
        assert set_windows_app_id()
        value = wintypes.LPWSTR()
        assert ctypes.windll.shell32.GetCurrentProcessExplicitAppUserModelID(ctypes.byref(value)) == 0
        assert value.value == APP_USER_MODEL_ID, value.value
        ctypes.windll.ole32.CoTaskMemFree(value)
    """)
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
