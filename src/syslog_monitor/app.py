"""Application entry point: logging, single instance, service, window and tray."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from PySide6.QtCore import QLockFile, QLocale, QSettings
from PySide6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon

from syslog_monitor import APP_DISPLAY_NAME, __version__
from syslog_monitor.config import default_config_dir, load_settings, save_settings
from syslog_monitor.mcp_server import McpService
from syslog_monitor.mcp_tools import LogTools
from syslog_monitor.service import CaptureService
from syslog_monitor.stats import StatsSnapshot
from syslog_monitor.storage import StorageError
from syslog_monitor.ui.icons import app_icon
from syslog_monitor.ui.main_window import MainWindow

log = logging.getLogger("syslog_monitor")

APP_USER_MODEL_ID = "SyslogMonitor.Desktop"


def set_windows_app_id(app_id: str = APP_USER_MODEL_ID) -> bool:
    """Give the process its own taskbar identity instead of grouping it under python.exe.

    Must run before the first window is created. No-op outside Windows.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id) == 0
    except (AttributeError, OSError):
        log.warning("Could not set AppUserModelID", exc_info=True)
        return False


def setup_logging(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_dir / "syslog_monitor.log", maxBytes=2 * 1024 * 1024,
                                  backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    sys.excepthook = lambda *exc: log.critical("Unhandled exception", exc_info=exc)


def main(argv: list[str] | None = None) -> int:
    config_dir = default_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(config_dir / "logs")
    log.info("Starting %s %s", APP_DISPLAY_NAME, __version__)

    set_windows_app_id()
    app =  QApplication.instance() or QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName(APP_DISPLAY_NAME)
    QLocale.setDefault(QLocale(QLocale.Language.English, QLocale.Country.UnitedStates))
    app.setWindowIcon(app_icon())

    lock = QLockFile(str(config_dir / "instance.lock"))
    if not lock.tryLock(100):
        QMessageBox.warning(None, APP_DISPLAY_NAME, f"{APP_DISPLAY_NAME} is already running (possibly in the system tray).")
        return 1
    try:
        return _run(app, config_dir)
    finally:
        lock.unlock()
        log.info("%s stopped", APP_DISPLAY_NAME)


def _run(app: QApplication, config_dir: Path) -> int:
    settings_path = config_dir / "settings.json"
    settings = load_settings(settings_path)
    if not settings_path.exists():
        save_settings(settings_path, settings)

    data_dir = settings.resolved_data_dir(config_dir)
    try:
        service = CaptureService(data_dir, settings)
    except StorageError as exc:
        log.exception("Database is unavailable")
        QMessageBox.critical(None, APP_DISPLAY_NAME,
                             f"{exc}\n\nCheck the data directory in {settings_path}.")
        return 2
    if settings.autostart_listener:
        service.start_listener()
    mcp = McpService(LogTools(service.db_path, boot_marker=settings.boot_marker,
                              status_provider=lambda: receiver_status(service.snapshot())))
    mcp.apply_async(settings)  # importing the MCP SDK must not delay the window

    tray_enabled = QSystemTrayIcon.isSystemTrayAvailable()
    if not tray_enabled:
        log.warning("System tray is unavailable; closing the window will exit the application")
    app.setQuitOnLastWindowClosed(not tray_enabled)
    ui_state = QSettings(str(config_dir / "ui.ini"), QSettings.IniFormat)
    window = MainWindow(service, settings_path=settings_path, ui_state=ui_state, tray_enabled=tray_enabled,
                        mcp=mcp)
    window.show()
    try:
        return app.exec()
    finally:
        window.shutdown()
        mcp.stop()
        service.shutdown()


def receiver_status(snap: StatsSnapshot) -> dict[str, object]:
    """Receiver part of the MCP ``status`` tool (called from the MCP thread)."""
    return {
        "state": snap.listener_state,
        "address": snap.listener_address,
        "listeners": [{"protocol": protocol, "address": f"{host}:{port}"}
                      for protocol, host, port in snap.listener_endpoints],
        "error": snap.listener_error or None,
        "received_since_start": snap.received,
        "dropped_since_start": snap.dropped_queue_full + snap.dropped_write_error + snap.dropped_tcp_framing,
        "tcp_connections_rejected_since_start": snap.tcp_connections_rejected,
        "tls_handshake_failures_since_start": snap.tls_handshake_failures,
    }


if __name__ == "__main__":
    sys.exit(main())
