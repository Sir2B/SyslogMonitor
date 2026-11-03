"""Persistent application settings (JSON) and default locations."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path

log = logging.getLogger(__name__)

APP_DIR_NAME = "SyslogMonitor"
MIN_STORAGE_MB = 64
MAX_RETENTION_DAYS = 3650
DEFAULT_BOOT_MARKER = "Initializing system"
MCP_HOST = "127.0.0.1"  # the MCP server is never reachable from other machines


def default_config_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(base) / APP_DIR_NAME


@dataclass(frozen=True, slots=True)
class Settings:
    bind_host: str = "0.0.0.0"
    port: int = 514
    retention_days: int = 30
    max_storage_mb: int = 5120
    data_dir: str = ""  # empty: <config dir>/data
    autostart_listener: bool = True
    mcp_enabled: bool = True
    mcp_port: int = 8514
    boot_marker: str = DEFAULT_BOOT_MARKER  # ";"-separated texts marking a device start (MCP)

    def resolved_data_dir(self, config_dir: Path) -> Path:
        return Path(self.data_dir) if self.data_dir else config_dir / "data"

    @property
    def max_storage_bytes(self) -> int:
        return self.max_storage_mb * 1024 * 1024

    def validate(self) -> list[str]:
        """Return human readable problems; empty list means valid."""
        errors: list[str] = []
        try:
            ip = ipaddress.ip_address(self.bind_host)
            if ip.version != 4:
                errors.append("Only IPv4 addresses are supported.")
        except ValueError:
            errors.append(f"Invalid IPv4 address: {self.bind_host!r}")
        if not 1 <= self.port <= 65535:
            errors.append("Port must be between 1 and 65535.")
        if not 1 <= self.retention_days <= MAX_RETENTION_DAYS:
            errors.append(f"Retention must be between 1 and {MAX_RETENTION_DAYS} days.")
        if self.max_storage_mb < MIN_STORAGE_MB:
            errors.append(f"Storage budget must be at least {MIN_STORAGE_MB} MiB.")
        if not isinstance(self.mcp_port, int) or not 1 <= self.mcp_port <= 65535:
            errors.append("MCP port must be between 1 and 65535.")
        if not isinstance(self.boot_marker, str):
            errors.append("Boot marker must be text.")
        return errors


def load_settings(path: Path) -> Settings:
    """Load settings; unknown keys are ignored, invalid files fall back to defaults."""
    if not path.exists():
        return Settings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        known = {f.name for f in fields(Settings)}
        settings = replace(Settings(), **{k: v for k, v in data.items() if k in known})
    except (OSError, ValueError, TypeError) as exc:
        log.warning("Could not read settings %s (%s); using defaults", path, exc)
        return Settings()
    if problems := settings.validate():
        log.warning("Invalid settings %s: %s; using defaults", path, problems)
        return Settings()
    return settings


def save_settings(path: Path, settings: Settings) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(asdict(settings), indent=2), encoding="utf-8")
    os.replace(tmp, path)
