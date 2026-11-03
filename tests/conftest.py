import os
import socket
import sys
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from syslog_monitor.events import SyslogEvent  # noqa: E402
from syslog_monitor.storage import EventStore  # noqa: E402

BASE_MS = 1_760_000_000_000  # fixed reference time for deterministic tests


def make_event(offset_ms: int = 0, *, severity: int | None = 6, message: str = "hello world",
               source_ip: str = "192.0.2.1", hostname: str | None = "host1",
               app_name: str | None = "app", facility: int | None = 1) -> SyslogEvent:
    return SyslogEvent(
        received_at=BASE_MS + offset_ms,
        source_ip=source_ip,
        source_port=514,
        raw=message.encode(),
        message=message,
        format="rfc5424",
        severity=severity,
        facility=facility,
        hostname=hostname,
        app_name=app_name,
    )


@pytest.fixture
def store(tmp_path: Path):
    s = EventStore(tmp_path)
    yield s
    s.close()


def send_udp(port: int, *payloads: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for payload in payloads:
            sock.sendto(payload, ("127.0.0.1", port))
