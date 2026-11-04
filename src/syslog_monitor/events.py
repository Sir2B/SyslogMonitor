"""Event model and syslog code tables shared by all layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

SEVERITY_NAMES = (
    "Emergency",
    "Alert",
    "Critical",
    "Error",
    "Warning",
    "Notice",
    "Info",
    "Debug",
)

FACILITY_NAMES = (
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
)


class SeverityClass(IntEnum):
    """Coarse severity groups used for colouring and the minimap."""

    ERROR = 0  # emergency .. error
    WARNING = 1
    INFO = 2  # notice, info
    DEBUG = 3
    UNKNOWN = 4  # no or invalid PRI


SEVERITY_CLASS_LABELS = {
    SeverityClass.ERROR: "Error",
    SeverityClass.WARNING: "Warning",
    SeverityClass.INFO: "Info",
    SeverityClass.DEBUG: "Debug",
    SeverityClass.UNKNOWN: "Unknown",
}


def severity_class(severity: int | None) -> SeverityClass:
    if severity is None:
        return SeverityClass.UNKNOWN
    if severity <= 3:
        return SeverityClass.ERROR
    if severity == 4:
        return SeverityClass.WARNING
    if severity <= 6:
        return SeverityClass.INFO
    return SeverityClass.DEBUG


def severity_name(severity: int | None) -> str:
    if severity is None or not 0 <= severity < len(SEVERITY_NAMES):
        return "Unknown"
    return SEVERITY_NAMES[severity]


def facility_name(facility: int | None) -> str:
    if facility is None:
        return "-"
    if 0 <= facility < len(FACILITY_NAMES):
        return FACILITY_NAMES[facility]
    return str(facility)


@dataclass(slots=True)
class SyslogEvent:
    """A received syslog message, parsed as far as possible.

    ``received_at`` is the local reception time (UTC, epoch milliseconds) and is
    the authoritative ordering key. ``reported_time_*`` is what the sender claims.
    """

    received_at: int
    source_ip: str
    source_port: int
    raw: bytes
    message: str
    format: str = "unparsed"  # rfc5424 | rfc3164 | unparsed
    issues: tuple[str, ...] = ()
    facility: int | None = None
    severity: int | None = None
    reported_time_text: str | None = None
    reported_time_utc: int | None = None
    hostname: str | None = None
    app_name: str | None = None
    procid: str | None = None
    msgid: str | None = None
    structured_data: str | None = None
    id: int | None = field(default=None, compare=False)
