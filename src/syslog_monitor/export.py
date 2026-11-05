"""Streaming exports from a consistent database snapshot, independent of UI paging."""

from __future__ import annotations

import base64
import csv
import json
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from typing import Callable

from syslog_monitor.config import DEFAULT_BOOT_MARKER
from syslog_monitor.query import EventFilter, build_where, highlight_sql, parse_highlights
from syslog_monitor.storage import EVENT_COLUMNS, connect

BATCH_SIZE = 1000
EXPORT_COLUMNS = ("id", *EVENT_COLUMNS[:-1], "raw_base64")


class ExportCancelled(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ExportOptions:
    period: str = "boot"
    format: str = "csv"
    filters: EventFilter = EventFilter()
    boot_marker: str = DEFAULT_BOOT_MARKER

    def validate(self) -> None:
        if self.period not in ("boot", "24h", "custom"):
            raise ValueError("Choose a valid export period.")
        if self.format not in ("csv", "jsonl"):
            raise ValueError("Choose CSV or JSONL.")
        if self.period == "boot" and not parse_highlights(self.boot_marker):
            raise ValueError("Configure a boot marker in Settings or choose another period.")
        if self.period == "custom":
            start, end = self.filters.start_ms, self.filters.end_ms
            if start is None or end is None or start >= end:
                raise ValueError("The start date must be before the end date.")


@dataclass(frozen=True, slots=True)
class ExportResult:
    rows: int
    skipped_devices: int = 0


def _csv_value(value: object) -> object:
    # Syslog fields are untrusted: prevent spreadsheet formula execution.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    if isinstance(value, str) and value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def _timestamp(value: int) -> str:
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat(timespec="milliseconds")


def export_events(db_path: Path, destination: Path, options: ExportOptions, *, now_ms: int,
                  cancel: Event | None = None,
                  progress: Callable[[int], None] | None = None) -> ExportResult:
    """Atomically replace the destination only after a successful, uncancelled export."""
    options.validate()
    database = db_path.resolve()
    if not database.is_file():
        raise FileNotFoundError(f"The log database does not exist: {database}")
    target = destination.resolve()
    protected = [Path(str(database) + suffix) for suffix in ("", "-wal", "-shm", "-journal")]
    if any(target == path or (target.exists() and path.exists() and target.samefile(path))
           for path in protected):
        raise ValueError("The export destination must not be the log database or its sidecar files.")
    cancel = cancel if cancel is not None else Event()

    def check_cancelled() -> None:
        if cancel.is_set():
            raise ExportCancelled()

    check_cancelled()
    conn = connect(database, readonly=True)
    temporary: Path | None = None
    try:
        conn.set_progress_handler(lambda: int(cancel.is_set()), 1000)
        conn.execute("BEGIN")
        filters = options.filters
        if options.period == "24h":
            filters = filters.with_time(now_ms - 86_400_000, now_ms + 1)
        elif options.period == "boot":
            filters = filters.with_time(None, now_ms + 1)
        where, params = build_where(filters)
        join = ""
        skipped = 0
        if options.period == "boot":
            marker_sql, marker_params = highlight_sql(options.boot_marker)
            cte = (
                "WITH ranked_boots AS ("
                "SELECT source_ip, received_at, id, "
                "ROW_NUMBER() OVER (PARTITION BY source_ip ORDER BY received_at DESC, id DESC) AS rank "
                f"FROM events WHERE {marker_sql} AND received_at <= ?), "
                "boots AS (SELECT source_ip, received_at, id FROM ranked_boots WHERE rank = 1) "
            )
            boot_params = [*marker_params, now_ms]
            if not conn.execute(cte + "SELECT 1 FROM boots LIMIT 1", boot_params).fetchone():
                raise ValueError("No stored boot marker was found. Choose 24 hours or a date range, "
                                 "or check the boot marker in Settings.")
            skipped = conn.execute(
                cte + f"SELECT COUNT(DISTINCT source_ip) FROM events WHERE {where} "
                "AND source_ip NOT IN (SELECT source_ip FROM boots)", [*boot_params, *params],
            ).fetchone()[0]
            cte += f", selected AS (SELECT * FROM events WHERE {where}) "
            join = (" JOIN boots b ON e.source_ip = b.source_ip "
                    "AND (e.received_at, e.id) >= (b.received_at, b.id)")
            params = [*boot_params, *params]
        else:
            cte = f"WITH selected AS (SELECT * FROM events WHERE {where}) "
        columns = ", ".join(f"e.{column}" for column in ("id", *EVENT_COLUMNS))
        cursor = conn.execute(
            cte + f"SELECT {columns} FROM selected e{join} ORDER BY e.received_at, e.id", params)
        count = 0
        reported_index = EXPORT_COLUMNS.index("reported_time_utc")
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8-sig" if options.format == "csv" else "utf-8",
                                         newline="", dir=target.parent, prefix=f".{target.name}.",
                                         suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            writer = csv.writer(output) if options.format == "csv" else None
            if writer:
                writer.writerow(EXPORT_COLUMNS)
            while rows := cursor.fetchmany(BATCH_SIZE):
                check_cancelled()
                for row in rows:
                    check_cancelled()
                    values = list(row[:-1]) + [base64.b64encode(row[-1]).decode("ascii")]
                    values[1] = _timestamp(values[1])
                    if values[reported_index] is not None:
                        values[reported_index] = _timestamp(values[reported_index])
                    if writer:
                        writer.writerow([_csv_value(value) for value in values])
                    else:
                        output.write(json.dumps(dict(zip(EXPORT_COLUMNS, values)), ensure_ascii=False) + "\n")
                count += len(rows)
                if progress:
                    progress(count)
            output.flush()
            os.fsync(output.fileno())
        check_cancelled()
        os.replace(temporary, target)
        return ExportResult(count, skipped)
    except sqlite3.OperationalError as exc:
        if cancel.is_set():
            raise ExportCancelled() from exc
        raise
    finally:
        conn.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)
