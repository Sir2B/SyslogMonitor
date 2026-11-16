"""Compressed archive for events that retention would otherwise delete.

Archived events are stored as xz-compressed JSON lines in several files under
``<data dir>/archive`` (about 35x smaller than the raw lines, roughly a third
smaller than gzip). Files written by older versions (``.jsonl.gz``) stay readable.
Files are large (about 5 % of the archive budget) so there are only a few of
them; the budget deletes whole files. The index records every appended xz stream
(offset, length, time range), so the viewer can load single days or parts of at
most ``VIEW_MAX_EVENTS`` events without reading whole files.

The writer thread appends each batch as a complete xz stream (concatenated
streams form a valid .xz file) and fsyncs it before the rows are deleted from the
database, so a crash can at worst truncate the last stream (readers stop there)
or duplicate a batch in the archive, but never lose events.
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import lzma
import logging
import os
import sqlite3
import threading
import zlib
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence

log = logging.getLogger(__name__)

ARCHIVE_DIRNAME = "archive"
INDEX_FILENAME = "index.json"
SUFFIX = ".jsonl.xz"
SUFFIXES = (SUFFIX, ".jsonl.gz")
XZ_PRESET = 6
MIN_FILE_BYTES = 1024 * 1024
FILE_SHARE_OF_ARCHIVE_BUDGET = 20  # ~200 MiB files for a 4 GiB archive
# A viewed part becomes ~500 bytes per event in the viewer database and loads at
# about 50,000 events/s: 1 million events are ~500 MB and ~20 s.
VIEW_MAX_EVENTS = 1_000_000
LOAD_BATCH = 5000


def archive_dir(data_dir: Path) -> Path:
    return data_dir / ARCHIVE_DIRNAME


def file_target_bytes(archive_budget_bytes: int) -> int:
    return max(MIN_FILE_BYTES, archive_budget_bytes // FILE_SHARE_OF_ARCHIVE_BUDGET)


@dataclass(frozen=True, slots=True)
class ArchiveFile:
    name: str
    first_ms: int
    last_ms: int
    count: int
    size: int
    # One [offset, length, first_ms, last_ms, count] per appended xz stream; empty for
    # legacy gzip files (read as a whole).
    segments: list = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ViewChunk:
    """A viewable part of the archive: consecutive streams of one local calendar day."""
    first_ms: int
    last_ms: int
    count: int
    parts: tuple[tuple[str, int, int], ...]  # (file name, offset, length); length -1: whole file

    @property
    def key(self) -> str:
        return f"{self.parts[0][0]}:{self.parts[0][1]}"


def _file_segments(entry: ArchiveFile) -> list[tuple[int, int, int, int, int]]:
    if entry.segments:
        return [tuple(segment) for segment in entry.segments]
    return [(0, -1, entry.first_ms, entry.last_ms, entry.count)]


def view_chunks(files: Sequence[ArchiveFile], max_events: int = VIEW_MAX_EVENTS) -> list[ViewChunk]:
    """Group archive streams by local calendar day, splitting days above ``max_events``."""
    chunks: list[ViewChunk] = []
    current: list[tuple[str, int, int, int, int, int]] = []

    def flush() -> None:
        if not current:
            return
        parts: list[list] = []
        for name, offset, length, *_ in current:
            last = parts[-1] if parts else None
            if last and last[0] == name and length >= 0 and last[2] >= 0 and last[1] + last[2] == offset:
                last[2] += length
            else:
                parts.append([name, offset, length])
        chunks.append(ViewChunk(min(s[3] for s in current), max(s[4] for s in current),
                                sum(s[5] for s in current), tuple(tuple(p) for p in parts)))
        current.clear()

    day = None
    count = 0
    for entry in files:
        for offset, length, first, last, n in _file_segments(entry):
            segment_day = datetime.fromtimestamp(first / 1000).date()
            if current and (segment_day != day or count + n > max_events):
                flush()
                count = 0
            current.append((entry.name, offset, length, first, last, n))
            day = segment_day
            count += n
    flush()
    return chunks


def encode_row(columns: Sequence[str], row: Sequence) -> bytes:
    record = dict(zip(columns, row))
    raw = record.pop("raw", None)
    if isinstance(raw, (bytes, bytearray, memoryview)):
        raw = bytes(raw)
        try:
            record["raw"] = raw.decode("utf-8")
        except UnicodeDecodeError:
            record["raw_b64"] = base64.b64encode(raw).decode("ascii")
    elif raw is not None:
        record["raw"] = str(raw)
    return (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def decode_row(columns: Sequence[str], line: bytes) -> tuple:
    record = json.loads(line)
    if "raw_b64" in record:
        record["raw"] = base64.b64decode(record.pop("raw_b64"))
    else:
        record["raw"] = str(record.get("raw", "")).encode("utf-8")
    return tuple(record.get(column) for column in columns)


READ_ERRORS = (EOFError, gzip.BadGzipFile, zlib.error, lzma.LZMAError)


def _reader(fileobj, name: str):
    if name.endswith(".gz"):
        return gzip.GzipFile(fileobj=fileobj, mode="rb")
    return lzma.LZMAFile(fileobj, mode="rb")


def _lines(fileobj, name: str) -> Iterator[bytes]:
    """Yield complete lines; a truncated tail (crash while appending) ends the file."""
    try:
        with _reader(fileobj, name) as stream:
            for line in stream:
                if line.endswith(b"\n"):
                    yield line
    except READ_ERRORS as exc:
        log.warning("Archive %s ends early: %s", name, exc)


def iter_lines(path: Path) -> Iterator[bytes]:
    with open(path, "rb") as raw:
        yield from _lines(raw, path.name)


def read_index(directory: Path) -> list[ArchiveFile]:
    """Archive files, oldest first, as recorded by the writer (safe from any thread)."""
    try:
        data = json.loads((directory / INDEX_FILENAME).read_text(encoding="utf-8"))
        files = [ArchiveFile(**entry) for entry in data.get("files", [])]
    except FileNotFoundError:
        return []
    except (OSError, ValueError, TypeError) as exc:
        log.warning("Could not read archive index: %s", exc)
        return []
    return sorted((f for f in files if (directory / f.name).exists()), key=lambda f: f.first_ms)


def _file_name(first_ms: int) -> str:
    stamp = datetime.fromtimestamp(first_ms / 1000, timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"syslog-{stamp}{SUFFIX}"


class _OpenFile:
    def __init__(self, path: Path, entry: ArchiveFile) -> None:
        self.path = path
        self.entry = entry
        self.raw = open(path, "ab")

    def write(self, data: bytes) -> tuple[int, int]:
        """Append one xz stream; returns its (offset, length)."""
        compressed = lzma.compress(data, preset=XZ_PRESET)
        self.raw.seek(0, os.SEEK_END)
        offset = self.raw.tell()
        self.raw.write(compressed)
        self.raw.flush()
        os.fsync(self.raw.fileno())
        return offset, len(compressed)

    def close(self) -> None:
        self.raw.close()


class Archive:
    """Writer-side archive; only one thread may append (the database writer)."""

    def __init__(self, data_dir: Path, columns: Sequence[str]) -> None:
        self.directory = archive_dir(data_dir)
        self.columns = tuple(columns)
        self._lock = threading.Lock()
        self._files: list[ArchiveFile] = []
        self._current: _OpenFile | None = None
        self._reconcile()

    # ---------------------------------------------------------------- index
    def _reconcile(self) -> None:
        """Load the index and rescan files that are missing from it or changed size."""
        known = {f.name: f for f in read_index(self.directory)}
        files: list[ArchiveFile] = []
        if self.directory.is_dir():
            for path in (p for suffix in SUFFIXES for p in self.directory.glob(f"*{suffix}")):
                size = path.stat().st_size
                entry = known.get(path.name)
                if (entry is None or entry.size != size
                        or (path.name.endswith(SUFFIX) and entry.count and not entry.segments)):
                    entry = self._scan(path, size)
                if entry is not None:
                    files.append(entry)
        files.sort(key=lambda f: f.first_ms)
        self._files = files
        if set(known) != {f.name for f in files} or any(known.get(f.name) != f for f in files):
            self._write_index()

    def _times(self, lines: Iterable[bytes]) -> list[int]:
        index = self.columns.index("received_at")
        times = []
        for line in lines:
            try:
                times.append(decode_row(self.columns, line)[index])
            except (ValueError, TypeError):
                continue
        return times

    def _scan_xz(self, path: Path) -> ArchiveFile | None:
        """Rebuild the stream index; an incomplete last stream (crash) is cut off."""
        segments: list[list[int]] = []
        start = 0
        with open(path, "rb") as stream:
            decoder, output, fed, broken = lzma.LZMADecompressor(lzma.FORMAT_XZ), [], 0, False
            while not broken and (chunk := stream.read(1 << 20)):
                while chunk:
                    try:
                        output.append(decoder.decompress(chunk))
                    except lzma.LZMAError:
                        broken = True
                        break
                    if not decoder.eof:
                        fed += len(chunk)
                        break
                    rest = decoder.unused_data
                    used = fed + len(chunk) - len(rest)
                    times = self._times(line for line in b"".join(output).split(b"\n") if line)
                    if times:
                        segments.append([start, used, min(times), max(times), len(times)])
                    start += used
                    decoder, output, fed, chunk = lzma.LZMADecompressor(lzma.FORMAT_XZ), [], 0, rest
        if start < path.stat().st_size:
            log.warning("Archive %s: removing an incomplete tail after %d bytes", path.name, start)
            with open(path, "r+b") as stream:
                stream.truncate(start)
        if not segments:
            if start == 0:
                path.unlink(missing_ok=True)
                return None
            return ArchiveFile(path.name, 0, 0, 0, start)
        return ArchiveFile(path.name, min(s[2] for s in segments), max(s[3] for s in segments),
                           sum(s[4] for s in segments), start, segments)

    def _scan(self, path: Path, size: int) -> ArchiveFile | None:
        if path.name.endswith(SUFFIX):
            return self._scan_xz(path)
        first = last = None
        count = 0
        index = self.columns.index("received_at")
        for line in iter_lines(path):
            try:
                received = decode_row(self.columns, line)[index]
            except (ValueError, TypeError):
                continue
            first = received if first is None else min(first, received)
            last = received if last is None else max(last, received)
            count += 1
        if first is None:
            return ArchiveFile(path.name, 0, 0, 0, size) if size else None
        return ArchiveFile(path.name, first, last, count, size)

    def _write_index(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        tmp = self.directory / (INDEX_FILENAME + ".tmp")
        tmp.write_text(json.dumps({"files": [asdict(f) for f in self._files]}, indent=1),
                       encoding="utf-8")
        for attempt in range(5):
            try:
                os.replace(tmp, self.directory / INDEX_FILENAME)
                return
            except PermissionError:  # a reader has the index open (Windows)
                threading.Event().wait(0.05 * (attempt + 1))
        log.warning("Could not update archive index")

    def files(self) -> list[ArchiveFile]:
        with self._lock:
            return list(self._files)

    def total_bytes(self) -> int:
        with self._lock:
            return sum(f.size for f in self._files)

    # ---------------------------------------------------------------- writing
    def append(self, rows: Sequence[Sequence], target_bytes: int) -> None:
        """Durably append rows (in ``columns`` order, oldest first)."""
        if not rows:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        index = self.columns.index("received_at")
        current = self._open_for_append(rows[0][index], target_bytes)
        offset, length = current.write(b"".join(encode_row(self.columns, row) for row in rows))
        times = [row[index] for row in rows]
        entry = current.entry
        first = min(times) if not entry.count else min(entry.first_ms, *times)
        current.entry = replace(
            entry, first_ms=first, last_ms=max(entry.last_ms, *times), count=entry.count + len(rows),
            size=offset + length,
            segments=[*entry.segments, [offset, length, min(times), max(times), len(rows)]])
        with self._lock:
            self._files[-1] = current.entry
        if current.entry.size >= target_bytes:
            self.finish()

    def _open_for_append(self, first_ms: int, target_bytes: int) -> _OpenFile:
        if self._current is not None:
            return self._current
        with self._lock:
            last = self._files[-1] if self._files else None
            if last is not None and last.name.endswith(SUFFIX) and last.size < target_bytes:
                entry = last
            else:
                name = _file_name(first_ms)
                suffix = 1
                while (self.directory / name).exists():
                    name = _file_name(first_ms).replace(SUFFIX, f"-{suffix}{SUFFIX}")
                    suffix += 1
                entry = ArchiveFile(name, first_ms, first_ms, 0, 0)
                self._files.append(entry)
        self._current = _OpenFile(self.directory / entry.name, entry)
        return self._current

    def finish(self) -> None:
        """Close the current file and persist the index."""
        current, self._current = self._current, None
        if current is None:
            return
        try:
            current.close()
        finally:
            entry = current.entry
            entry = replace(entry, size=current.path.stat().st_size)
            with self._lock:
                self._files = [entry if f.name == entry.name else f for f in self._files]
            self._write_index()

    def enforce_budget(self, budget_bytes: int) -> int:
        """Delete the oldest files while the archive exceeds its budget; returns removed events."""
        self.finish()
        removed = 0
        with self._lock:
            files = list(self._files)
        total = sum(f.size for f in files)
        while files and total > budget_bytes:
            oldest = files[0]
            try:
                (self.directory / oldest.name).unlink(missing_ok=True)
            except PermissionError:  # opened by a viewer; try again later
                log.info("Archive %s is in use; deleting it later", oldest.name)
                break
            files.pop(0)
            total -= oldest.size
            removed += oldest.count
            log.info("Archive budget: deleted %s (%d events)", oldest.name, oldest.count)
        if removed:
            with self._lock:
                self._files = files
            self._write_index()
        return removed

    def close(self) -> None:
        self.finish()


def load_parts(directory: Path, parts: Sequence[tuple[str, int, int]], conn: sqlite3.Connection,
               columns: Sequence[str], *, insert: Callable[[sqlite3.Connection, Iterable[tuple]], None],
               progress: Callable[[int, int], bool] | None = None) -> int:
    """Copy the events of archive parts ``(file name, offset, length)`` into ``conn``;
    ``progress(read_bytes, total_bytes)`` returning False cancels. Returns the event count."""
    sizes = [length if length >= 0 else (directory / name).stat().st_size for name, _, length in parts]
    total = sum(sizes)
    done = loaded = 0
    for (name, offset, length), size in zip(parts, sizes):
        with open(directory / name, "rb") as raw:
            if length >= 0:
                raw.seek(offset)
                source = io.BytesIO(raw.read(length))
            else:
                source = raw
            batch: list[tuple] = []
            for line in _lines(source, name):
                try:
                    batch.append(decode_row(columns, line))
                except (ValueError, TypeError):
                    continue
                if len(batch) >= LOAD_BATCH:
                    insert(conn, batch)
                    loaded += len(batch)
                    batch = []
                    if progress is not None and not progress(done + min(source.tell(), size), total):
                        return loaded
            if batch:
                insert(conn, batch)
                loaded += len(batch)
        done += size
    if progress is not None:
        progress(total, total)
    return loaded


def load_into_database(path: Path, conn: sqlite3.Connection, columns: Sequence[str], *,
                       insert: Callable[[sqlite3.Connection, Iterable[tuple]], None],
                       progress: Callable[[int, int], bool] | None = None) -> int:
    """Copy all events of one archive file into ``conn``."""
    return load_parts(path.parent, [(path.name, 0, -1)], conn, columns, insert=insert,
                      progress=progress)
