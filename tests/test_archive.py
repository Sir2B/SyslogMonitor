import gzip
import lzma
import sqlite3

from conftest import BASE_MS, make_event

from syslog_monitor.archive import (
    Archive, archive_dir, decode_row, encode_row, file_target_bytes, iter_lines, load_into_database,
    read_index,
)
from syslog_monitor.query import EventFilter, QueryRunner
from syslog_monitor.storage import EVENT_COLUMNS, EventStore, insert_rows, open_database

DAY = 86_400_000


def messages(path):
    return [r.message for r in QueryRunner(path).fetch_older(EventFilter(), None, 100_000)]


def archived_messages(data_dir):
    index = EVENT_COLUMNS.index("message")
    return [decode_row(EVENT_COLUMNS, line)[index]
            for entry in read_index(archive_dir(data_dir))
            for line in iter_lines(archive_dir(data_dir) / entry.name)]


def test_row_roundtrip_keeps_binary_raw():
    row = tuple(range(len(EVENT_COLUMNS) - 1)) + (b"\xff\x00bin",)
    assert decode_row(EVENT_COLUMNS, encode_row(EVENT_COLUMNS, row)) == row
    text = tuple(range(len(EVENT_COLUMNS) - 1)) + ("<13>Grüße".encode(),)
    assert decode_row(EVENT_COLUMNS, encode_row(EVENT_COLUMNS, text)) == text


def test_expired_events_are_archived_instead_of_deleted(tmp_path):
    store = EventStore(tmp_path)
    store.insert([make_event(-40 * DAY, message="ancient"), make_event(-35 * DAY, message="old"),
                  make_event(0, message="now")])
    assert store.apply_retention(BASE_MS, 30, 2**30, 2**30) == 2
    assert messages(store.path) == ["now"]
    assert archived_messages(tmp_path) == ["ancient", "old"]
    [entry] = read_index(archive_dir(tmp_path))
    assert (entry.count, entry.first_ms, entry.last_ms) == (2, BASE_MS - 40 * DAY, BASE_MS - 35 * DAY)
    assert store.usage().archive_bytes == entry.size > 0
    store.close()


def test_age_retention_waits_for_a_chunk(tmp_path):
    store = EventStore(tmp_path)
    store.insert([make_event(-30 * DAY - 1000, message="just expired"), make_event(0)])
    # Only a few hours overdue: wait until at least a day (10 % of 30 days = 3 days) is due.
    assert store.apply_retention(BASE_MS, 30, 2**30, 2**30) == 0
    assert store.apply_retention(BASE_MS + 4 * DAY, 30, 2**30, 2**30) == 1
    assert archived_messages(tmp_path) == ["just expired"]
    store.close()


def test_without_archive_budget_events_are_deleted(tmp_path):
    store = EventStore(tmp_path)
    store.insert([make_event(-40 * DAY), make_event(0)])
    assert store.apply_retention(BASE_MS, 30, 2**30, 0) == 1
    assert read_index(archive_dir(tmp_path)) == []
    store.close()


def test_budget_overflow_is_archived_and_appended_to_the_same_file(tmp_path):
    store = EventStore(tmp_path)
    payload = "x" * 2000
    for chunk in range(10):
        store.insert([make_event(chunk * 1000 + i, message=f"{payload} n{chunk}_{i}") for i in range(500)])
    budget = store.usage().used_bytes // 2
    deleted = store.apply_retention(BASE_MS, 3650, budget, 2**30)
    store.insert([make_event(20_000 + i, message=f"{payload} m{i}") for i in range(2000)])
    deleted += store.apply_retention(BASE_MS, 3650, budget, 2**30)
    archived = archived_messages(tmp_path)
    assert len(archived) == deleted > 0
    assert archived[0].endswith("n0_0")
    assert len(read_index(archive_dir(tmp_path))) == 1
    assert set(archived).isdisjoint(messages(store.path))
    store.close()


def test_new_file_when_target_size_is_reached(tmp_path):
    archive = Archive(tmp_path, EVENT_COLUMNS)
    rows = [(BASE_MS + i, "10.0.0.1", 514, 1, 6, "rfc3164", "", None, None, "h", "a", None, None,
             None, f"message {i} " + "y" * 200, b"raw") for i in range(3000)]
    archive.append(rows[:1000], target_bytes=1)
    archive.append(rows[1000:2000], target_bytes=1)
    archive.finish()
    files = read_index(archive_dir(tmp_path))
    assert [f.count for f in files] == [1000, 1000]
    assert files[0].last_ms < files[1].first_ms


def test_archive_budget_deletes_oldest_files(tmp_path):
    archive = Archive(tmp_path, EVENT_COLUMNS)
    for part in range(3):
        archive.append([(BASE_MS + part * 1000 + i, "10.0.0.1", 514, 1, 6, "rfc3164", "", None, None,
                         "h", "a", None, None, None, f"p{part} {i}", b"r") for i in range(100)], 1)
    files = archive.files()
    removed = archive.enforce_budget(files[1].size + files[2].size)
    assert removed == 100
    assert [f.name for f in read_index(archive_dir(tmp_path))] == [f.name for f in files[1:]]


def test_truncated_file_is_readable_and_reindexed(tmp_path):
    archive = Archive(tmp_path, EVENT_COLUMNS)
    archive.append([(BASE_MS + i, "10.0.0.1", 514, 1, 6, "rfc3164", "", None, None, "h", "a",
                     None, None, None, f"m{i}", b"r") for i in range(50)], 2**30)
    # Simulate a crash: sync-flushed member without gzip trailer, index never written.
    archive._current.raw.close()
    archive._current = None
    (archive_dir(tmp_path) / "index.json").unlink(missing_ok=True)
    [entry] = Archive(tmp_path, EVENT_COLUMNS).files()
    assert entry.count == 50


def test_load_into_viewer_database(tmp_path):
    store = EventStore(tmp_path / "live")
    store.insert([make_event(-40 * DAY + i, message=f"archived {i}") for i in range(12_000)])
    store.apply_retention(BASE_MS, 30, 2**30, 2**30)
    store.close()
    [entry] = read_index(archive_dir(tmp_path / "live"))
    conn = open_database(tmp_path / "view")
    seen = []
    count = load_into_database(archive_dir(tmp_path / "live") / entry.name, conn, EVENT_COLUMNS,
                               insert=insert_rows, progress=lambda done, total: seen.append(done) or True)
    conn.close()
    assert count == 12_000 and seen[-1] == entry.size
    runner = QueryRunner(tmp_path / "view" / "syslog.sqlite3")
    assert runner.fetch_older(EventFilter(), None, 1)[0].message == "archived 11999"
    fts = sqlite3.connect(tmp_path / "view" / "syslog.sqlite3")
    assert fts.execute("SELECT count(*) FROM events_fts WHERE events_fts MATCH '11999'").fetchone()[0] == 1
    fts.close()


def test_file_target_size():
    assert file_target_bytes(2**30, 4 * 2**30) == 2**30 // 80
    assert file_target_bytes(2**30, 100 * 2**20) == 5 * 2**20
    assert file_target_bytes(64 * 2**20, 16 * 2**20) == 2**20


def test_archive_files_are_plain_xz(tmp_path):
    archive = Archive(tmp_path, EVENT_COLUMNS)
    archive.append([(BASE_MS, "10.0.0.1", 514, 1, 6, "rfc3164", "", None, None, "h", "a", None, None,
                     None, "hello", b"<14>hello")], 2**30)
    archive.append([(BASE_MS + 1, "10.0.0.1", 514, 1, 6, "rfc3164", "", None, None, "h", "a", None,
                     None, None, "world", b"<14>world")], 2**30)
    archive.finish()
    [entry] = archive.files()
    text = lzma.decompress((archive_dir(tmp_path) / entry.name).read_bytes()).decode()
    assert '"message":"hello"' in text and '"message":"world"' in text


def test_legacy_gzip_files_stay_readable_and_are_not_appended(tmp_path):
    from syslog_monitor.archive import encode_row
    row = (BASE_MS, "10.0.0.1", 514, 1, 6, "rfc3164", "", None, None, "h", "a", None, None, None,
           "legacy", b"r")
    directory = archive_dir(tmp_path)
    directory.mkdir(parents=True)
    (directory / "syslog-old.jsonl.gz").write_bytes(gzip.compress(encode_row(EVENT_COLUMNS, row)))
    archive = Archive(tmp_path, EVENT_COLUMNS)
    archive.append([row[:14] + ("new", b"r")], 2**30)
    archive.finish()
    names = [f.name for f in archive.files()]
    assert names[0] == "syslog-old.jsonl.gz" and names[1].endswith(".jsonl.xz")
    assert archived_messages(tmp_path) == ["legacy", "new"]