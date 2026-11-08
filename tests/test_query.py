import re
from dataclasses import replace

import pytest

from conftest import BASE_MS, make_event

from syslog_monitor.events import SeverityClass
from syslog_monitor.matching import (
    MatchOptions, like_pattern, match_error, message_regex, regex_matches, text_matches,
)
from syslog_monitor.query import (
    TEXT_MODE_SUBSTRING, EventFilter, FilterRule, HighlightRule, QueryRunner,
    active_highlights, build_where, fts_query, highlight_matches, matching_highlight, parse_highlights,
)

def test_negative_rules_and_boolean_group_apply_everywhere(store):
    q = fill(store, [
        make_event(0, message="heartbeat", app_name="web"),
        make_event(1, message="disk error", app_name="db"),
        make_event(2, message="login", app_name=None, hostname=None),
        make_event(3, message="50%_done", app_name="web"),
    ])
    rules = (FilterRule("message", "not_contains", "heartbeat"),
             FilterRule("app", "equals", "WEB"))
    f = EventFilter(rules=rules)
    assert [r.message for r in q.fetch_older(f, None, 20)] == ["50%_done"]
    assert q.time_bounds(f) == (BASE_MS + 3, BASE_MS + 3)
    assert q.histogram(f, BASE_MS, BASE_MS + 4, 4).total == 1
    assert q.find_match(f, "heartbeat", TEXT_MODE_SUBSTRING) is None
    assert q.find_match(f, "done", TEXT_MODE_SUBSTRING).message == "50%_done"
    assert q.fetch_context(f, (BASE_MS + 3, 4), 10, 10)[1][0].message == "50%_done"
    union = EventFilter(rules=rules, rules_match="any")
    assert len(q.fetch_older(union, None, 20)) == 4
    # Basic filters are ANDed with the entire OR group, including the time range.
    assert [r.message for r in q.fetch_older(
        union.with_time(BASE_MS + 1, BASE_MS + 2), None, 20)] == ["disk error"]
    absent = EventFilter(rules=(FilterRule("app", "not_equals", "web"),))
    assert {r.message for r in q.fetch_older(absent, None, 20)} == {"disk error", "login"}
    literal = EventFilter(rules=(FilterRule("message", "contains", "%_"),))
    assert [r.message for r in q.fetch_older(literal, None, 20)] == ["50%_done"]
    injection = EventFilter(rules=(FilterRule("message", "contains", "' OR 1=1 --"),))
    assert q.fetch_older(injection, None, 20) == []
    empty = EventFilter(rules=(FilterRule(value=" "),), rules_match="any")
    assert len(q.fetch_older(empty, None, 20)) == 4
    q.close()


def fill(store, events):
    store.insert(events)
    return QueryRunner(store.path)


@pytest.mark.parametrize(("left", "right", "similar"), [
    ("temperature=24.3C load=1", "temperature=-9.75C load=100", True),
    ("eth1: errors 2", "eth20: errors 8", True),
    ("range 1-5", "range 10-20", True),
    ("disk full", "disk FULL", False),
    ("port 1 up", "port 2 down", False),
    ("code {number}", "code 42", False),
    ("hello", "hello 1", False),
    ("code 1", "code 1 2", False),
    ("100%_done", "200%_done", True),
    ("a.b (1) [x]", "a.b (22) [x]", True),
    ("a.b (1) [x]", "axb (1) [x]", False),
    ("line 1\nnext", "line 2\nnext", True),
])
def test_message_regex_varies_only_numbers(left, right, similar):
    assert regex_matches(message_regex(left), left)
    assert regex_matches(message_regex(left), right) == similar


def test_message_regex_is_readable():
    assert message_regex("temp=24.3 (max 30)") == r"^temp=-?\d+(?:\.\d+)? \(max -?\d+(?:\.\d+)?\)$"
    assert message_regex("plain text") == "^plain text$"


def test_graph_bucket_sizes_are_round_and_bounded():
    from syslog_monitor.query import GRAPH_MAX_BUCKETS, graph_bucket_ms

    assert graph_bucket_ms(1_000) == 1_000
    assert graph_bucket_ms(3_600_000) == 60_000
    assert graph_bucket_ms(24 * 3_600_000) == 1_800_000
    huge = 1000 * 86_400_000 * 7
    assert huge / graph_bucket_ms(huge) <= GRAPH_MAX_BUCKETS


def test_message_statistics_exact_similar_scope_and_empty_hours(store):
    hour = 3_600_000
    q = fill(store, [
        make_event(0, message="other traffic"),
        make_event(hour, message="temperature=24.3"),
        make_event(hour + 1, message="temperature=24.3"),
        make_event(hour + 2, message="temperature=99.5"),
        make_event(hour + 3, message="temperature=99.5", source_ip="192.0.2.2"),
        make_event(hour + 4, message="temperature=99.5", app_name="other"),
        make_event(hour + 5, message="Temperature=24.3"),
        make_event(2 * hour, message="temperature=24.3"),
    ])
    try:
        row = q.fetch_older(EventFilter(end_ms=BASE_MS + 2 * hour), None, 10)[-2]
        assert row.message == "temperature=24.3"
        stats = q.message_statistics(
            EventFilter(start_ms=BASE_MS, end_ms=BASE_MS + 2 * hour), row, BASE_MS + 3 * hour)
        assert stats.exact.count == 2 and stats.similar.count == 3
        assert (stats.exact.per_hour, stats.exact.deviation) == pytest.approx((1, 1))
        assert (stats.similar.per_hour, stats.similar.deviation) == pytest.approx((1.5, 1.5))
        filtered = q.message_statistics(
            EventFilter(start_ms=BASE_MS, end_ms=BASE_MS + 2 * hour,
                        rules=(FilterRule("message", "equals", "temperature=99.5"),)),
            row, BASE_MS + 3 * hour)
        assert filtered.exact.count == 0 and filtered.similar.count == 1
        assert stats.regex == r"^temperature=-?\d+(?:\.\d+)?$"
        assert stats.bucket_ms == 300_000 and len(stats.similar.series) == 24
        assert stats.exact.series[12] == 2 and stats.similar.series[12] == 3
        assert sum(stats.similar.series) == stats.similar.count
        custom = q.message_statistics(
            EventFilter(start_ms=BASE_MS, end_ms=BASE_MS + 2 * hour), row, BASE_MS + 3 * hour,
            r"(?i)^temperature=99")
        assert custom.custom_regex and custom.regex == r"(?i)^temperature=99"
        assert custom.exact.count == 2 and custom.similar.count == 1
        assert sum(custom.exact.series) == 2
        with pytest.raises(re.error):
            q.message_statistics(EventFilter(), row, BASE_MS, "(")
    finally:
        q.close()


def test_message_statistics_partial_hours_null_app_and_open_start(store):
    hour = 3_600_000
    q = fill(store, [
        make_event(0, message="boot", app_name=None),
        make_event(hour // 4, message="value 1", app_name=None),
        make_event(hour, message="value 2", app_name=None),
    ])
    try:
        row = q.fetch_older(EventFilter(), None, 1)[0]
        stats = q.message_statistics(EventFilter(), row, BASE_MS + hour + hour // 2)
        assert stats.start_ms == BASE_MS
        assert stats.similar.count == 2
        assert stats.similar.per_hour == pytest.approx(2 / 1.5)
        assert stats.similar.deviation == pytest.approx((2 - (2 / 1.5) ** 2) ** 0.5)
        instant = q.message_statistics(
            EventFilter(start_ms=BASE_MS + hour, end_ms=BASE_MS + hour + 1),
            row, BASE_MS + hour + 1)
        assert instant.exact.count == 1 and instant.exact.per_hour == 3600
    finally:
        q.close()


def test_message_statistics_count_beyond_loaded_page_and_clamp_future_end(store):
    q = fill(store, [make_event(i, message=f"value={i}%_") for i in range(5001)])
    try:
        row = q.fetch_older(EventFilter(), None, 1)[0]
        stats = q.message_statistics(
            EventFilter(start_ms=BASE_MS, end_ms=BASE_MS + 4 * 3_600_000),
            row, BASE_MS + 2 * 3_600_000)
        assert stats.end_ms == BASE_MS + 2 * 3_600_000
        assert stats.exact.count == 1
        assert stats.similar.count == 5001
        assert stats.similar.per_hour == pytest.approx(2500.5)
        assert q.count(EventFilter()) == 5001
    finally:
        q.close()


def test_fts_query_is_safe():
    assert fts_query('foo "bar" OR NEAR(x)') == '"foo"* "bar"* "OR"* "NEAR"* "x"*'
    assert fts_query("!!!") is None


def test_like_pattern_escapes_wildcards():
    assert like_pattern("50%_a\\b") == "%50\\%\\_a\\\\b%"


def test_required_rules_and_word_rules_keep_parameter_order(store):
    q = fill(store, [
        make_event(0, message="disk failure", app_name="web"),
        make_event(1, message="disk failure", app_name="db"),
        make_event(2, message="disk okay", app_name="web"),
        make_event(3, message="disk failure", app_name="excluded"),
    ])
    f = EventFilter(rules=(
        FilterRule("app", "equals", "web"),
        FilterRule("text", "words", "disk fail", required=True),
        FilterRule("app", "equals", "db"),
        FilterRule("app", "not_equals", "excluded", required=True),
    ), rules_match="any")
    assert {r.app_name for r in q.fetch_older(f, None, 10)} == {"web", "db"}
    negative = EventFilter(rules=(FilterRule("text", "not_words", "disk fail"),))
    assert [r.message for r in q.fetch_older(negative, None, 10)] == ["disk okay"]
    q.close()


def test_highlight_histogram_preserves_counts_and_filters(store):
    q = fill(store, [
        make_event(0, message="Initializing system", severity=7),
        make_event(1, message="INITIALIZING SYSTEM ready", severity=6),
        make_event(2, message="unrelated", severity=3),
        make_event(3, message="50%_done", severity=7),
    ])
    hist = q.histogram(EventFilter(), BASE_MS, BASE_MS + 4, 4, "Initializing system")
    assert hist.total == 4
    assert hist.highlights == [1, 1, 0, 0]
    assert hist.class_total(SeverityClass.DEBUG) == 2
    assert q.histogram(EventFilter(severities=frozenset({6})),
                       BASE_MS, BASE_MS + 4, 4, "Initializing system").highlights == [0, 1, 0, 0]
    assert q.histogram(EventFilter(), BASE_MS + 1, BASE_MS + 2, 1,
                       "Initializing system").highlights == [1]
    assert q.histogram(EventFilter(), BASE_MS, BASE_MS + 4, 4, "%_").highlights == [0, 0, 0, 1]
    assert q.histogram(EventFilter(), BASE_MS, BASE_MS + 4, 4, " ").highlights == [0] * 4
    assert q.histogram(EventFilter(), BASE_MS, BASE_MS + 4, 4,
                       "unrelated; %_ ;initializing system").highlights == [1, 1, 1, 1]
    assert q.histogram(EventFilter(), BASE_MS, BASE_MS + 4, 4, " ; ;").highlights == [0] * 4
    q.close()


def test_highlight_hourly_statistics_include_empty_hours_and_ignore_minimap_resolution(store):
    hour = 3_600_000
    q = fill(store, [make_event(hour + i, message="match", severity=3) for i in range(4)]
             + [make_event(2 * hour, message="match", severity=3)])
    try:
        for buckets in (1, 7, 100):
            hist = q.histogram(EventFilter(), BASE_MS, BASE_MS + 2 * hour, buckets,
                               (HighlightRule("match"), HighlightRule("match"), HighlightRule("absent")))
            assert hist.total == 4  # End boundary is exclusive.
            assert hist.highlight_hourly_counts == [{1: 4}, {}, {}]
            assert hist.highlight_hourly_statistics(0) == pytest.approx((2.0, 2.0))
            assert hist.highlight_hourly_statistics(1) == (0.0, 0.0)
            assert hist.highlight_hourly_statistics(2) == (0.0, 0.0)
        filtered = q.histogram(EventFilter(severities=frozenset({7})), BASE_MS,
                               BASE_MS + 2 * hour, 2, "match")
        assert filtered.highlight_hourly_statistics(0) == (0.0, 0.0)
    finally:
        q.close()


def test_highlight_hourly_statistics_weight_partial_hours(store):
    hour = 3_600_000
    q = fill(store, [make_event(0, message="match"), make_event(1, message="match"),
                     make_event(hour, message="match")])
    try:
        hist = q.histogram(EventFilter(), BASE_MS, BASE_MS + hour + hour // 2, 3, "match")
        assert hist.highlight_hourly_statistics(0) == pytest.approx((2.0, 0.0))
        short = q.histogram(EventFilter(), BASE_MS, BASE_MS + hour // 2, 1, "match")
        assert short.highlight_hourly_statistics(0) == pytest.approx((4.0, 0.0))
    finally:
        q.close()


def test_parse_and_match_multiple_highlights():
    assert parse_highlights(" a ;b;; A ;") == ("a", "b")
    assert parse_highlights("") == ()
    assert highlight_matches("Watchdog RESET", "foo; watchdog")
    assert not highlight_matches("nothing", "foo; bar")
    assert not highlight_matches("anything", " ; ")


def test_colored_highlights_first_active_match_wins(store):
    rules = (HighlightRule("disabled", "#000000", False), HighlightRule(" ; "),
             HighlightRule("boot; 50%_", "#ff0000"), HighlightRule("ready", "#00ff00"))
    q = fill(store, [
        make_event(0, message="BOOT ready", severity=3),
        make_event(1, message="ready", severity=6),
        make_event(2, message="disabled", severity=7),
        make_event(3, message="50%_", severity=6),
        make_event(4, message="50xx", severity=7),
    ])
    hist = q.histogram(EventFilter(), BASE_MS, BASE_MS + 5, 1, rules)
    assert hist.total == 5
    assert hist.highlights == [3]  # overlap is counted once
    assert hist.highlight_rules == active_highlights(rules) == (rules[2], rules[3])
    assert hist.highlight_counts == [[2, 1]]
    for message in ("BOOT ready", "ready", "disabled", "50%_", "50xx"):
        expected = matching_highlight(message, rules)
        filtered = q.histogram(EventFilter(rules=(FilterRule("message", "equals", message),)),
                               BASE_MS, BASE_MS + 5, 1, rules)
        assert filtered.highlights == [int(expected is not None)]
        if expected:
            assert filtered.highlight_counts[0][filtered.highlight_rules.index(expected)] == 1
    reversed_hist = q.histogram(EventFilter(), BASE_MS, BASE_MS + 5, 1, tuple(reversed(rules)))
    assert reversed_hist.highlight_counts == [[2, 1]]
    assert reversed_hist.highlight_rules[0].text == "ready"
    assert q.histogram(EventFilter(), BASE_MS, BASE_MS + 5, 1, ()).highlight_counts == [[]]
    q.close()


def test_highlight_rule_rejects_invalid_persisted_values():
    import pytest

    for kwargs in ({"color": "red"}, {"color": "#fff"}, {"text": None},
                   {"enabled": "false"}, {"popup": "false"}, {"color": None}):
        with pytest.raises(ValueError):
            HighlightRule(**kwargs)
    assert HighlightRule().popup


def test_new_highlights_since_id_ignores_view_filter(store):
    q = fill(store, [
        make_event(0, message="Initializing system", severity=7),
        make_event(1, message="ok"),
    ])
    start = q.max_id()
    assert q.new_highlights(start, "Initializing system", 3) == (start, 0, [])
    store.insert([make_event(2, message="initializing system again"),
                        make_event(3, message="noise"),
                        make_event(4, message="Watchdog fired"),
                        make_event(5, message="watchdog 2")])
    batch = q.new_highlights(start, "Initializing system; watchdog", 2)
    assert batch.last_id == start + 4 and batch.count == 3
    assert [r.message for r in batch.rows] == ["watchdog 2", "Watchdog fired"]
    assert q.new_highlights(batch.last_id, "watchdog", 2).count == 0
    assert q.new_highlights(start, "", 2) == (start + 4, 0, [])
    q.close()


def test_paging_is_stable_with_equal_timestamps(store):
    events = [make_event(i // 3, message=f"m{i}") for i in range(10)]  # 3 per ms
    q = fill(store, events)
    f = EventFilter()
    seen, cursor = [], None
    while page := q.fetch_older(f, cursor, 4):
        seen += page
        cursor = page[-1].cursor
    assert [r.message for r in seen] == [f"m{i}" for i in reversed(range(10))]
    newer = q.fetch_newer(f, seen[5].cursor, 2)
    assert [r.message for r in newer] == [seen[3].message, seen[4].message]
    assert q.count_newer(f, seen[5].cursor, 100) == 5
    assert q.count_newer(f, seen[5].cursor, 3) == 3
    assert q.count_newer(f, seen[0].cursor, 100) == 0
    assert q.count_newer(f, None, 100) == 10
    assert q.count_newer(EventFilter(text="m1"), None, 100) == 1


def test_newer_queries_preserve_time_bounds_and_equal_timestamp_rows(store):
    q = fill(store, [make_event(i // 3, message=f"m{i}") for i in range(12)])
    try:
        rows = q.fetch_older(EventFilter(), None, 20)
        cursor = rows[7].cursor
        for start, end in ((None, None), (BASE_MS, BASE_MS + 3),
                           (BASE_MS + 2, None), (None, BASE_MS + 1)):
            f = EventFilter(start_ms=start, end_ms=end)
            expected = [row for row in reversed(rows) if row.cursor > cursor
                        and (start is None or row.received_at >= start)
                        and (end is None or row.received_at < end)]
            assert q.fetch_newer(f, cursor, 3) == list(reversed(expected[:3]))
            assert q.count_newer(f, cursor, 3) == min(3, len(expected))
    finally:
        q.close()


def test_empty_newer_queries_do_not_scan_the_selected_time_range(store):
    q = fill(store, [make_event(i, message=f"m{i}") for i in range(5000)])
    try:
        f = EventFilter(start_ms=BASE_MS, end_ms=BASE_MS + 6000)
        cursor = q.fetch_older(f, None, 1)[0].cursor
        steps = []
        q._conn.set_progress_handler(lambda: steps.append(1) or 0, 1)
        assert q.fetch_newer(f, cursor, 1000) == []
        assert q.count_newer(f, cursor, 10_000) == 0
        assert len(steps) < 1000
    finally:
        q._conn.set_progress_handler(None, 0)
        q.close()


def test_combined_filters(store):
    q = fill(store, [
        make_event(0, severity=3, source_ip="192.0.2.1", app_name="sshd", message="login failed"),
        make_event(1, severity=6, source_ip="192.0.2.2", app_name="sshd", message="login ok"),
        make_event(2, severity=3, source_ip="192.0.2.2", app_name="cron", message="job failed"),
        make_event(3, severity=None, facility=None, source_ip="192.0.2.3", hostname="sw1", message="raw"),
    ])
    msgs = lambda f: {r.message for r in q.fetch_older(f, None, 100)}  # noqa: E731
    assert msgs(EventFilter(severities=frozenset({3}))) == {"login failed", "job failed"}
    assert msgs(EventFilter(severities=frozenset({None}))) == {"raw"}
    assert msgs(EventFilter(severities=frozenset())) == set()
    assert msgs(EventFilter(sender="0.2.2")) == {"login ok", "job failed"}
    assert msgs(EventFilter(sender="SW1")) == {"raw"}  # host name, ASCII case-insensitive
    assert msgs(EventFilter(app="ssh", severities=frozenset({3}))) == {"login failed"}
    assert msgs(EventFilter(text="failed")) == {"login failed", "job failed"}
    assert msgs(EventFilter(text="fail")) == {"login failed", "job failed"}  # prefix
    assert msgs(EventFilter(text="login fail")) == {"login failed"}
    assert msgs(EventFilter(start_ms=BASE_MS + 1, end_ms=BASE_MS + 3)) == {"login ok", "job failed"}
    assert msgs(EventFilter(facility=1, severities=frozenset({6}))) == {"login ok"}


def test_text_search_unicode_and_punctuation(store):
    q = fill(store, [
        make_event(0, message="Café server overload"),
        make_event(1, message="error: 50% done (code_17)"),
        make_event(2, message="unrelated"),
    ])
    msgs = lambda f: [r.message for r in q.fetch_older(f, None, 100)]  # noqa: E731
    assert msgs(EventFilter(text="café")) == ["Café server overload"]
    assert msgs(EventFilter(text="cafe")) == ["Café server overload"]  # diacritics removed
    assert msgs(EventFilter(text='"error" 50')) == ["error: 50% done (code_17)"]
    assert msgs(EventFilter(text="50%", text_mode=TEXT_MODE_SUBSTRING)) == ["error: 50% done (code_17)"]
    assert msgs(EventFilter(text="e_1", text_mode=TEXT_MODE_SUBSTRING)) == ["error: 50% done (code_17)"]
    assert msgs(EventFilter(text="e%1", text_mode=TEXT_MODE_SUBSTRING)) == []
    assert msgs(EventFilter(text="   ")) == msgs(EventFilter())


def test_fetch_around(store):
    q = fill(store, [make_event(i * 1000, message=str(i)) for i in range(10)])
    newer, older = q.fetch_around(EventFilter(), BASE_MS + 4500, before=3, after=2)
    assert [r.message for r in newer] == ["6", "5"]
    assert [r.message for r in older] == ["4", "3", "2"]
    newer, older = q.fetch_around(EventFilter(), BASE_MS - 1, before=3, after=2)
    assert [r.message for r in newer] == ["1", "0"] and older == []


def test_histogram_buckets_and_consistency_with_list(store):
    q = fill(store, [
        make_event(0, severity=3), make_event(10, severity=4), make_event(15, severity=6),
        make_event(99, severity=7), make_event(50, severity=None, facility=None),
        make_event(100, severity=3),  # outside [0, 100)
    ])
    hist = q.histogram(EventFilter(), BASE_MS, BASE_MS + 100, 4)
    assert hist.counts[0][SeverityClass.ERROR] == 1
    assert hist.counts[0][SeverityClass.WARNING] == 1
    assert hist.counts[0][SeverityClass.INFO] == 1
    assert hist.counts[2][SeverityClass.UNKNOWN] == 1
    assert hist.counts[3][SeverityClass.DEBUG] == 1
    assert hist.total == 5
    f = EventFilter(severities=frozenset({3, 4}))
    in_range = q.fetch_older(f.with_time(BASE_MS, BASE_MS + 100), None, 100)
    assert q.histogram(f, BASE_MS, BASE_MS + 100, 7).total == len(in_range) == 2


def test_get_event_roundtrip(store):
    ev = make_event(5, message="detail")
    ev.issues = ("no_timestamp", "invalid_utf8")
    ev.structured_data = '[x@1 a="b"]'
    q = fill(store, [ev])
    row = q.fetch_older(EventFilter(), None, 1)[0]
    loaded = q.get_event(row.id)
    assert loaded.message == "detail" and loaded.raw == b"detail"
    assert loaded.issues == ("no_timestamp", "invalid_utf8")
    assert loaded.structured_data == '[x@1 a="b"]'
    assert q.get_event(99999) is None
    assert q.time_bounds() == (BASE_MS + 5, BASE_MS + 5)


def test_find_match_keeps_filter_and_uses_exact_cursor(store):
    q = fill(store, [
        make_event(0, message="keep needle old"),
        make_event(0, message="keep context"),
        make_event(0, message="keep needle new"),
        make_event(0, message="needle excluded by text filter"),
        make_event(1, severity=3, message="keep needle excluded by severity"),
    ])
    f = EventFilter(text="keep", severities=frozenset({6}))
    new = q.find_match(f, "needle", "words")
    assert new.message == "keep needle new"
    old = q.find_match(f, "needle", "words", new.cursor)
    assert old.message == "keep needle old"
    assert q.find_match(f, "needle", "words", old.cursor) is None
    assert q.find_match(f, "needle", "words", old.cursor, newer=True) == new
    assert q.find_match(f, "needle", "words", new.cursor, newer=True) is None
    newer, older = q.fetch_context(f, new.cursor, 10, 10)
    assert newer == []
    assert [r.message for r in older] == ["keep needle new", "keep context", "keep needle old"]
    newer, older = q.fetch_context(f, old.cursor, 10, 10)
    assert [r.message for r in newer] == ["keep needle new", "keep context"]
    assert older == [old]


def test_find_match_modes_empty_and_no_result(store):
    q = fill(store, [make_event(message="Café: code_17 (50%)")])
    assert q.find_match(EventFilter(), "cafe", "words").message.startswith("Café")
    assert q.find_match(EventFilter(), "e_17 (50%)", TEXT_MODE_SUBSTRING) is not None
    assert q.find_match(EventFilter(), "e%17", TEXT_MODE_SUBSTRING) is None
    for text in ("", "  ", "!!!", "missing"):
        assert q.find_match(EventFilter(), text, "words") is None


def test_find_highlight_match_steps_through_separated_terms(store):
    q = fill(store, [
        make_event(0, message="first alarm", app_name="wanted"),
        make_event(1, message="context", app_name="wanted"),
        make_event(2, message="second needle", app_name="wanted"),
        make_event(3, message="not a message match", hostname="alarm-host", app_name="wanted"),
        make_event(4, message="excluded alarm", app_name="other"),
    ])
    f = EventFilter(rules=(FilterRule("app", "equals", "wanted"),))
    newest = q.find_highlight_match(f, "alarm; needle")
    assert newest.message == "second needle"
    older = q.find_highlight_match(f, "alarm; needle", newest.cursor)
    assert older.message == "first alarm"
    assert q.find_highlight_match(f, "alarm; needle", older.cursor) is None
    assert q.find_highlight_match(f, "alarm; needle", older.cursor, newer=True) == newest


MESSAGES = ("Error: disk sda1 failed", "error in errorlog", "user.name=bob", "Port 22 up",
            "port 220 down")


@pytest.mark.parametrize(("text", "options", "expected"), [
    ("error", MatchOptions(), {0, 1}),
    ("error", MatchOptions(case_sensitive=True), {1}),
    ("Error", MatchOptions(case_sensitive=True), {0}),
    ("error", MatchOptions(whole_word=True), {0, 1}),
    ("errorlog", MatchOptions(whole_word=True), {1}),
    ("rror", MatchOptions(whole_word=True), set()),
    ("port 22", MatchOptions(whole_word=True), {3}),
    ("user.name", MatchOptions(), {2}),
    ("user.name", MatchOptions(whole_word=True), {2}),
    ("user.name", MatchOptions(regex=True), {2}),
    (r"port \d{3}", MatchOptions(regex=True), {4}),
    (r"^port", MatchOptions(regex=True, case_sensitive=True), {4}),
    (r"sd[a-z]\d", MatchOptions(regex=True, whole_word=True), {0}),
    ("err|down", MatchOptions(regex=True, whole_word=True), {4}),
])
def test_match_options_sql_and_python_agree(store, text, options, expected):
    q = fill(store, [make_event(i, message=m) for i, m in enumerate(MESSAGES)])
    assert {i for i, m in enumerate(MESSAGES) if text_matches(m, text, options)} == expected
    rule = FilterRule("message", "contains", text, False, options.case_sensitive,
                      options.whole_word, options.regex)
    found = {r.message for r in q.fetch_older(EventFilter(rules=(rule,)), None, 20)}
    assert found == {MESSAGES[i] for i in expected}
    negated = replace(rule, operator="not_contains")
    assert {r.message for r in q.fetch_older(EventFilter(rules=(negated,)), None, 20)} == (
        set(MESSAGES) - found)
    highlight = HighlightRule(text, case_sensitive=options.case_sensitive,
                              whole_word=options.whole_word, regex=options.regex)
    assert {r.message for r in q.fetch_highlighted(EventFilter(), highlight, 20)} == found
    assert {m for m in MESSAGES if highlight_matches(m, highlight)} == found
    hit = q.find_match(EventFilter(), text, TEXT_MODE_SUBSTRING, options=options)
    assert (hit.message if hit else None) == max(found, key=MESSAGES.index, default=None)
    q.close()


def test_equals_with_match_options(store):
    q = fill(store, [make_event(0, message="Port 22 up"), make_event(1, message="port 22 up\n")])
    def matching(**options):
        rule = FilterRule("message", "equals", options.pop("value", "port 22 up"), **options)
        return {r.id for r in q.fetch_older(EventFilter(rules=(rule,)), None, 20)}
    assert matching() == {1}
    assert matching(value="PORT 22 UP") == {1}
    assert matching(case_sensitive=True, value="Port 22 up") == {1}
    assert matching(whole_word=True, value="port 22") == set()  # equals ignores whole word
    assert matching(regex=True, value=r"port \d+ up") == {1}  # \Z: no trailing newline
    assert matching(regex=True, value=r"port \d+ up\s") == {2}
    assert matching(regex=True, value=r"port \d+") == set()  # regex must match the whole value
    q.close()


def test_invalid_regex_rules_are_inactive_and_regex_is_not_split():
    assert match_error("a(b", MatchOptions(regex=True))
    assert match_error("a(b", MatchOptions()) is None
    assert match_error("a(b", MatchOptions(whole_word=True)) is None
    assert parse_highlights("a(b", MatchOptions(regex=True)) == ()
    assert parse_highlights("a;b", MatchOptions(regex=True)) == ("a;b",)
    assert parse_highlights("Foo;foo", MatchOptions(case_sensitive=True)) == ("Foo", "foo")
    assert active_highlights((HighlightRule("a(b", regex=True),)) == ()
    where, params = build_where(EventFilter(rules=(FilterRule(value="a(b", regex=True),)))
    assert (where, params) == ("1", [])
    where, _ = build_where(EventFilter(text="a(b", text_mode=TEXT_MODE_SUBSTRING,
                                       text_options=MatchOptions(regex=True)))
    assert where == "0"
    plain, plain_params = build_where(EventFilter(rules=(FilterRule(value="x"),)))
    assert "LIKE" in plain and plain_params == ["%x%"]  # default keeps the fast LIKE path
    words = FilterRule("text", "words", "x", regex=True)
    assert not words.uses_options and "events_fts" in build_where(EventFilter(rules=(words,)))[0]


def test_old_persisted_rules_get_default_match_options():
    assert FilterRule(**{"field": "message", "operator": "contains", "value": "x",
                         "required": False}).options == MatchOptions()
    assert HighlightRule(**{"text": "x", "color": "#000000", "enabled": True,
                            "popup": True}).options == MatchOptions()
    with pytest.raises(ValueError):
        FilterRule(regex="yes")
    with pytest.raises(ValueError):
        HighlightRule(whole_word=1)


def test_export_supports_regex_rules(tmp_path, store):
    from syslog_monitor.export import ExportOptions, export_events

    store.insert([make_event(0, message="port 22 up"), make_event(1, message="port x up")])
    options = ExportOptions(period="custom", filters=EventFilter(
        start_ms=BASE_MS, end_ms=BASE_MS + 10, rules=(FilterRule(value=r"port \d+", regex=True),)))
    target = tmp_path / "out.csv"
    export_events(store.path, target, options, now_ms=BASE_MS + 10)
    content = target.read_text(encoding="utf-8")
    assert "port 22 up" in content and "port x up" not in content


def test_filtered_time_bounds(store):
    q = fill(store, [
        make_event(0), make_event(100, severity=3), make_event(200, severity=3),
        make_event(300),
    ])
    assert q.time_bounds() == (BASE_MS, BASE_MS + 300)
    assert q.time_bounds(EventFilter(severities=frozenset({3}))) == (BASE_MS + 100, BASE_MS + 200)
    assert q.time_bounds(EventFilter(start_ms=BASE_MS + 150, end_ms=BASE_MS + 250)) == (
        BASE_MS + 200, BASE_MS + 200)
    assert q.time_bounds(EventFilter(text="missing")) is None
