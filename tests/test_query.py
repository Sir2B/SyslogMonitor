from conftest import BASE_MS, make_event

from syslog_monitor.events import SeverityClass
from syslog_monitor.query import (
    TEXT_MODE_SUBSTRING, EventFilter, FilterRule, HighlightRule, QueryRunner, active_highlights,
    fts_query, highlight_matches, like_pattern, matching_highlight, parse_highlights,
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
                   {"enabled": "false"}, {"color": None}):
        with pytest.raises(ValueError):
            HighlightRule(**kwargs)


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
