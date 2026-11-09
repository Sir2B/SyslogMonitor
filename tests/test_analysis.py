import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from conftest import BASE_MS, make_event

from syslog_monitor.analysis import (
    MAX_SIMILAR_INPUT, MODE_EXACT, MODE_NUMBERS, MODE_SIMILAR, FrequencyGroup, cluster_similar, similarity,
)
from syslog_monitor.matching import number_template
from syslog_monitor.query import EventFilter, FilterRule, QueryRunner
from ui_test_helpers import send


def group(pattern, count=1, variants=1, first=0, last=0):
    return FrequencyGroup(pattern, count, variants, first, last, pattern)


def test_number_template_replaces_numbers_like_the_statistics_regex():
    assert number_template("port 22 up after 1.5s, delta -3") == "port # up after #s, delta #"
    assert number_template("range 1-5 ok") == "range #-# ok"
    assert number_template(None) == ""


def test_similarity_compares_words_and_ignores_whitespace():
    assert similarity("a b c d e", "a  b c d e") == 1.0
    assert similarity("a b c d e", "a b c d x") == pytest.approx(0.8)
    assert similarity("", "") == 1.0
    assert similarity("a", "") == 0.0


def test_cluster_similar_merges_at_threshold_and_keeps_leader():
    groups = [
        group("link up on port # speed # mbit", 5, 2, first=10, last=50),
        group("link down on port # speed # mbit", 3, 1, first=5, last=40),
        group("disk full on volume #", 7, 3, first=20, last=30),
        group("user # logged in", 1),
    ]
    merged = cluster_similar(groups, 0.8)
    assert [g.pattern for g in merged] == [
        "link up on port # speed # mbit", "disk full on volume #", "user # logged in"]
    link = merged[0]
    assert (link.count, link.variants, link.first_ms, link.last_ms, link.patterns) == (8, 3, 5, 50, 2)
    assert sum(g.count for g in merged) == sum(g.count for g in groups)
    # A stricter threshold keeps the two link messages apart.
    assert len(cluster_similar(groups, 0.95)) == 4


def test_cluster_similar_compares_with_leader_to_avoid_chaining():
    chain = [group("a b c d e f g h i j", 9), group("a b c d e f g h x y", 5),
             group("a b c d e f x y z w", 1)]
    merged = cluster_similar(chain, 0.8)
    assert [g.count for g in merged] == [14, 1]


def test_cluster_similar_rejects_invalid_thresholds():
    with pytest.raises(ValueError):
        cluster_similar([], 0.4)
    with pytest.raises(ValueError):
        cluster_similar([], 1.1)


def test_cluster_similar_stops_like_an_interrupted_query():
    import sqlite3

    calls = []

    def stop_on_second():
        calls.append(1)
        return len(calls) > 1

    with pytest.raises(sqlite3.OperationalError, match="interrupt"):
        cluster_similar([group("a b"), group("c d"), group("e f")], 0.8, stop_on_second)


def test_runner_interrupt_cancels_similar_grouping(store, monkeypatch):
    import sqlite3

    from syslog_monitor import query

    q = fill(store, [make_event(i, message=f"msg {chr(97 + i)} x") for i in range(3)])
    original = query.cluster_similar

    def interrupted_meanwhile(groups, threshold, should_stop):
        q.interrupt()  # simulates the GUI starting a new generation during grouping
        return original(groups, threshold, should_stop)

    monkeypatch.setattr(query, "cluster_similar", interrupted_meanwhile)
    try:
        with pytest.raises(sqlite3.OperationalError, match="interrupt"):
            q.message_frequencies(EventFilter(), MODE_SIMILAR)
        monkeypatch.setattr(query, "cluster_similar", original)
        assert q.message_frequencies(EventFilter(), MODE_SIMILAR).total == 3
    finally:
        q.close()


def fill(store, events):
    store.insert(events)
    return QueryRunner(store.path)


def test_message_frequencies_exact_numbers_and_similar(store):
    q = fill(store, [
        make_event(0, message="temp 21 C"),
        make_event(1, message="temp 21 C"),
        make_event(2, message="temp 22 C"),
        make_event(3, message="temp # C"),  # literal "#" must not merge with numbers
        make_event(4, message="fan on at level 3 now"),
        make_event(5, message="fan off at level 3 now"),
        make_event(6, message="other", app_name="db"),
    ])
    try:
        exact = q.message_frequencies(EventFilter(), MODE_EXACT)
        assert exact.total == 7 and not exact.truncated
        assert [(g.pattern, g.count) for g in exact.groups][0] == ("temp 21 C", 2)
        assert {g.pattern for g in exact.groups} >= {"temp 22 C", "temp # C"}

        numbers = q.message_frequencies(EventFilter(), MODE_NUMBERS)
        top = numbers.groups[0]
        assert (top.pattern, top.count, top.variants) == ("temp # C", 3, 2)
        assert (top.first_ms, top.last_ms) == (BASE_MS, BASE_MS + 2)
        assert sum(g.count for g in numbers.groups) == 7
        assert [g.count for g in numbers.groups if g.pattern == "temp # C"] == [3, 1]

        similar = q.message_frequencies(EventFilter(), MODE_SIMILAR, 0.8)
        fan = [g for g in similar.groups if g.pattern.startswith("fan")]
        assert len(fan) == 1 and fan[0].count == 2 and fan[0].patterns == 2
        assert sum(g.count for g in similar.groups) == 7

        filtered = q.message_frequencies(
            EventFilter(rules=(FilterRule("app", "equals", "db"),)), MODE_NUMBERS)
        assert filtered.total == 1 and [g.pattern for g in filtered.groups] == ["other"]
        timed = q.message_frequencies(EventFilter().with_time(BASE_MS + 4, None), MODE_EXACT)
        assert timed.total == 3
        with pytest.raises(ValueError):
            q.message_frequencies(EventFilter(), "bogus")
        with pytest.raises(ValueError):
            q.message_frequencies(EventFilter(), MODE_SIMILAR, 0.2)
    finally:
        q.close()


def test_message_frequencies_reports_truncation(store, monkeypatch):
    from syslog_monitor import query

    q = fill(store, [make_event(i, message=f"msg {chr(97 + i)}") for i in range(5)])
    try:
        monkeypatch.setattr(query, "group_limit", lambda mode: 3)
        report = q.message_frequencies(EventFilter(), MODE_EXACT)
        assert report.truncated and len(report.groups) == 3 and report.total == 5
    finally:
        q.close()
    assert MAX_SIMILAR_INPUT <= 5000


def test_analysis_page_uses_current_filter_and_switches_modes(qtbot, window):
    send(window, "<134>Nov  6 00:00:00 host app: job 1 done",
         "<134>Nov  6 00:00:00 host app: job 2 done",
         "<134>Nov  6 00:00:00 host app: job 2 done",
         "<134>Nov  6 00:00:00 host other: unrelated")
    qtbot.waitUntil(lambda: window.model.rowCount() == 4)
    window.analysis_action.trigger()
    page = window._analysis_page
    assert window.current_page == "analysis"
    qtbot.waitUntil(lambda: page.report is not None and not page.busy)
    assert page.report.mode == MODE_NUMBERS
    assert page.table.item(0, 5).text() == "job # done"
    assert page.table.item(0, 0).text() == "3"
    assert "2 groups from 4 messages" in page.summary.text()
    assert not page.similarity.isEnabled()

    page.mode.setCurrentIndex(page.mode.findData(MODE_EXACT))
    qtbot.waitUntil(lambda: page.report.mode == MODE_EXACT and not page.busy)
    assert page.table.isColumnHidden(2)
    assert [page.table.item(row, 5).text() for row in range(page.table.rowCount())][0] == "job 2 done"

    page.mode.setCurrentIndex(page.mode.findData(MODE_SIMILAR))
    qtbot.waitUntil(lambda: page.report.mode == MODE_SIMILAR and not page.busy)
    assert page.similarity.isEnabled() and page.similarity.value() == 80

    page.table.sortItems(0, Qt.AscendingOrder)
    counts = [page.table.item(row, 0).data(Qt.UserRole) for row in range(page.table.rowCount())]
    assert counts == sorted(counts)
    assert QApplication.activeModalWidget() is None


def test_analysis_page_reanalyses_with_log_view_filter_when_shown(qtbot, window, monkeypatch):
    send(window, "<134>Nov  6 00:00:00 host app: job 1 done",
         "<134>Nov  6 00:00:00 host other: unrelated")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    window.show_page("analysis")
    page = window._analysis_page
    qtbot.waitUntil(lambda: page.report is not None and not page.busy)
    assert page.report.total == 2

    only_other = FilterRule("app", "equals", "other")
    monkeypatch.setattr(window.filter_bar, "current_filter", lambda: EventFilter(rules=(only_other,)))
    window.show_page("logs")
    window.show_page("analysis")
    qtbot.waitUntil(lambda: page.report.total == 1 and not page.busy)
    assert [page.table.item(row, 5).text() for row in range(page.table.rowCount())] == ["unrelated"]
