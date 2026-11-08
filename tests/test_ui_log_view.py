"""GUI integration tests: log view."""

import time
import csv
import io
from conftest import BASE_MS, make_event
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication
from syslog_monitor.config import Settings
from syslog_monitor.service import CaptureService
from syslog_monitor.query import FilterRule, QueryRunner
from syslog_monitor.ui.main_window import CUSTOM_RANGE_INDEX, DEFAULT_RANGE_INDEX, PAGE_SIZE, MainWindow
from syslog_monitor.ui.query_worker import QueryClient
from ui_test_helpers import FAST, click_severity, send


def test_newer_banner_row_replaces_sidebar_scroll_controls(qtbot, window):
    from PySide6.QtWidgets import QToolBar

    assert not window.findChildren(QToolBar)
    assert window.log_page.layout().itemAt(0).widget() is window.rules_splitter
    banner = window.newer_banner
    assert window._live and banner.isHidden()
    send(window, "<14>first", "<14>second")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    window.set_live(False)
    assert window.table.banner_visible and not banner.isHidden()
    header = window.table.horizontalHeader()
    assert banner.geometry().top() >= header.geometry().bottom()
    assert header.geometry().top() <= window.table.contentsRect().top()
    assert banner.width() == window.table.viewport().width()
    assert window.table.viewport().geometry().top() >= banner.geometry().bottom()
    qtbot.waitUntil(lambda: banner.count == 0)
    assert "no newer messages" in banner.label.text()
    send(window, "<14>third", "<14>fourth")
    qtbot.waitUntil(lambda: banner.count == 2, timeout=5000)
    assert banner.new == 2
    assert "2 messages above" in banner.label.text() and "2 new since pausing" in banner.label.text()
    assert window.model.rowCount() == 2
    banner.latest_button.click()
    qtbot.waitUntil(lambda: window.model.rowCount() == 4)
    assert not window._live and window.table.banner_visible
    qtbot.waitUntil(lambda: banner.count == 0 and banner.new == 0)
    banner.autoscroll_button.click()
    assert window._live and window.live_action.isChecked() and banner.isHidden()
    send(window, *[f"<14>fill {i}" for i in range(80)])
    qtbot.waitUntil(lambda: window.model.rowCount() == 84, timeout=5000)
    bar = window.table.verticalScrollBar()
    bar.setValue(bar.maximum())  # scrolling into history pauses autoscroll
    above = window.table.rowAt(0)
    assert not window._live and above > 0
    qtbot.waitUntil(lambda: banner.count == above and banner.new == 0, timeout=5000)
    send(window, "<14>late")
    qtbot.waitUntil(lambda: banner.count == above + 1 and banner.new == 1, timeout=5000)
    window.clear_view()
    assert window._live and not window.table.banner_visible


def test_query_errors_from_old_selection_generation_are_discarded(qapp, store):
    client = QueryClient(store.path)
    errors = []
    client.error.connect(errors.append)
    try:
        request = client.submit(lambda runner: None, lambda result: None)
        client.new_generation()
        client._on_failed(request, "obsolete failure")
        assert not errors
    finally:
        client.shutdown()


def test_go_to_latest_is_one_shot_and_autoscroll_is_independent(qtbot, window):
    send(window, "<14>oldest", "<14>newest")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    window.set_live(False)
    window.show_page("about")
    window.latest_action.trigger()
    qtbot.waitUntil(lambda: window.current_page == "logs" and not window.queries.busy)
    assert not window.live_action.isChecked()
    assert window.model.row_at(0).message == "newest"
    send(window, "<14>arrived while not following")
    qtbot.wait(200)
    assert window.model.rowCount() == 2
    window.latest_action.trigger()
    qtbot.waitUntil(lambda: window.model.rowCount() == 3)
    assert not window.live_action.isChecked()
    window.live_action.setChecked(True)
    send(window, "<14>autoscrolled")
    qtbot.waitUntil(lambda: window.model.rowCount() == 4)
    assert window.model.row_at(0).message == "autoscrolled"


def test_clickable_severity_groups_combine_and_reset(qtbot, window):
    send(window, "<11>error", "<12>warning", "<13>notice", "<14>info", "<15>debug",
         "unknown")
    qtbot.waitUntil(lambda: window.minimap.histogram is not None and
                   window.minimap.histogram.total == 6)
    click_severity(qtbot, window, "0")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1)
    assert window.model.row_at(0).severity == 3
    assert window.list_filter().severities == frozenset({0, 1, 2, 3})
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 1)
    click_severity(qtbot, window, "3", Qt.ControlModifier)
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    assert {window.model.row_at(i).severity for i in range(2)} == {3, 7}
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 2)
    click_severity(qtbot, window, "0", Qt.ControlModifier)
    qtbot.waitUntil(lambda: window.model.rowCount() == 1)
    assert window.model.row_at(0).severity == 7
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 1)
    click_severity(qtbot, window, "3")
    qtbot.waitUntil(lambda: window.model.rowCount() == 6)
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 6)
    click_severity(qtbot, window, "2")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    assert {window.model.row_at(i).severity for i in range(2)} == {5, 6}
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 2)
    click_severity(qtbot, window, "4")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1)
    assert window.model.row_at(0).severity is None
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 1)
    click_severity(qtbot, window, "all")
    qtbot.waitUntil(lambda: window.model.rowCount() == 6)


def test_severity_click_preserves_rules_facility_and_search(qtbot, window):
    send(window, "<11>1 - h web - - - keep error", "<15>1 - h web - - - keep debug",
         "<19>1 - h web - - - keep other facility", "<11>1 - h db - - - excluded")
    qtbot.waitUntil(lambda: window.model.rowCount() == 4)
    window.filter_bar.add_rule(FilterRule("app", "equals", "web"))
    window.filter_bar.facility.setCurrentIndex(window.filter_bar.facility.findData(1))
    qtbot.waitUntil(lambda: window.minimap.histogram is not None and
                   window.minimap.histogram.total == 2)
    click_severity(qtbot, window, "0")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1)
    assert window.model.row_at(0).message == "keep error"
    window.search_text.setText("debug")
    window.find_text()
    qtbot.waitUntil(lambda: window.search_result.text() == "No matches")
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 1)
    click_severity(qtbot, window, "all")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    assert window.list_filter().facility == 1
    assert window.list_filter().rules == (FilterRule("app", "equals", "web"),)


def test_live_view_shows_new_messages(qtbot, window):
    send(window, "<11>1 - h1 app - - - disk failure", "<14>1 - h2 web - - - request ok")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2, timeout=5000)
    assert window.model.row_at(0).message == "request ok"
    qtbot.waitUntil(lambda: window.minimap.histogram is not None and window.minimap.histogram.total == 2,
                    timeout=5000)
    assert "Error 1" in window.legend.text()
    qtbot.waitUntil(lambda: "stored 2" in window.counter_label.text(), timeout=5000)
    assert "Live:" in window.counter_label.text()


def test_multiple_selection_and_copy_full_messages(qtbot, window):
    messages = ["first", "long " + "x" * 700 + "\nnext\tfield", "last"]
    send(window, *(f"<15>1 - h app - - - {text}" for text in messages))
    qtbot.waitUntil(lambda: window.model.rowCount() == 3, timeout=5000)
    window.table.setFocus()
    qtbot.mouseClick(window.table.viewport(), Qt.LeftButton,
                     pos=window.table.visualRect(window.model.index(0, 0)).center())
    qtbot.mouseClick(window.table.viewport(), Qt.LeftButton, Qt.ShiftModifier,
                     pos=window.table.visualRect(window.model.index(2, 0)).center())
    assert len(window.table.selectionModel().selectedRows()) == 3
    assert not window._live
    qtbot.keyClick(window.table, Qt.Key_C, Qt.ControlModifier)
    copied = list(csv.reader(io.StringIO(QApplication.clipboard().text()), delimiter="\t"))
    assert [row[-1] for row in copied] == list(reversed(messages))
    assert all(len(row) == 7 for row in copied)
    window.table.clearSelection()
    assert not window.copy_action.isEnabled()
    window.select_all_action.trigger()
    assert len(window.table.selectionModel().selectedRows()) == 3
    window.copy_action.trigger()
    assert "Copied 3 rows" in window.statusBar().currentMessage()
    qtbot.keyClick(window.table, Qt.Key_A, Qt.ControlModifier)
    assert len(window.table.selectionModel().selectedRows()) == 3
    qtbot.mouseClick(window.table.viewport(), Qt.LeftButton,
                     pos=window.table.visualRect(window.model.index(0, 0)).center())
    qtbot.mouseClick(window.table.viewport(), Qt.LeftButton, Qt.ControlModifier,
                     pos=window.table.visualRect(window.model.index(2, 0)).center())
    qtbot.keyClick(window.table, Qt.Key_C, Qt.ControlModifier)
    copied = list(csv.reader(io.StringIO(QApplication.clipboard().text()), delimiter="\t"))
    assert [row[-1] for row in copied] == [messages[2], messages[0]]


def test_negative_rules_update_table_and_minimap(qtbot, window):
    send(window, "<15>1 - h web - - - heartbeat", "<11>1 - h db - - - disk error",
         "<14>1 - h web - - - login")
    qtbot.waitUntil(lambda: window.model.rowCount() == 3, timeout=5000)
    window.filter_bar.add_rule(FilterRule("message", "not_contains", "heartbeat"))
    window.filter_bar.add_rule(FilterRule("app", "equals", "web"))
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)
    assert window.model.row_at(0).message == "login"
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 1, timeout=5000)
    window.filter_bar.rules_match.setCurrentIndex(1)
    qtbot.waitUntil(lambda: window.model.rowCount() == 3, timeout=5000)
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 3, timeout=5000)


def test_pause_keeps_storing_and_live_resumes(qtbot, window):
    send(window, "<14>first")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)
    window.live_action.setChecked(False)
    send(window, "<14>second", "<14>third")
    assert window.service.flush()
    qtbot.wait(300)
    assert window.model.rowCount() == 1  # view frozen
    assert window.service.snapshot().persisted == 3
    qtbot.waitUntil(lambda: window.newer_banner.count == 2, timeout=5000)
    window.live_action.setChecked(True)
    qtbot.waitUntil(lambda: window.model.rowCount() == 3, timeout=5000)


def test_details_and_paging_and_jump(qtbot, window):
    total = PAGE_SIZE + 150
    window.live_action.setChecked(False)  # avoid live prepends racing with the page load
    send(window, *[f"<14>1 - h app - - - line {i}" for i in range(total)])
    qtbot.waitUntil(lambda: window.service.snapshot().persisted == total, timeout=10000)
    window.refresh_all()
    qtbot.waitUntil(lambda: window.model.rowCount() == PAGE_SIZE, timeout=5000)
    assert window.model.has_older

    window.table.selectRow(0)
    qtbot.waitUntil(lambda: "Raw data" in window.details.toPlainText(), timeout=5000)
    assert f"line {total - 1}" in window.details.toPlainText()

    window.table.scrollToBottom()  # loads the next (older) page
    qtbot.waitUntil(lambda: window.model.rowCount() == total, timeout=5000)
    assert not window.model.has_older

    oldest = window.model.row_at(total - 1)
    window.jump_to_time(oldest.received_at)
    qtbot.waitUntil(lambda: window.model.has_newer, timeout=5000)
    current = window.table.currentIndex().row()
    assert window.model.row_at(current).received_at <= oldest.received_at


def test_scrolling_away_pauses_live_view(qtbot, window):
    send(window, *[f"<14>m{i}" for i in range(200)])
    qtbot.waitUntil(lambda: window.model.rowCount() == 200, timeout=5000)
    qtbot.waitUntil(lambda: window.table.verticalScrollBar().maximum() >= 50)
    window.table.verticalScrollBar().setValue(50)
    assert not window.live_action.isChecked()
    assert "Autoscroll off" in window.mode_label.text()


def test_minimap_visible_range_tracks_table_scroll_resize_and_empty_view(qtbot, window, monkeypatch):
    from PySide6.QtCore import QItemSelectionModel

    from syslog_monitor import receiver

    start = time.time_ns() // 1_000_000 - 200_000
    timestamps = iter(start + index * 1000 for index in range(200))
    monkeypatch.setattr(receiver, "now_ms", lambda: next(timestamps))
    send(window, *[f"<14>range example {index}" for index in range(200)])
    qtbot.waitUntil(lambda: window.model.rowCount() == 200)
    qtbot.waitUntil(lambda: window.minimap.visible_range is not None)
    qtbot.waitUntil(lambda: window.table.verticalScrollBar().maximum() >= 50)

    def expected_bounds():
        first = window.table.rowAt(0)
        last = window.table.rowAt(window.table.viewport().height() - 1)
        if last < 0:
            last = window.model.rowCount() - 1
        return (window.model.row_at(last).received_at, window.model.row_at(first).received_at)

    qtbot.waitUntil(lambda: window.minimap.visible_range == expected_bounds())
    assert window.minimap.visible_range[0] > start
    assert window.minimap.selected_times == ()
    window.table.selectRow(5)
    assert window.minimap.selected_times == (start + 194_000,)
    window.table.verticalScrollBar().setValue(50)
    qtbot.waitUntil(lambda: window.minimap.visible_range == expected_bounds())
    assert window.minimap.visible_range[1] == start + 149_000
    assert window.minimap.selected_times == (start + 194_000,)
    window.table.selectionModel().select(
        window.model.index(50, 0), QItemSelectionModel.ClearAndSelect | QItemSelectionModel.Rows)
    window.table.selectionModel().select(
        window.model.index(60, 0), QItemSelectionModel.Select | QItemSelectionModel.Rows)
    assert window.minimap.selected_times == (start + 139_000, start + 149_000)
    window.table.clearSelection()
    assert window.minimap.selected_times == ()
    window.splitter.setSizes([150, 500])
    qtbot.waitUntil(lambda: window.minimap.visible_range == expected_bounds())
    window.filter_bar.add_rule(FilterRule(value="no matching event"))
    qtbot.waitUntil(lambda: window.model.rowCount() == 0)
    qtbot.waitUntil(lambda: window.minimap.visible_range is None)


def test_zoom_and_reset(qtbot, window):
    send(window, "<14>a")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)
    now = time.time_ns() // 1_000_000
    window.zoom_to(now - 3_600_000, now - 1_800_000)
    qtbot.waitUntil(lambda: window.model.rowCount() == 0, timeout=5000)
    assert window.reset_zoom_action.isEnabled() and "Zoom" in window.mode_label.text()
    window.reset_zoom()
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)


def test_clear_view_sets_range_start_without_deleting(qtbot, window):
    send(window, "<11>1 - h app - - - old error", "<14>1 - h app - - - old info")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2, timeout=5000)
    window.live_action.setChecked(False)
    assert not window.custom_range.isVisible()
    qtbot.wait(5)  # cleared view starts strictly after the old rows
    window.clear_view_action.trigger()
    assert window._live and window.model.rowCount() == 0
    assert window.range_combo.currentIndex() == CUSTOM_RANGE_INDEX and window.custom_range.isVisible()
    assert window.range_from_check.isChecked() and not window.range_to_check.isChecked()
    assert " from " in window.mode_label.text()
    start = window.custom_bounds()[0]
    qtbot.waitUntil(lambda: window.minimap.histogram is not None and window.minimap.histogram.total == 0,
                    timeout=5000)
    assert window.minimap.histogram.start_ms >= start
    send(window, "<14>1 - h app - - - new info")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)
    assert window.model.row_at(0).message == "new info"
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 1, timeout=5000)
    assert window.service.snapshot().persisted == 3  # nothing deleted
    window.search_text.setText("old")
    window.find_text()
    qtbot.waitUntil(lambda: window.search_result.text() == "No matches", timeout=5000)
    window.range_from_check.setChecked(False)  # Von off: everything again
    qtbot.waitUntil(lambda: window.model.rowCount() == 3, timeout=5000)
    assert " from " not in window.mode_label.text()
    window.range_combo.setCurrentIndex(DEFAULT_RANGE_INDEX)
    assert not window.custom_range.isVisible()


def test_custom_from_to_range_limits_table_and_is_saved(qtbot, window, tmp_path):
    from PySide6.QtCore import QDateTime
    send(window, "<14>1 - h app - - - early")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)
    qtbot.wait(1100)  # Bis has second resolution
    split = time.time_ns() // 1_000_000
    qtbot.wait(1100)
    send(window, "<14>1 - h app - - - late")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2, timeout=5000)
    window.range_combo.setCurrentIndex(CUSTOM_RANGE_INDEX)  # starts from the previous preset
    assert window.range_from_check.isChecked() and not window.range_to_check.isChecked()
    qtbot.waitUntil(lambda: window.model.rowCount() == 2, timeout=5000)
    window.range_to.setDateTime(QDateTime.fromMSecsSinceEpoch(split - 1000))
    window.range_to_check.setChecked(True)
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)
    assert window.model.row_at(0).message == "early"
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 1, timeout=5000)
    # Von after Bis is corrected instead of producing an inverted range
    window.range_from.setDateTime(QDateTime.fromMSecsSinceEpoch(split + 5000))
    assert window.range_to.dateTime() >= window.range_from.dateTime()
    bounds = window.custom_bounds()
    window._save_ui_state()

    service = CaptureService(tmp_path / "data2", Settings(bind_host="127.0.0.1", port=0))
    win = MainWindow(service, settings_path=tmp_path / "s2.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST)
    try:
        assert win.range_combo.currentIndex() == CUSTOM_RANGE_INDEX
        assert win.custom_bounds() == bounds
    finally:
        win.shutdown()
        service.shutdown()


def test_stale_query_results_are_discarded(qtbot, tmp_path):
    from syslog_monitor.storage import EventStore
    store = EventStore(tmp_path)
    client = QueryClient(store.path)
    results = []
    client.submit(lambda r: (time.sleep(0.2), "old")[1], results.append)
    client.new_generation()
    client.submit(lambda r: "new", results.append)
    qtbot.waitUntil(lambda: not client.busy, timeout=3000)
    assert results == ["new"]
    client.shutdown()
    store.close()


def test_selected_rows_remain_distinct_over_highlights_and_without_focus(qtbot, window):
    from PySide6.QtGui import QColor

    send(window, "<14>1 - h app - - - Initializing system",
         "<14>1 - h app - - - ordinary message")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    window.set_live(False)
    window.table.selectAll()
    window.table.setFocus()

    def selected_colors():
        image = window.table.viewport().grab().toImage()
        colors = []
        for row_number in range(2):
            rect = window.table.visualRect(window.model.index(row_number, 4))
            colors.append(image.pixelColor(rect.right() - 8, rect.center().y()))
        return colors

    qtbot.waitUntil(lambda: selected_colors() == [QColor("#505050")] * 2)
    window.search_text.setFocus()
    qtbot.waitUntil(lambda: selected_colors() == [QColor("#505050")] * 2)
    window.table.selectionModel().clearSelection()
    qtbot.waitUntil(lambda: all(color != QColor("#505050") for color in selected_colors()))


def test_minimap_adapts_to_available_filtered_data(window, store, monkeypatch):
    from syslog_monitor.ui import main_window
    now = BASE_MS + 3_600_000
    monkeypatch.setattr(main_window, "_now_ms", lambda: now)
    store.insert([
        make_event(0), make_event(3_590_000, severity=3), make_event(3_595_000, severity=3),
    ])
    runner = QueryRunner(store.path)
    try:
        hist = window._histogram_job(100)(runner)
        assert hist.total == 3
        window.filter_bar.set_severities({3})
        hist = window._histogram_job(100)(runner)
        assert hist.total == 2
        assert hist.end_ms - hist.start_ms <= 15_000
        assert hist.start_ms <= BASE_MS + 3_590_000
        assert hist.end_ms > BASE_MS + 3_595_000
        window._apply_histogram(hist)
        assert "automatic" in window.minimap_range_label.text()
        window._zoom = (BASE_MS, now)
        hist = window._histogram_job(100)(runner)
        assert (hist.start_ms, hist.end_ms) == window._zoom
    finally:
        runner.close()


def test_minimap_single_event_empty_and_time_limit(window, store, monkeypatch):
    from syslog_monitor.ui import main_window
    now = BASE_MS + 20 * 60_000
    monkeypatch.setattr(main_window, "_now_ms", lambda: now)
    window.range_combo.setCurrentIndex(0)  # last 15 minutes
    store.insert([make_event(0), make_event(20 * 60_000 - 1000)])
    runner = QueryRunner(store.path)
    try:
        hist = window._histogram_job(100)(runner)
        assert hist.total == 1  # older event outside preset is not included
        assert 0 < hist.end_ms - hist.start_ms <= 10_000
        window.filter_bar.add_rule(FilterRule("text", "words", "missing"))
        hist = window._histogram_job(100)(runner)
        assert hist.total == 0
        assert hist.end_ms - hist.start_ms == 60_000
        window._set_custom(now - 30_000, None)  # Von/Bis replaces the preset
        window.range_combo.blockSignals(True)
        window.range_combo.setCurrentIndex(CUSTOM_RANGE_INDEX)
        window.range_combo.blockSignals(False)
        hist = window._histogram_job(100)(runner)
        assert (hist.start_ms, hist.end_ms) == (now - 30_000, now + 1)
        window.filter_bar.reset()
        hist = window._histogram_job(100)(runner)
        assert hist.total == 1 and hist.start_ms >= now - 30_000
        window._set_custom(None, now - 60_000)  # only Bis: older events up to that second
        hist = window._histogram_job(100)(runner)
        assert hist.total == 1 and hist.end_ms <= now - 59_000
        window._set_custom(now, None)
        assert window._histogram_job(100)(runner).total == 0
    finally:
        runner.close()


def test_query_shutdown_closes_connection_before_returning(qtbot, tmp_path):
    from syslog_monitor.storage import EventStore
    store = EventStore(tmp_path / "shutdown")
    client = QueryClient(store.path)
    client.submit(lambda r: r.time_bounds(), lambda result: None)
    qtbot.waitUntil(lambda: not client.busy)
    assert client._worker._runner is not None
    client.shutdown()
    assert not client._thread.isRunning()
    assert client._worker._runner is None
    store.close()
    store.path.unlink()  # Windows rejects this if a connection is still open.
