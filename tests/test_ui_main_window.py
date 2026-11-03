"""End-to-end GUI tests: real UDP traffic through service, database and window."""

import time
import csv
import io

import pytest
from conftest import BASE_MS, make_event, send_udp
from PySide6.QtCore import QPoint, QSettings, Qt
from PySide6.QtGui import QTextDocument
from PySide6.QtWidgets import QApplication, QToolBar

from syslog_monitor.config import Settings
from syslog_monitor.service import CaptureService
from syslog_monitor.query import FilterRule, HighlightRule, QueryRunner
from syslog_monitor.ui.main_window import CUSTOM_RANGE_INDEX, DEFAULT_RANGE_INDEX, PAGE_SIZE, MainWindow, Timings
from syslog_monitor.ui.query_worker import QueryClient
from syslog_monitor.writer import WriterTuning

FAST = Timings(live_ms=50, histogram_ms=200, status_ms=100)


@pytest.fixture
def window(qtbot, tmp_path):
    service = CaptureService(tmp_path / "data", Settings(bind_host="127.0.0.1", port=0),
                             tuning=WriterTuning(flush_interval_s=0.05))
    assert service.start_listener()
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST)
    qtbot.addWidget(win)
    win.show()
    yield win
    win.shutdown()
    service.shutdown()


def send(win, *messages: str):
    send_udp(win.service.bound_port, *(m.encode() for m in messages))


def test_time_controls_are_grouped_with_minimap(qtbot, window):
    section = window.minimap.parentWidget()
    assert window.range_combo.parentWidget() is section
    assert window.reset_zoom_button.parentWidget() is section
    assert window.minimap_range_label.parentWidget() is section
    assert window.legend.parentWidget() is section
    assert window.range_combo.geometry().bottom() < window.minimap.geometry().top()
    assert window.legend.geometry().bottom() < window.minimap.geometry().top()
    # Highlight rules form an independent list, like the filter rules.
    assert window.highlights.rule_rows[0].value.isVisible()
    assert window.filters_scroll.geometry().right() < window.highlights_scroll.geometry().left()
    assert window.rules_splitter.geometry().bottom() < section.geometry().top()
    assert window.splitter.width() == window.rules_splitter.width()
    assert window.mode_label.parentWidget() is window.findChild(QToolBar, "main_toolbar")
    # the long range label must not force a wide window (snapping to half screen)
    window.minimap_range_label.setText("Minimap: 2026-10-24 19:10:20 – 2026-10-25 19:10:26 (automatic)")
    assert section.minimumSizeHint().width() < (
        window.legend.minimumSizeHint().width() + window.minimap_range_label.sizeHint().width())
    assert not window.reset_zoom_button.isEnabled()

    now = time.time_ns() // 1_000_000
    window.zoom_to(now - 10_000, now)
    assert window.reset_zoom_button.isEnabled()
    qtbot.mouseClick(window.reset_zoom_button, Qt.LeftButton)
    assert window._zoom is None
    assert not window.reset_zoom_button.isEnabled()


def test_top_rules_scroll_without_shrinking_message_list(qtbot, window):
    window.resize(1300, 750)
    qtbot.wait(20)
    height = window.rules_splitter.height()
    table_height = window.table.height()
    for i in range(12):
        window.highlights.add_rule(HighlightRule(f"highlight {i}"))
        window.filter_bar.add_rule(FilterRule(value=f"filter {i}"))
    qtbot.waitUntil(lambda: window.highlights_scroll.verticalScrollBar().maximum() > 0
                    and window.filters_scroll.verticalScrollBar().maximum() > 0)
    assert window.rules_splitter.height() == height
    assert window.table.height() == table_height
    row = window.highlights.rule_rows[0]
    assert row.enabled.geometry().top() <= row.value.geometry().center().y()
    assert row.value.geometry().right() < row.color_button.geometry().left()
    window.rules_splitter.setSizes([700, 500])
    window._save_ui_state()
    sizes = window.rules_splitter.sizes()
    window.rules_splitter.setSizes([500, 700])
    window._restore_ui_state()
    assert window.rules_splitter.sizes() == sizes


def click_severity(qtbot, window, link, modifiers=Qt.NoModifier):
    qtbot.wait(20)  # allow the label's new rich text to update its geometry
    label = window.legend
    doc = QTextDocument()
    doc.setDefaultFont(label.font())
    doc.setDocumentMargin(0)
    doc.setHtml(label.text())
    doc.setTextWidth(label.contentsRect().width())
    doc.size()  # force layout before inspecting QTextLine geometry
    block = doc.begin()
    while block.isValid():
        iterator = block.begin()
        while not iterator.atEnd():
            fragment = iterator.fragment()
            if fragment.charFormat().anchorHref() == link:
                layout = block.layout()
                offset = fragment.position() - block.position()
                line = layout.lineForTextPosition(offset)
                assert line.isValid()
                x1, _ = line.cursorToX(offset)
                x2, _ = line.cursorToX(offset + min(3, fragment.length()))
                rect = doc.documentLayout().blockBoundingRect(block)
                y = (label.height() - doc.size().height()) / 2 + rect.y() + line.y() + line.height() / 2
                qtbot.mouseClick(label, Qt.LeftButton, modifiers,
                                 QPoint(int((x1 + x2) / 2), int(y)))
                return
            iterator += 1
        block = block.next()
    pytest.fail(f"Missing legend link: {link}")


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


def test_highlight_updates_table_minimap_and_saved_state(qtbot, window):
    assert window.highlights.rule_rows[0].value.text() == "Initializing system"
    send(window, "<15>1 - h app - - - Initializing system",
         "<14>1 - h app - - - regular info",
         "<15>1 - h app - - - regular debug")
    qtbot.waitUntil(lambda: window.model.rowCount() == 3)
    qtbot.waitUntil(lambda: window.minimap.histogram is not None
                    and sum(window.minimap.histogram.highlights) == 1)
    window.set_live(False)
    window.highlights.rule_rows[0].value.setText("regular")
    qtbot.waitUntil(lambda: sum(window.minimap.histogram.highlights) == 2)
    assert window.model.highlight_text == "regular"
    assert window.model.rowCount() == 3
    window._save_ui_state()
    window.highlights.rule_rows[0].value.setText("other")
    window._restore_ui_state()
    assert window.highlights.rule_rows[0].value.text() == window.model.highlight_text == "regular"
    window.highlights.rule_rows[0].value.clear()
    qtbot.waitUntil(lambda: sum(window.minimap.histogram.highlights) == 0)
    assert window.model.rowCount() == 3
    window._save_ui_state()
    window.highlights.rule_rows[0].value.setText("other")
    window._restore_ui_state()
    assert window.highlights.rule_rows[0].value.text() == ""


def test_popup_only_for_new_live_highlights_even_when_hidden(qtbot, tmp_path):
    service = CaptureService(tmp_path / "data", Settings(bind_host="127.0.0.1", port=0),
                             tuning=WriterTuning(flush_interval_s=0.05))
    assert service.start_listener()
    send_udp(service.bound_port, b"<15>1 - h app - - - Initializing system (old)")
    deadline = time.monotonic() + 5
    while service.snapshot().persisted < 1 and time.monotonic() < deadline:
        time.sleep(0.02)
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST)
    qtbot.addWidget(win)
    shown = []
    win.highlight_alerts.show = lambda title, body: shown.append((title, body))
    try:
        win.highlights.add_rule(HighlightRule("watchdog", "#00796b"))
        qtbot.waitUntil(lambda: win._watch_after_id is not None, timeout=5000)
        qtbot.wait(200)
        assert shown == []  # history is not announced
        win.hide()
        send_udp(service.bound_port, b"<15>1 - plc-01 app - - - WATCHDOG reset",
                 b"<14>1 - plc-01 app - - - normal info")
        qtbot.waitUntil(lambda: len(shown) == 1, timeout=5000)
        assert shown[0][0] == "Highlight: 1 new message"
        assert "plc-01: WATCHDOG reset" in shown[0][1]

        win.highlight_popup.setChecked(False)
        send_udp(service.bound_port, b"<15>1 - plc-01 app - - - watchdog again")
        qtbot.waitUntil(lambda: service.snapshot().persisted == 4, timeout=5000)
        qtbot.wait(300)
        assert len(shown) == 1
        win._save_ui_state()
        win.highlight_popup.setChecked(True)
        win._restore_ui_state()
        assert not win.highlight_popup.isChecked()
    finally:
        win.shutdown()
        service.shutdown()


def test_multiple_highlight_colors_priority_and_restore(qtbot, window):
    from PySide6.QtGui import QColor

    panel = window.highlights
    panel.rule_rows[0].value.setText("boot")
    second = panel.add_rule(HighlightRule("ready", "#ffff00"))
    send(window, "<14>1 - h app - - - boot ready", "<14>1 - h app - - - ready",
         "<14>1 - h app - - - noise")
    qtbot.waitUntil(lambda: window.model.rowCount() == 3)
    qtbot.waitUntil(lambda: window.minimap.histogram is not None
                    and sum(window.minimap.histogram.highlights) == 2)
    assert [row.count_label.text() for row in panel.rule_rows] == ["1", "1"]
    assert window.model.data(window.model.index(2, 0), Qt.BackgroundRole).color() == QColor("#7b1fa2")
    assert window.model.data(window.model.index(1, 0), Qt.BackgroundRole).color() == QColor("#ffff00")
    qtbot.mouseClick(second.up_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: window.minimap.histogram.highlight_rules[0].color == "#ffff00")
    assert window.model.data(window.model.index(2, 0), Qt.BackgroundRole).color() == QColor("#ffff00")
    assert sum(bucket[0] for bucket in window.minimap.histogram.highlight_counts) == 2
    assert sum(bucket[1] for bucket in window.minimap.histogram.highlight_counts) == 0
    assert [row.count_label.text() for row in panel.rule_rows] == ["2", "0"]
    second.enabled.setChecked(False)
    qtbot.waitUntil(lambda: sum(window.minimap.histogram.highlights) == 1)
    assert [row.count_label.text() for row in panel.rule_rows] == ["–", "1"]
    saved = panel.rules()
    window._save_ui_state()
    panel.remove_rule(second)
    window._restore_ui_state()
    assert panel.rules() == saved == window.model.highlight_rules
    assert not panel.rule_rows[0].enabled.isChecked()
    for row in list(panel.rule_rows):
        qtbot.mouseClick(row.remove_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: sum(window.minimap.histogram.highlights) == 0)
    window._save_ui_state()
    window._restore_ui_state()
    assert panel.rules() == ()
    assert window.model.rowCount() == 3


def test_legacy_and_invalid_highlight_state(qtbot, window, caplog):
    window._ui_state.remove("highlight_rules")
    window._ui_state.setValue("highlight_text", "Boot; Watchdog")
    window._restore_ui_state()
    assert window.highlights.rules() == (HighlightRule("Boot; Watchdog"),)
    window._ui_state.setValue("highlight_rules", '[{"text":"x","color":"invalid"}]')
    window._restore_ui_state()
    assert window.highlights.rules() == (HighlightRule("Initializing system"),)
    assert "Could not read stored highlights" in caplog.text


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


def test_filter_and_search(qtbot, window):
    send(window, "<11>1 - h1 app - - - disk failure", "<14>1 - h2 web - - - request ok",
         "<12>1 - h3 db - - - slow query")
    qtbot.waitUntil(lambda: window.model.rowCount() == 3, timeout=5000)
    window.filter_bar.add_rule(FilterRule("text", "words", "disk"))
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)
    assert window.model.row_at(0).message == "disk failure"
    window.filter_bar.reset()
    qtbot.waitUntil(lambda: window.model.rowCount() == 3, timeout=5000)
    window.filter_bar.set_severities({4})
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)
    assert window.model.row_at(0).message == "slow query"


def test_pause_keeps_storing_and_live_resumes(qtbot, window):
    send(window, "<14>first")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1, timeout=5000)
    window.live_action.setChecked(False)
    send(window, "<14>second", "<14>third")
    assert window.service.flush()
    qtbot.wait(300)
    assert window.model.rowCount() == 1  # view frozen
    assert window.service.snapshot().persisted == 3
    qtbot.waitUntil(lambda: "2 new messages" in window.statusBar().currentMessage(), timeout=5000)
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
    window.table.verticalScrollBar().setValue(50)
    assert not window.live_action.isChecked()
    assert "PAUSED" in window.mode_label.text()


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


def test_listener_toggle(qtbot, window):
    window.listen_action.trigger()
    assert not window.service.listening
    qtbot.waitUntil(lambda: "stopped" in window.listener_label.text(), timeout=2000)
    window.listen_action.trigger()
    assert window.service.listening


def test_close_without_tray_quits_and_saves_state(qtbot, window, tmp_path):
    window.filter_bar.add_rule(FilterRule("text", "words", "persist me"))
    assert window.close()
    state = QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat)
    assert "persist me" in state.value("filters")


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


def selected_message(window):
    row = window.model.row_at(window.table.currentIndex().row())
    return None if row is None else row.message


def test_search_navigates_without_hiding_context(qtbot, window):
    send(window, "<14>context before", "<11>needle first", "<14>context between",
         "<11>needle second", "<14>context after")
    qtbot.waitUntil(lambda: window.model.rowCount() == 5)
    window.search_text.setText("needle")
    qtbot.wait(350)
    assert window.model.rowCount() == 5 and window.live_action.isChecked()
    qtbot.mouseClick(window.search_next, Qt.LeftButton)
    qtbot.waitUntil(lambda: selected_message(window) == "needle second")
    assert window.model.rowCount() == 5
    assert not window.live_action.isChecked()
    qtbot.waitUntil(lambda: "needle second" in window.details.toPlainText())
    qtbot.waitUntil(lambda: window.minimap.histogram.total == 5)
    qtbot.keyClick(window.search_text, Qt.Key_Return)
    qtbot.waitUntil(lambda: selected_message(window) == "needle first")
    qtbot.mouseClick(window.search_next, Qt.LeftButton)
    qtbot.waitUntil(lambda: window.search_result.text() == "No more matches")
    assert selected_message(window) == "needle first"
    assert window.model.rowCount() == 5
    qtbot.mouseClick(window.search_previous, Qt.LeftButton)
    qtbot.waitUntil(lambda: selected_message(window) == "needle second")
    window.search_text.setText("missing")
    qtbot.mouseClick(window.search_next, Qt.LeftButton)
    qtbot.waitUntil(lambda: window.search_result.text() == "No matches")
    assert window.model.rowCount() == 5
    window.search_text.clear()
    assert not window.search_next.isEnabled() and not window.search_previous.isEnabled()


def test_search_and_text_filter_can_be_combined(qtbot, window):
    send(window, "<14>keep context", "<11>keep needle: code_17", "<11>other needle")
    qtbot.waitUntil(lambda: window.model.rowCount() == 3)
    window.filter_bar.add_rule(FilterRule("text", "words", "keep"))
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    window.search_text.setText("e_17")
    window.search_mode.setCurrentIndex(1)
    window.find_text()
    qtbot.waitUntil(lambda: selected_message(window) == "keep needle: code_17")
    assert {window.model.row_at(i).message for i in range(window.model.rowCount())} == {
        "keep context", "keep needle: code_17"}
    window.filter_bar.set_severities({6})
    qtbot.waitUntil(lambda: window.model.rowCount() == 1)
    window.find_text()
    qtbot.waitUntil(lambda: window.search_result.text() == "No matches")
    assert window.model.row_at(0).message == "keep context"


def test_search_loads_context_beyond_current_page(qtbot, window):
    total = PAGE_SIZE + 100
    window.set_live(False)
    send(window, *[f"<14>{'needle' if i == 10 else 'line'} {i}" for i in range(total)])
    qtbot.waitUntil(lambda: window.service.snapshot().persisted == total, timeout=10000)
    window.refresh_all()
    qtbot.waitUntil(lambda: window.model.rowCount() == PAGE_SIZE
                   and window.model.row_at(0).message == f"line {total - 1}")
    assert not any("needle" in window.model.row_at(i).message for i in range(PAGE_SIZE))
    window.search_text.setText("needle")
    window.find_text()
    qtbot.waitUntil(lambda: selected_message(window) == "needle 10")
    assert window.model.rowCount() > 20
    assert window.model.has_newer
    assert "line 9" in {window.model.row_at(i).message for i in range(window.model.rowCount())}
    assert "line 11" in {window.model.row_at(i).message for i in range(window.model.rowCount())}


def test_changing_search_discards_pending_result(qtbot, window, monkeypatch):
    send(window, "<14>context", "<11>needle")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    original = QueryRunner.find_match

    def slow_match(self, *args, **kwargs):
        time.sleep(0.15)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(QueryRunner, "find_match", slow_match)
    window.search_text.setText("needle")
    window.find_text()
    window.search_text.setText("different")
    qtbot.waitUntil(lambda: not window.queries.busy)
    assert window._search_cursor is None
    assert window.search_result.text() == ""
    assert selected_message(window) is None
    assert window.model.rowCount() == 2


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


def test_search_keyboard_shortcuts(qtbot, window):
    send(window, "<14>needle older", "<14>context", "<14>needle newer")
    qtbot.waitUntil(lambda: window.model.rowCount() == 3)
    window.activateWindow()
    qtbot.keyClick(window, Qt.Key_F, Qt.ControlModifier)
    qtbot.waitUntil(window.search_text.hasFocus)
    window.search_text.setText("needle")
    qtbot.keyClick(window.search_text, Qt.Key_F3)
    qtbot.waitUntil(lambda: selected_message(window) == "needle newer")
    qtbot.keyClick(window.search_text, Qt.Key_F3)
    qtbot.waitUntil(lambda: selected_message(window) == "needle older")
    qtbot.keyClick(window.search_text, Qt.Key_F3, Qt.ShiftModifier)
    qtbot.waitUntil(lambda: selected_message(window) == "needle newer")


def test_firewall_status_is_shown_and_rechecked(qtbot, tmp_path):
    from syslog_monitor.firewall import FirewallCheck, Level

    calls = []
    results = [FirewallCheck(Level.WARNING, "UDP 514 is not allowed",
                             ("Private: no allow rule for UDP 514",)),
               FirewallCheck(Level.OK, "UDP 514 is allowed")]

    def checker(host, port):
        calls.append((host, port))
        return results[min(len(calls), len(results)) - 1]

    service = CaptureService(tmp_path / "data", Settings(bind_host="0.0.0.0", port=0))
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST, firewall_checker=checker)
    qtbot.addWidget(win)
    try:
        qtbot.waitUntil(lambda: "not allowed" in win.firewall_label.text(), timeout=3000)
        assert calls == [("0.0.0.0", 0)]
        assert "Private: no allow rule" in win.firewall_label.toolTip()
        win.check_firewall()
        qtbot.waitUntil(lambda: "Firewall ✓" in win.firewall_label.text(), timeout=3000)
    finally:
        win.shutdown()
        service.shutdown()


def test_firewall_monitor_survives_broken_checker(qtbot):
    from syslog_monitor.firewall import Level
    from syslog_monitor.ui.firewall_status import FirewallMonitor

    def broken(host, port):
        raise RuntimeError("boom")

    monitor = FirewallMonitor(broken)
    with qtbot.waitSignal(monitor.checked, timeout=3000) as blocker:
        monitor.request("0.0.0.0", 514)
    assert blocker.args[0].level == Level.UNKNOWN
    assert "boom" in blocker.args[0].details[0]


def test_firewall_monitor_coalesces_requests(qtbot):
    import threading

    from syslog_monitor.firewall import FirewallCheck, Level
    from syslog_monitor.ui.firewall_status import FirewallMonitor

    gate = threading.Event()
    seen = []

    def slow(host, port):
        gate.wait(3)
        seen.append(port)
        return FirewallCheck(Level.OK, str(port))

    monitor = FirewallMonitor(slow)
    received = []
    monitor.checked.connect(lambda c: received.append(c.summary))
    for port in (1, 2, 3):
        monitor.request("0.0.0.0", port)
    gate.set()
    qtbot.waitUntil(lambda: len(received) == 2, timeout=3000)
    qtbot.wait(100)
    assert seen == [1, 3] and received == ["1", "3"]


def test_mcp_status_details_and_settings(qtbot, tmp_path, monkeypatch):
    import json as json_module
    from dataclasses import replace

    from PySide6.QtCore import QTimer

    from syslog_monitor import mcp_server
    from syslog_monitor.mcp_tools import LogTools
    from syslog_monitor.ui import main_window as main_window_module
    from syslog_monitor.ui.settings_dialog import SettingsDialog

    settings = Settings(bind_host="127.0.0.1", port=0, mcp_port=0)
    service = CaptureService(tmp_path / "data", settings)
    mcp = mcp_server.McpService(LogTools(service.db_path))
    mcp.apply_async(settings).join(30)
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST, mcp=mcp)
    qtbot.addWidget(win)
    try:
        assert f"MCP ✓ :{mcp.port}" in win.mcp_label.text()
        assert mcp.url in win.mcp_label.toolTip()
        assert "no authentication" in win.mcp_label.toolTip()

        details = []
        def click(text):
            box = QApplication.activeModalWidget()
            details.append(box.informativeText())
            next(b for b in box.buttons() if b.text() == text).click()

        QTimer.singleShot(0, lambda: click("Copy configuration"))
        win.show_mcp_details()
        copied = json_module.loads(QApplication.clipboard().text())
        assert copied["servers"]["syslog-monitor"]["url"] == mcp.url
        assert "unauthenticated" in details[0]
        assert "other local programs" in details[0]
        assert "external provider" in details[0]

        dialog = SettingsDialog(settings)
        assert dialog.mcp_enabled.isChecked() and dialog.boot_marker.text() == "Initializing system"
        assert "Other programs" in dialog.mcp_enabled.toolTip()
        dialog.mcp_enabled.setChecked(False)
        assert not dialog.mcp_port.isEnabled()
        dialog.boot_marker.setText(" booted; started ")
        new = dialog.result_settings()
        assert (new.mcp_enabled, new.boot_marker) == (False, "booted; started")

        class FakeDialog:
            def __init__(self, *_):
                pass

            def exec(self):
                return True

            def result_settings(self):
                return new

        monkeypatch.setattr(main_window_module, "SettingsDialog", FakeDialog)
        win.open_settings()
        assert not mcp.running and mcp.tools.boot_marker == "booted; started"
        assert "MCP off" in win.mcp_label.text()

        new = replace(new, mcp_enabled=True)
        win.open_settings()
        assert mcp.running and "MCP ✓" in win.mcp_label.text()
    finally:
        win.shutdown()
        mcp.stop()
        service.shutdown()


def test_without_mcp_the_status_label_is_hidden(window):
    assert window.mcp is None and window.mcp_label.isHidden()
