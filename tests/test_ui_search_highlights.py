"""GUI integration tests: search highlights."""

import time
from conftest import send_udp
from PySide6.QtCore import QSettings, Qt
from syslog_monitor.config import Settings
from syslog_monitor.service import CaptureService
from syslog_monitor.matching import MatchOptions
from syslog_monitor.query import FilterRule, HighlightRule, QueryRunner
from syslog_monitor.ui.main_window import PAGE_SIZE, MainWindow
from syslog_monitor.writer import WriterTuning
from ui_test_helpers import FAST, selected_message, send


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
        watchdog_rule = win.highlights.rule_rows[1]
        qtbot.waitUntil(lambda: win._watch_after_id is not None, timeout=5000)
        qtbot.wait(200)
        assert shown == []  # history is not announced
        win.hide()
        send_udp(service.bound_port, b"<15>1 - plc-01 app - - - WATCHDOG reset",
                 b"<14>1 - plc-01 app - - - normal info")
        qtbot.waitUntil(lambda: len(shown) == 1, timeout=5000)
        assert shown[0][0] == "Highlight: 1 new message"
        assert "plc-01: WATCHDOG reset" in shown[0][1]

        watchdog_rule.popup_checkbox.setChecked(False)
        send_udp(service.bound_port, b"<15>1 - plc-01 app - - - watchdog again")
        qtbot.waitUntil(lambda: service.snapshot().persisted == 4, timeout=5000)
        qtbot.wait(300)
        assert len(shown) == 1
        win._save_ui_state()
        watchdog_rule.popup_checkbox.setChecked(True)
        win._restore_ui_state()
        assert not win.highlights.rule_rows[1].popup_checkbox.isChecked()
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


def test_legacy_global_popup_setting_migrates_to_per_rule_preferences(qtbot, window):
    window._ui_state.setValue("highlight_popup", False)
    window._ui_state.setValue(
        "highlight_rules",
        '[{"text":"boot","color":"#7b1fa2","enabled":true},'
        '{"text":"watchdog","color":"#00796b","enabled":true}]',
    )
    window._restore_ui_state()
    assert [rule.popup for rule in window.highlights.rules()] == [False, False]
    assert window.highlights.notification_text() == ""


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


def test_highlight_navigation_steps_through_rule_terms(qtbot, window):
    row = window.highlights.rule_rows[0]
    row.value.setText("needle;alarm")
    window.highlights.select_rule(row)
    send(window, "<11>1 - h app - - - alarm first", "<14>1 - h app - - - context",
         "<11>1 - h app - - - needle second", "<11>1 - h app - - - alarm newest")
    qtbot.waitUntil(lambda: window.model.rowCount() == 4)
    qtbot.mouseClick(window.highlights.next_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: selected_message(window) == "alarm newest")
    qtbot.mouseClick(window.highlights.next_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: selected_message(window) == "needle second")
    qtbot.mouseClick(window.highlights.previous_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: selected_message(window) == "alarm newest")


def test_search_and_text_filter_can_be_combined(qtbot, window):
    send(window, "<14>keep context", "<11>keep needle: code_17", "<11>other needle")
    qtbot.waitUntil(lambda: window.model.rowCount() == 3)
    window.filter_bar.add_rule(FilterRule("text", "words", "keep"))
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    window.search_text.setText("e_17")
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


def test_search_match_options_regex_case_word_and_persistence(qtbot, window, tmp_path):
    send(window, "<14>Port 22 up", "<14>port 220 down", "<14>context")
    qtbot.waitUntil(lambda: window.model.rowCount() == 3)
    window.search_text.setText("port 22")
    window.search_text.setFocus()
    qtbot.keyClick(window.search_text, Qt.Key_W, Qt.AltModifier)
    assert window.search_options.word_button.isChecked()
    window.find_text()
    qtbot.waitUntil(lambda: selected_message(window) == "Port 22 up")
    window.search_options.case_button.click()
    window.find_text()
    qtbot.waitUntil(lambda: window.search_result.text() == "No matches")
    window.search_options.set_options(MatchOptions(regex=True))
    window.search_text.setText(r"port \d{3}")
    window.find_text()
    qtbot.waitUntil(lambda: selected_message(window) == "port 220 down")
    window.search_text.setText("port (")
    assert window.search_options.error() and "border" in window.search_text.styleSheet()
    window.find_text()
    assert window.search_result.text() == "Invalid regex"
    window._save_ui_state()
    window.search_options.set_options(MatchOptions())
    window._restore_ui_state()
    assert window.search_options.options() == MatchOptions(regex=True)


def test_highlight_rule_match_options_color_rows_and_navigate(qtbot, window):
    row = window.highlights.rule_rows[0]
    row.value.setText(r"err\w+")
    row.match_options.regex_button.click()
    window.highlights.select_rule(row)
    send(window, "<14>errors found", "<14>err only", "<14>ERRORS again")
    qtbot.waitUntil(lambda: window.model.rowCount() == 3)
    colored = {window.model.row_at(i).message for i in range(3)
               if window.model.data(window.model.index(i, 6), Qt.BackgroundRole).color().name()
               == row.rule().color}
    assert colored == {"errors found", "ERRORS again"}
    qtbot.mouseClick(window.highlights.next_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: selected_message(window) == "ERRORS again")
    assert "· .*" in row.summary_button.text()
    stored = window.highlights.state()[0]
    assert stored["regex"] is True and stored["case_sensitive"] is False
