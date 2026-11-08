"""GUI integration tests: inspector controller."""

from PySide6.QtCore import Qt
from syslog_monitor.query import FilterRule, QueryRunner
from ui_test_helpers import send


def test_selected_message_statistics_split_exact_and_numeric_family(qtbot, window):
    send(window, "<14>temperature=24.3", "<14>temperature=24.3", "<14>temperature=99.5",
         "<14>unrelated")
    qtbot.waitUntil(lambda: window.model.rowCount() == 4)
    window.set_live(False)
    window.table.setCurrentIndex(window.model.index(1, 0))
    qtbot.waitUntil(lambda: "Pattern (regex) · 3" in window.inspector.statistics_text())
    text = window.inspector.statistics_text()
    assert "Identical text · 1" in text and "Occurrences: 1" in text
    assert "/h" in text and "Standard deviation:" in window.inspector.summary.toolTip()
    window.inspector.mode_buttons["pattern"].click()
    assert window.inspector.regex.text() == r"^temperature=-?\d+(?:\.\d+)?$"
    assert sum(window.inspector.graph.series) == 3
    window._save_ui_state()
    assert window._ui_state.value("statistics_mode") == "pattern"
    window.inspector.regex.setText(r"^temperature=24")
    window.inspector.regex.returnPressed.emit()
    qtbot.waitUntil(lambda: "Custom regex · 2" in window.inspector.statistics_text())
    assert "Identical text · 1" in window.inspector.statistics_text()
    window.inspector.reset_regex.click()
    qtbot.waitUntil(lambda: "Pattern (regex) · 3" in window.inspector.statistics_text())
    assert "temperature=99.5" in window.details.toPlainText()
    assert window.splitter.orientation() == Qt.Vertical
    assert window.splitter.widget(0) is window.table
    assert window.splitter.widget(1) is window.inspector
    assert "temperature=99.5" in window.details.toPlainText()
    assert not window.inspector.raw.isVisible()
    window.inspector.toggle.click()
    assert window.inspector.raw.isVisible()
    window.inspector_action.setChecked(False)
    assert not window.inspector.isVisible()
    window.inspector_action.setChecked(True)
    window.table.setCurrentIndex(window.model.index(0, 0))
    qtbot.waitUntil(lambda: "^unrelated$" in window.inspector.statistics_text())
    assert "temperature=" not in window.inspector.statistics_text()
    window.filter_bar.add_rule(FilterRule(value="does not exist"))
    qtbot.waitUntil(lambda: window.model.rowCount() == 0)
    assert not window.inspector.statistics_text()


def test_statistics_errors_are_visible(qtbot, window, monkeypatch):
    def fail(*args):
        raise RuntimeError("statistics test failure")

    monkeypatch.setattr(QueryRunner, "message_statistics", fail)
    send(window, "<14>sample")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1)
    window.table.setCurrentIndex(window.model.index(0, 0))
    qtbot.waitUntil(lambda: "Statistics failed: statistics test failure" in window.inspector.statistics_text())


def test_inspector_visibility_and_bottom_layout_restore(window):
    window.inspector_action.setChecked(False)
    window._save_ui_state()
    assert window._ui_state.value("inspector_visible") is False
    window.inspector_action.setChecked(True)
    window._restore_ui_state()
    assert not window.inspector_action.isChecked()
    assert window.inspector.isHidden()
    assert window.splitter.orientation() == Qt.Vertical


def test_statistics_refresh_for_paused_view_without_reloading_rows(qtbot, window):
    send(window, "<14>value 1")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1)
    window.set_live(False)
    window.table.setCurrentIndex(window.model.index(0, 0))
    qtbot.waitUntil(lambda: "Occurrences: 1" in window.inspector.statistics_text())
    send(window, "<14>value 2")
    qtbot.waitUntil(lambda: window.service.snapshot().persisted == 2)
    window.inspector_controller.timer.start(0)
    qtbot.waitUntil(lambda: "Pattern (regex) · 2" in window.inspector.statistics_text())
    assert window.model.rowCount() == 1
    assert "value 1" in window.details.toPlainText()


def test_slow_statistics_do_not_block_details_or_publish_stale_selection(qtbot, window, monkeypatch):
    from threading import Event

    started, release = Event(), Event()
    original = QueryRunner.message_statistics

    def delayed(runner, filters, row, now, regex=None):
        if row.message == "old selection":
            started.set()
            if not release.wait(5):
                raise TimeoutError("Test did not release statistics worker")
        return original(runner, filters, row, now, regex)

    monkeypatch.setattr(QueryRunner, "message_statistics", delayed)
    send(window, "<14>old selection", "<14>new selection")
    qtbot.waitUntil(lambda: window.model.rowCount() == 2)
    window.set_live(False)
    try:
        window.table.setCurrentIndex(window.model.index(1, 0))
        qtbot.waitUntil(started.is_set)
        qtbot.waitUntil(lambda: "old selection" in window.details.toPlainText())
        window.table.setCurrentIndex(window.model.index(0, 0))
        qtbot.waitUntil(lambda: "new selection" in window.details.toPlainText())
        window.inspector.set_mode("pattern")
        release.set()
        qtbot.waitUntil(lambda: "^new selection$" in window.inspector.statistics_text())
        assert "old selection" not in window.inspector.statistics_text()
    finally:
        release.set()
