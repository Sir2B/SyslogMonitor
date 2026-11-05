import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from syslog_monitor.query import HighlightRule, Histogram
from syslog_monitor.ui.highlight_panel import HighlightPanel


def test_adding_editing_disabling_removing_and_ordering(qtbot):
    panel = HighlightPanel()
    qtbot.addWidget(panel)
    panel.show()
    first = panel.rule_rows[0]
    assert not first.up_button.isEnabled() and not first.down_button.isEnabled()
    qtbot.mouseClick(panel.add_rule_button, Qt.LeftButton)
    second = panel.rule_rows[1]
    assert second.rule().color != first.rule().color
    assert second.value.text() == ""
    with qtbot.waitSignal(panel.changed):
        second.value.setText("Watchdog")
    assert "Watchdog" in panel.notification_text()
    qtbot.mouseClick(second.up_button, Qt.LeftButton)
    assert panel.rule_rows[0] is second
    assert not second.up_button.isEnabled()
    second.enabled.click()
    assert "Watchdog" not in panel.notification_text()
    assert len(panel.rules()) == 2 and len(panel.active_rules()) == 1
    qtbot.mouseClick(first.remove_button, Qt.LeftButton)
    qtbot.mouseClick(second.remove_button, Qt.LeftButton)
    assert panel.rules() == () and panel.notification_text() == ""


def test_color_dialog_accept_and_cancel(qtbot, monkeypatch):
    panel = HighlightPanel()
    qtbot.addWidget(panel)
    row = panel.rule_rows[0]
    monkeypatch.setattr("syslog_monitor.ui.highlight_panel.QColorDialog.getColor",
                        lambda *args: QColor("#ffff00"))
    with qtbot.waitSignal(panel.changed):
        row.color_button.click()
    assert row.rule().color == "#ffff00"
    assert "color:#000000" in row.color_button.styleSheet()
    monkeypatch.setattr("syslog_monitor.ui.highlight_panel.QColorDialog.getColor",
                        lambda *args: QColor())
    row.color_button.click()
    assert row.rule().color == "#ffff00"


def test_state_roundtrip_preserves_empty_disabled_order_and_colors(qtbot):
    panel = HighlightPanel()
    qtbot.addWidget(panel)
    state = [{"text": "Boot", "color": "#123456", "enabled": False, "popup": False},
             {"text": "", "color": "#abcdef", "enabled": True, "popup": True}]
    panel.restore_state(state)
    assert panel.state() == state
    panel.restore_state([])
    assert panel.rules() == ()


def test_highlight_rows_are_compact_until_edited(qtbot):
    panel = HighlightPanel()
    qtbot.addWidget(panel)
    row = panel.rule_rows[0]
    assert panel._editors.isHidden()
    assert row.summary_button.text() == "Initializing system"
    row.edit_button.click()
    assert panel._editors.currentWidget() is row.editor and not panel._editors.isHidden()
    row.edit_button.click()
    assert panel._editors.isHidden()


def test_popup_notifications_are_selected_per_rule(qtbot):
    panel = HighlightPanel()
    qtbot.addWidget(panel)
    panel.restore_state([
        {"text": "boot", "color": "#7b1fa2", "enabled": True, "popup": False},
        {"text": "watchdog", "color": "#00796b", "enabled": True, "popup": True},
        {"text": "noise", "color": "#1565c0", "enabled": False, "popup": True},
    ])
    assert panel.notification_text() == "watchdog"


def test_highlight_chips_flow_side_by_side_with_embedded_pencil(qtbot):
    panel = HighlightPanel()
    qtbot.addWidget(panel)
    panel.resize(600, 180)
    panel.show()
    first = panel.rule_rows[0]
    second = panel.add_rule(HighlightRule("Second rule", "#00796b"))
    qtbot.waitUntil(lambda: second.geometry().y() > first.geometry().y())
    assert first.geometry().y() == panel.add_rule_button.geometry().y()
    assert first.edit_button.parentWidget() is first.chip


def test_counts_follow_rule_order_including_duplicates_and_inactive_rows(qtbot):
    panel = HighlightPanel()
    qtbot.addWidget(panel)
    panel.restore_state([
        {"text": "Boot", "color": "#123456", "enabled": False},
        {"text": "Boot", "color": "#123456", "enabled": True},
        {"text": "", "color": "#abcdef", "enabled": True},
        {"text": "Boot", "color": "#123456", "enabled": True},
    ])
    histogram = Histogram(0, 100, highlight_rules=panel.active_rules(),
                          highlight_counts=[[1000, 0], [234, 0]])
    panel.set_counts(histogram)
    assert [row.count_label.text() for row in panel.rule_rows] == ["–", "1,234", "–", "0"]
    assert "filters and time range" in panel.rule_rows[1].count_label.toolTip()
    panel.rule_rows[1].value.setText("changed")
    panel.invalidate_counts()
    assert [row.count_label.text() for row in panel.rule_rows] == ["–", "…", "–", "…"]
    panel.set_counts(histogram)
    assert panel.rule_rows[1].count_label.text() == "…"


@pytest.mark.parametrize(("language", "expected"), [
    ("en", "Average: 2.00 matches/hour; standard deviation: 2.00 matches/hour."),
    ("de", "Durchschnitt: 2.00 Treffer/Stunde; Standardabweichung: 2.00 Treffer/Stunde."),
])
def test_hourly_statistics_are_shown_in_tooltip(qtbot, language, expected):
    from syslog_monitor.i18n import set_language

    set_language(language)
    try:
        panel = HighlightPanel()
        qtbot.addWidget(panel)
        hist = Histogram(0, 7_200_000, highlight_rules=panel.active_rules(),
                         highlight_counts=[[4]], highlight_hourly_counts=[{1: 4}])
        panel.set_counts(hist)
        assert panel.rule_rows[0].count_label.text() == "4"
        assert expected in panel.rule_rows[0].count_label.toolTip()
    finally:
        set_language("en")


@pytest.mark.parametrize("state", [None, {}, [None], [{"color": "red"}],
                                      [{"text": "x", "enabled": "false"}]])
def test_bad_state_does_not_destroy_existing_rules(qtbot, state):
    panel = HighlightPanel()
    qtbot.addWidget(panel)
    before = panel.rules()
    with pytest.raises((TypeError, ValueError)):
        panel.restore_state(state)
    assert panel.rules() == before == (HighlightRule("Initializing system"),)
