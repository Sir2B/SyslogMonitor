from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from syslog_monitor.query import MessageFrequency, MessageStatistics
from syslog_monitor.ui.message_inspector import (
    MODE_EXACT, MODE_PATTERN, MessageInspector, format_bucket,
)
from conftest import make_event


def test_inspector_groups_message_cards_and_expandable_raw_data(qtbot):
    inspector = MessageInspector()
    qtbot.addWidget(inspector)
    inspector.resize(1200, 260)
    inspector.show()
    inspector.show_event(make_event(message="selected message <script>"))
    assert "selected message <script>" in inspector.details.toPlainText()
    qtbot.waitUntil(lambda: inspector.details.verticalScrollBar().maximum() == 0)
    assert inspector.raw.isHidden()
    qtbot.mouseClick(inspector.toggle, Qt.LeftButton)
    assert inspector.raw.isVisible()
    assert inspector.toggle.arrowType() == Qt.DownArrow
    inspector.clear()
    assert not inspector.raw.toPlainText()
    assert not inspector.details.toPlainText()
    assert not inspector.statistics_text()


def _stats():
    return MessageStatistics(0, 3_600_000, MessageFrequency(2, 2, 0, (1, 0, 1)),
                             MessageFrequency(5, 5, 0, (3, 0, 2)), r"^value=-?\d+(?:\.\d+)?$",
                             1_200_000)


def test_statistics_mode_switch_graph_and_regex(qtbot):
    inspector = MessageInspector()
    qtbot.addWidget(inspector)
    inspector.resize(1200, 260)
    inspector.show()
    modes = []
    inspector.mode_changed.connect(modes.append)
    inspector.show_statistics(_stats(), ["Regex", "<script>not markup</script>"], marker_ms=1_000)
    assert inspector.mode == MODE_EXACT
    assert "Occurrences: 2" in inspector.summary.text()
    assert inspector.graph.series == (1, 0, 1)
    assert inspector.regex_row.isHidden()
    assert "Identical text · 2" in inspector.statistics_text()
    assert "Pattern (regex) · 5" in inspector.statistics_text()
    assert "<script>not markup</script>" in inspector.statistics.toolTip()
    inspector.mode_buttons[MODE_PATTERN].click()
    assert modes == [MODE_PATTERN]
    assert "Occurrences: 5" in inspector.summary.text()
    assert inspector.graph.series == (3, 0, 2)
    assert inspector.regex_row.isVisible()
    assert inspector.regex.text() == r"^value=-?\d+(?:\.\d+)?$"
    inspector.copy_regex.click()
    assert QApplication.clipboard().text() == inspector.regex.text()
    assert "per 20 min" in inspector.footer.text()
    assert inspector.graph.bucket_at(inspector.graph.width() - 2) == 2
    assert "2 occurrences" in inspector.graph.bucket_tooltip(2)
    inspector.graph.grab()
    inspector.set_mode("bogus")
    assert inspector.mode == MODE_EXACT


def test_regex_editing_validates_applies_and_resets(qtbot):
    inspector = MessageInspector()
    qtbot.addWidget(inspector)
    inspector.show()
    inspector.set_mode(MODE_PATTERN)
    applied = []
    inspector.regex_changed.connect(applied.append)
    inspector.show_statistics(_stats(), [])
    assert not inspector.regex.isReadOnly()
    assert not inspector.reset_regex.isEnabled()
    inspector.regex.setFocus()
    inspector.regex.selectAll()
    qtbot.keyClicks(inspector.regex, "(")
    assert "Invalid regex" in inspector.regex.toolTip()
    qtbot.keyClick(inspector.regex, Qt.Key_Return)
    assert applied == []
    inspector.regex.selectAll()
    qtbot.keyClicks(inspector.regex, "^value")
    inspector.show_statistics(_stats(), [])  # refresh must not overwrite unapplied edits
    assert inspector.regex.text() == "^value"
    qtbot.keyClick(inspector.regex, Qt.Key_Return)
    assert applied == ["^value"]
    custom = MessageStatistics(0, 3_600_000, MessageFrequency(2, 2, 0, (1, 0, 1)),
                               MessageFrequency(4, 4, 0, (2, 0, 2)), "^value", 1_200_000, True)
    inspector.show_statistics(custom, [])
    assert "Custom regex · 4" in inspector.statistics_text()
    assert inspector.reset_regex.isEnabled()
    inspector.reset_regex.click()
    assert applied == ["^value", None]


def test_bucket_labels():
    assert format_bucket(1_000) == "1 s"
    assert format_bucket(300_000) == "5 min"
    assert format_bucket(7_200_000) == "2 h"
    assert format_bucket(86_400_000) == "1 d"


def test_inspector_keeps_raw_data_separate(qtbot):
    inspector = MessageInspector()
    qtbot.addWidget(inspector)
    inspector.resize(800, 260)
    inspector.show()
    inspector.toggle.setChecked(True)
    inspector.show_event(make_event(message="raw content"))
    assert inspector.raw.toPlainText() == "raw content"
