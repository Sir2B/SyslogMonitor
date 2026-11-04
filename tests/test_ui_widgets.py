from conftest import BASE_MS, make_event

from syslog_monitor.query import TEXT_MODE_SUBSTRING, EventFilter, FilterRule, QueryRunner
from syslog_monitor.ui.filter_bar import FilterBar
from syslog_monitor.ui.formatting import format_bytes, format_count, format_event_details


def test_format_helpers():
    assert format_bytes(512) == "512 B"
    assert format_bytes(5 * 1024**3) == "5.0 GiB"
    assert format_count(1234567) == "1,234,567"


def test_filter_dropdowns_have_equal_height(qtbot):
    bar = FilterBar()
    qtbot.addWidget(bar)
    bar.show()
    assert bar.severity_button.height() == bar.facility.height() == bar.rules_match.height()


def test_rule_delete_controls_remain_visible_without_hover(qtbot):
    from PySide6.QtCore import QEvent, QPointF
    from PySide6.QtGui import QEnterEvent
    from PySide6.QtWidgets import QApplication

    from syslog_monitor.ui.highlight_panel import HighlightPanel

    bar = FilterBar()
    highlights = HighlightPanel()
    for panel in (bar, highlights):
        qtbot.addWidget(panel)
        panel.show()
    filter_row = bar.add_rule(FilterRule(value="example"))
    for row in (filter_row, highlights.rule_rows[0]):
        QApplication.sendEvent(row, QEvent(QEvent.Leave))
        assert not row.remove_button.isHidden()
        before = row.sizeHint()
        QApplication.sendEvent(row, QEnterEvent(QPointF(1, 1), QPointF(1, 1), QPointF(1, 1)))
        assert not row.remove_button.isHidden()
        assert row.sizeHint() == before
        assert row.remove_button.parentWidget() is row.chip
        assert row.editor.layout().indexOf(row.remove_button) == -1
        QApplication.sendEvent(row, QEvent(QEvent.Leave))
        assert not row.remove_button.isHidden()
        assert row.sizeHint() == before
    filter_row.remove_button.click()
    assert bar.rule_rows == []
    highlights.rule_rows[0].remove_button.click()
    assert highlights.rule_rows == []


def test_flow_layout_keeps_items_together_until_they_overflow(qtbot):
    from PySide6.QtWidgets import QPushButton, QWidget

    from syslog_monitor.ui.flow_layout import FlowLayout

    panel = QWidget()
    layout = FlowLayout(panel, horizontal_spacing=0, vertical_spacing=0)
    buttons = [QPushButton(f"Item {i}") for i in range(3)]
    for button in buttons:
        button.setFixedSize(60, 24)
        layout.addWidget(button)
    qtbot.addWidget(panel)
    panel.resize(150, 60)
    panel.show()
    qtbot.waitUntil(lambda: buttons[2].geometry().top() > buttons[0].geometry().top())
    assert buttons[0].geometry().top() == buttons[1].geometry().top()
    assert buttons[2].geometry().top() > buttons[1].geometry().top()


def test_event_details_contains_everything():
    ev = make_event(0, severity=None, facility=None, message="hello")
    ev.issues = ("no_pri",)
    ev.raw = b"hello \xff"
    text = format_event_details(ev)
    assert "Severity:       Unknown" in text
    assert "No PRI header" in text
    assert "hello \\xff" in text
    assert "192.0.2.1:514" in text


def test_filter_bar_builds_filter_and_roundtrips_state(qtbot):
    bar = FilterBar()
    qtbot.addWidget(bar)
    assert bar.current_filter() == EventFilter()
    with qtbot.waitSignal(bar.changed, timeout=2000):
        bar.add_rule(FilterRule("text", "contains", "disk full"))
    bar.set_severities({0, 1, 2, 3})
    bar.add_rule(FilterRule("sender", "contains", "192.0.2."))
    bar.facility.setCurrentIndex(bar.facility.findData(1))
    f = bar.current_filter()
    assert f.rules == (FilterRule("text", "contains", "disk full"),
                       FilterRule("sender", "contains", "192.0.2."))
    assert f.facility == 1
    assert f.severities == frozenset({0, 1, 2, 3})
    assert bar.severity_button.text() == "Severity: errors"

    state = bar.state()
    other = FilterBar()
    qtbot.addWidget(other)
    with qtbot.assertNotEmitted(other.changed, wait=400):
        other.restore_state(state)
    assert other.current_filter() == f

    with qtbot.waitSignal(bar.changed):
        bar.reset()
    assert bar.current_filter() == EventFilter()


def test_filter_bar_unknown_severity(qtbot):
    bar = FilterBar()
    qtbot.addWidget(bar)
    bar.set_severities({None})
    assert bar.current_filter().severities == frozenset({None})
    restored = FilterBar()
    qtbot.addWidget(restored)
    restored.restore_state(bar.state())
    assert restored.current_filter().severities == frozenset({None})


def test_rule_rows_roundtrip_remove_and_reset(qtbot):
    bar = FilterBar()
    other = FilterBar()
    qtbot.addWidget(bar)
    qtbot.addWidget(other)
    bar.add_rule_button.click()
    row = bar.rule_rows[0]
    assert row.editor.isHidden()
    row.edit_button.click()
    assert bar._editors.currentWidget() is row.editor and not bar._editors.isHidden()
    row.value.setText("heartbeat")
    row.operator.setCurrentIndex(row.operator.findData("not_contains"))
    bar.add_rule(FilterRule("app", "equals", "db"))
    bar.rules_match.setCurrentIndex(1)
    with qtbot.waitSignal(bar.changed, timeout=2000):
        row.value.setText("poll")
    f = bar.current_filter()
    assert f.rules == (FilterRule("message", "not_contains", "poll"),
                       FilterRule("app", "equals", "db"))
    assert f.rules_match == "any"
    with qtbot.assertNotEmitted(other.changed, wait=400):
        other.restore_state(bar.state())
    assert other.current_filter() == f
    with qtbot.waitSignal(other.changed, timeout=2000):
        other.rule_rows[0].remove_button.click()
    assert other.current_filter().rules == (FilterRule("app", "equals", "db"),)
    other.reset()
    assert other.current_filter() == EventFilter()
    assert not other.rule_rows


def test_filter_rule_row_has_compact_summary_and_toggleable_editor(qtbot):
    bar = FilterBar()
    qtbot.addWidget(bar)
    row = bar.add_rule(FilterRule("text", "words", "disk fail", required=True))
    assert row.editor.isHidden()
    assert "Text (all fields) contains all words: disk fail" in row.summary_button.text()
    assert "Always AND" in row.summary_button.text()
    row.edit_button.click()
    assert bar._editors.currentWidget() is row.editor and not bar._editors.isHidden()
    row.value.setText("kernel panic")
    assert "kernel panic" in row.summary_button.text()
    row.summary_button.click()
    assert bar._editors.currentWidget() is row.editor
    row.edit_button.click()
    assert bar._editors.isHidden()


def test_filter_rule_chips_flow_side_by_side_with_embedded_pencil(qtbot):
    bar = FilterBar()
    qtbot.addWidget(bar)
    bar.resize(760, 180)
    bar.show()
    first = bar.add_rule(FilterRule(value="first"))
    second = bar.add_rule(FilterRule(value="second"))
    qtbot.waitUntil(lambda: second.geometry().y() > first.geometry().y())
    assert first.geometry().y() == bar.add_rule_button.geometry().y()
    assert first.edit_button.parentWidget() is first.chip


def test_restore_ignores_invalid_saved_rules(qtbot):
    bar = FilterBar()
    qtbot.addWidget(bar)
    bar.restore_state({"rules": [{"field": "bogus", "operator": "contains", "value": "x"},
                                 {"unknown": 1},
                                 {"field": "app", "operator": "not_equals", "value": "db"}]})
    assert bar.current_filter().rules == (FilterRule("app", "not_equals", "db"),)


def test_legacy_filters_migrate_without_changing_or_semantics(qtbot, store):
    events = [
        make_event(0, message="disk failure", app_name="web", severity=3),
        make_event(1, message="disk failure", app_name="db", severity=6),
        make_event(2, message="disk failure", app_name="other", severity=7),
        make_event(3, message="other message", app_name="web", severity=3),
    ]
    store.insert(events)
    bar = FilterBar()
    qtbot.addWidget(bar)
    bar.restore_state({
        "text": "disk fail", "sender": "192.0.2.", "rules_match": "any",
        "rules": [{"field": "app", "operator": "equals", "value": "web"},
                  {"field": "app", "operator": "equals", "value": "db"}],
    })
    f = bar.current_filter()
    assert f.text == f.sender == ""
    assert f.rules[-2:] == (FilterRule("text", "words", "disk fail", required=True),
                            FilterRule("sender", "contains", "192.0.2.", required=True))
    with_runner = QueryRunner(store.path)
    try:
        assert {r.app_name for r in with_runner.fetch_older(f, None, 20)} == {"web", "db"}
        assert with_runner.histogram(f, BASE_MS, BASE_MS + 4, 4).total == 2
    finally:
        with_runner.close()
    state = bar.state()
    assert "text" not in state and "sender" not in state and "mode" not in state
    bar.restore_state(state)
    assert bar.current_filter() == f


def test_legacy_substring_and_app_migrate(qtbot):
    bar = FilterBar()
    qtbot.addWidget(bar)
    bar.restore_state({"text": "code_17", "mode": TEXT_MODE_SUBSTRING, "app": "web"})
    assert bar.current_filter().rules == (
        FilterRule("text", "contains", "code_17"), FilterRule("app", "contains", "web"))


def test_word_operators_follow_field_and_required_roundtrips(qtbot):
    bar = FilterBar()
    qtbot.addWidget(bar)
    row = bar.add_rule(FilterRule("text", "words", "disk", required=True))
    assert row.rule().operator == "words"
    row.field.setCurrentIndex(row.field.findData("message"))
    assert row.operator.findData("words") == -1
    assert row.rule().field == "message"
    assert row.rule().required
    row.field.setCurrentIndex(row.field.findData("text"))
    assert row.operator.findData("words") >= 0


def test_app_icon_exports_multi_resolution_ico(qtbot):
    import struct

    from PySide6.QtGui import QImage

    from syslog_monitor.ui.icons import ICO_SIZES, app_ico_bytes, app_icon
    assert not app_icon().isNull()
    data = app_ico_bytes()
    reserved, kind, count = struct.unpack_from("<HHH", data)
    assert (reserved, kind, count) == (0, 1, len(ICO_SIZES))
    for i, size in enumerate(ICO_SIZES):
        width, _h, _c, _r, _planes, _bpp, length, offset = struct.unpack_from("<BBBBHHII", data, 6 + 16 * i)
        assert width == (0 if size == 256 else size)
        image = QImage.fromData(data[offset:offset + length], "PNG")
        assert (image.width(), image.height()) == (size, size)
