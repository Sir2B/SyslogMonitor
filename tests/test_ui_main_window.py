"""End-to-end GUI tests: real UDP traffic through service, database and window."""

import time
import csv
import io

import pytest
from conftest import BASE_MS, make_event, send_udp
from PySide6.QtCore import QPoint, QSettings, Qt, QTimer
from PySide6.QtGui import QTextDocument
from PySide6.QtWidgets import QApplication

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


def test_client_checks_dialog_keeps_normal_receiver_unchanged(qtbot, window):
    original_port = window.service.bound_port
    window.diagnostics_action.trigger()
    dialog = window._diagnostics_dialog
    assert dialog is not None
    assert window.current_page == "validation"
    assert window.service.bound_port == original_port
    window.show_page("logs")
    assert window._diagnostics_dialog is dialog
    send(window, "<134>Nov  6 00:00:00 client app: normal reception")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1)


def test_sidebar_navigation_is_compact_expandable_and_stateful(qtbot, window):
    assert window.current_page == "logs"
    assert list(window.sidebar.buttons) == [
        "logs", "export", "validation", "latest", "autoscroll", "receive", "settings", "about", "quit"]
    collapsed_width = window.sidebar.width()
    compact_icon = window.sidebar.buttons["logs"].iconSize()
    assert all(not button.icon().isNull() for button in window.sidebar.buttons.values())
    assert window.sidebar.buttons["logs"].toolButtonStyle() == Qt.ToolButtonIconOnly
    qtbot.mouseClick(window.sidebar.toggle, Qt.LeftButton)
    qtbot.waitUntil(lambda: window.sidebar.width() > collapsed_width)
    assert window.sidebar.buttons["logs"].iconSize().width() > compact_icon.width()
    assert window.sidebar.buttons["logs"].toolButtonStyle() == Qt.ToolButtonTextBesideIcon
    assert all(button.accessibleName() and button.toolTip()
               for button in window.sidebar.buttons.values())
    window._save_ui_state()
    assert window._ui_state.value("sidebar_expanded") is True
    window.sidebar.set_expanded(False)
    window._ui_state.setValue("sidebar_expanded", True)
    window._restore_ui_state()
    assert window.sidebar.expanded
    for name in ("export", "settings", "about", "validation", "quit", "logs"):
        qtbot.mouseClick(window.sidebar.buttons[name], Qt.LeftButton)
        assert window.current_page == name
        assert window.pages.currentWidget() is window._pages[name]
        assert window.sidebar.buttons[name].isChecked()
        assert sum(window.sidebar.buttons[key].isChecked()
                   for key in ("logs", "export", "settings", "about", "validation", "quit")) == 1
    assert QApplication.activeModalWidget() is None


def test_sidebar_stays_expanded_across_zoom_and_page_creation(qtbot, window):
    rail = window.sidebar
    try:
        rail.set_expanded(True)
        qtbot.waitUntil(lambda: rail.width() > 100)
        expanded_width = rail.width()
        window.zoom_controller.set_zoom(1.5)
        window.show_page("about")
        qtbot.waitUntil(lambda: rail.width() > expanded_width)
        assert rail.buttons["logs"].iconSize().width() > 26
        rail.set_expanded(False)
        qtbot.waitUntil(lambda: rail.width() < expanded_width)
        window.show_page("settings")
        QApplication.processEvents()
        assert rail.width() < expanded_width
        window.focus_search()
        assert window.current_page == "logs" and window.search_text.hasFocus()
    finally:
        window.zoom_controller.set_zoom(1.0)


def test_log_controls_are_in_separate_middle_sidebar_group_without_top_toolbar(window):
    from PySide6.QtWidgets import QToolBar

    assert not window.findChildren(QToolBar)
    assert window.sidebar.buttons["latest"].defaultAction() is window.latest_action
    assert window.sidebar.buttons["autoscroll"].defaultAction() is window.live_action
    layout = window.sidebar.widget().layout()
    latest_index = layout.indexOf(window.sidebar.buttons["latest"])
    autoscroll_index = layout.indexOf(window.sidebar.buttons["autoscroll"])
    assert layout.itemAt(latest_index - 1).spacerItem() is not None
    assert layout.itemAt(autoscroll_index + 1).spacerItem() is not None
    assert window.log_page.layout().itemAt(0).widget() is window.rules_splitter
    window.sidebar.buttons["autoscroll"].click()
    assert not window._live
    window.sidebar.buttons["latest"].click()
    assert not window._live and window.current_page == "logs"


def test_quit_page_distinguishes_minimize_and_exit(qtbot, window, monkeypatch):
    exited = []
    monkeypatch.setattr(window, "quit_application", lambda: exited.append(True))
    window.sidebar.buttons["quit"].click()
    assert window.current_page == "quit" and window.isVisible()
    QApplication.processEvents()
    minimize_position = window.minimize_button.mapTo(window, QPoint())
    exit_position = window.exit_button.mapTo(window, QPoint())
    assert minimize_position.y() == exit_position.y()
    assert minimize_position.x() + window.minimize_button.width() < exit_position.x()
    assert window.exit_button.height() >= 96
    assert window.exit_button.width() < window.pages.width() / 2
    assert "background: #b42318" in window.exit_button.styleSheet()
    assert not exited
    window.minimize_button.click()
    qtbot.waitUntil(window.isMinimized)
    assert window.service.listening and not exited
    window.show_and_raise()
    window.exit_button.click()
    assert exited == [True]


def test_about_and_settings_use_compact_top_left_content(qtbot, window):
    from syslog_monitor.ui.about_dialog import AboutDialog

    window.resize(1600, 1000)
    window.show_page("about")
    about = window._pages["about"].findChild(AboutDialog)
    qtbot.waitUntil(lambda: about.isVisible())
    QApplication.processEvents()
    assert about.width() <= 640
    assert about.height() < window.pages.height() / 2
    assert about.pos().x() == 0 and about.pos().y() == 0
    assert about.details_label.geometry().top() - about.version_label.geometry().bottom() < 30
    window.show_page("settings")
    settings = window._settings_page
    QApplication.processEvents()
    assert settings.width() <= 860
    assert settings.pos().x() == 0 and settings.pos().y() == 0
    assert settings.height() < settings.parentWidget().height()


@pytest.mark.parametrize("name", ["export", "validation"])
def test_export_and_validation_use_bounded_top_left_content(window, name):
    window.resize(1600, 1000)
    window.show_page(name)
    dialog = window._export_dialog if name == "export" else window._diagnostics_dialog
    QApplication.processEvents()
    assert dialog.width() <= 1000
    assert dialog.pos().x() == 0 and dialog.pos().y() == 0
    assert dialog.isVisible()


def test_embedded_validation_has_no_nested_form_scroll_area(window):
    from PySide6.QtWidgets import QScrollArea

    window.show_page("validation")
    assert not window._diagnostics_dialog.findChildren(QScrollArea)
    assert len(window._pages["validation"].findChildren(QScrollArea)) == 1


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


def test_statistics_refresh_for_paused_view_without_reloading_rows(qtbot, window):
    send(window, "<14>value 1")
    qtbot.waitUntil(lambda: window.model.rowCount() == 1)
    window.set_live(False)
    window.table.setCurrentIndex(window.model.index(0, 0))
    qtbot.waitUntil(lambda: "Occurrences: 1" in window.inspector.statistics_text())
    send(window, "<14>value 2")
    qtbot.waitUntil(lambda: window.service.snapshot().persisted == 2)
    window._statistics_timer.start(0)
    qtbot.waitUntil(lambda: "Pattern (regex) · 2" in window.inspector.statistics_text())
    assert window.model.rowCount() == 1
    assert "value 1" in window.details.toPlainText()


def test_slow_statistics_do_not_block_details_or_publish_stale_selection(qtbot, window, monkeypatch):
    from threading import Event

    started, release = Event(), Event()
    original = QueryRunner.message_statistics

    def delayed(runner, filters, row, now):
        if row.message == "old selection":
            started.set()
            if not release.wait(5):
                raise TimeoutError("Test did not release statistics worker")
        return original(runner, filters, row, now)

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


def test_minimize_to_tray_keeps_receiver_running(window):
    from types import SimpleNamespace

    notifications = []
    window.tray = SimpleNamespace(notify_hidden_once=lambda: notifications.append(True))
    try:
        window.show_page("quit")
        window.minimize_button.click()
        assert not window.isVisible()
        assert window.service.listening and notifications == [True]
    finally:
        window.tray = None


def test_sidebar_can_scroll_to_bottom_actions_in_small_windows(qtbot):
    from PySide6.QtGui import QAction
    from syslog_monitor.ui.navigation import NavigationRail

    rail = NavigationRail()
    qtbot.addWidget(rail)
    for name in ("logs", "export", "validation", "receive", "settings", "about", "quit"):
        rail.add_item(name, QAction(name, rail), page=name != "receive")
    rail.resize(rail.sizeHint().width(), 200)
    rail.show()
    qtbot.waitUntil(lambda: rail.verticalScrollBar().maximum() > 0)
    last = rail.buttons["quit"]
    rail.ensureWidgetVisible(last)
    qtbot.waitUntil(lambda: rail.viewport().rect().contains(last.mapTo(rail.viewport(), last.rect().center())))


def test_validation_continues_across_navigation_and_settings_apply(qtbot, window):
    window.show_page("validation")
    dialog = window._diagnostics_dialog
    dialog.host.setText("127.0.0.1")
    dialog.client.setText("127.0.0.1")
    dialog.ssh_enabled.setChecked(False)
    dialog.port.setMinimum(0)
    dialog.port.setValue(0)
    dialog.start_check()
    qtbot.waitUntil(lambda: "Listening" in dialog.status.text())
    worker = dialog.worker
    window.show_page("settings")
    assert worker.isRunning() and not worker.cancel.is_set()
    settings = window._settings_page
    settings.theme.setCurrentIndex(settings.theme.findData("dark"))
    test_port = window.service.bound_port
    settings.port.setValue(test_port)
    settings.accept()
    assert window.service.settings.theme == "dark"
    assert window.service.settings.port == test_port
    assert window.current_page == "settings" and settings.isVisible()
    settings.theme.setCurrentIndex(settings.theme.findData("system"))
    settings.accept()
    window.show_page("validation")
    assert window._diagnostics_dialog is dialog
    dialog.stop_check()
    qtbot.waitUntil(lambda: dialog.worker is None)


def test_export_page_keeps_options_and_refreshes_filter_context(window):
    window.show_page("export")
    dialog = window._export_dialog
    dialog.format.setCurrentIndex(dialog.format.findData("jsonl"))
    window.show_page("logs")
    window.filter_bar.add_rule(FilterRule(value="router"))
    window.show_page("export")
    assert dialog is window._export_dialog
    assert dialog.format.currentData() == "jsonl"
    assert dialog._filters == window.filter_bar.current_filter()
    dialog.reject()
    assert dialog.isVisible()


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


def test_time_controls_are_grouped_with_minimap(qtbot, window):
    section = window.minimap.parentWidget()
    assert window.range_combo.parentWidget() is section
    assert window.reset_zoom_button.parentWidget() is section
    assert window.minimap_range_label.parentWidget() is section
    assert window.legend.parentWidget() is section
    assert window.range_combo.geometry().bottom() < window.minimap.geometry().top()
    assert window.legend.geometry().bottom() < window.minimap.geometry().top()
    # Highlight rules form an independent compact list, like the filter rules.
    assert window.highlights._editors.isHidden()
    assert window.highlights.rule_rows[0].summary_button.isVisible()
    assert window.filters_scroll.geometry().right() < window.highlights_scroll.geometry().left()
    assert window.rules_splitter.geometry().bottom() < section.geometry().top()
    assert window.splitter.width() == window.rules_splitter.width()
    assert window.mode_label.parentWidget() is window.statusBar()
    assert window.rules_splitter.handleWidth() == 17
    assert "palette(mid)" in window.rules_splitter.styleSheet()
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
    def settle_rules_layout():
        # The panel height is updated by a timer before its parent layout is recalculated.
        qtbot.waitUntil(lambda: not window._rules_height_timer.isActive())
        window.centralWidget().layout().activate()
        qtbot.wait(100)

    window.resize(1300, 750)
    qtbot.wait(20)
    settle_rules_layout()
    height = window.rules_splitter.height()
    table_height = window.table.height()
    for i in range(12):
        window.highlights.add_rule(HighlightRule(f"highlight {i}"))
        window.filter_bar.add_rule(FilterRule(value=f"filter {i}"))
    qtbot.waitUntil(lambda: window.highlights_scroll.verticalScrollBar().maximum() > 0
                    and window.filters_scroll.verticalScrollBar().maximum() > 0)
    settle_rules_layout()
    qtbot.waitUntil(lambda: window.rules_splitter.height() >= height)
    assert window.rules_splitter.height() >= height
    assert window.table.height() <= table_height
    row = window.highlights.rule_rows[0]
    window.rules_splitter.setSizes([700, 500])
    qtbot.wait(20)
    window._save_ui_state()
    sizes = window.rules_splitter.sizes()
    window.rules_splitter.setSizes([500, 700])
    qtbot.wait(20)
    window._restore_ui_state()
    qtbot.wait(20)
    restored_sizes = window.rules_splitter.sizes()
    assert abs(restored_sizes[0] / sum(restored_sizes) - sizes[0] / sum(sizes)) < 0.02
    row = window.highlights.rule_rows[0]
    window.highlights.edit_rule(row)
    assert window.highlights._editors.currentWidget() is row.editor


def test_rules_height_grows_to_three_rows_then_scrolls_and_shrinks(qtbot, window):
    window.resize(2600, 900)
    qtbot.waitUntil(lambda: not window._rules_height_timer.isActive())
    window.centralWidget().layout().activate()
    row_height = max(
        panel._flow_layout.itemAt(index).sizeHint().height()
        for panel in (window.filter_bar, window.highlights)
        for index in range(panel._flow_layout.count()))
    qtbot.waitUntil(lambda: window.rules_splitter.height() <= row_height + 6)
    initial_height = window.rules_splitter.height()
    assert initial_height <= row_height + 6
    for index in range(30):
        window.highlights.add_rule(HighlightRule(f"Highlight example {index}"))
    qtbot.waitUntil(lambda: window.rules_splitter.height() > initial_height)
    qtbot.waitUntil(lambda: window.highlights_scroll.verticalScrollBar().maximum() > 0)
    capped_height = window.rules_splitter.height()
    assert capped_height <= 3 * row_height + 6
    for index in range(10):
        window.highlights.add_rule(HighlightRule(f"Additional example {index}"))
    qtbot.wait(50)
    assert window.rules_splitter.height() == capped_height
    for row in list(window.highlights.rule_rows[1:]):
        window.highlights.remove_rule(row)
    qtbot.waitUntil(lambda: window.rules_splitter.height() <= initial_height)


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


def test_table_columns_can_be_hidden_and_visibility_is_saved(qtbot, window):
    window._populate_column_menu()
    sender_action = next(action for action in window.column_menu.actions()
                         if action.text() == "Sender")
    assert sender_action.isChecked()
    sender_action.trigger()
    assert window.table.isColumnHidden(3)

    window._save_ui_state()
    window.table.setColumnHidden(3, False)
    assert not window.table.isColumnHidden(3)
    window._restore_ui_state()
    assert window.table.isColumnHidden(3)

    window._populate_column_menu()
    for action in window.column_menu.actions():
        if action.isChecked():
            action.trigger()
    assert sum(not window.table.isColumnHidden(index)
               for index in range(window.model.columnCount())) == 1


def test_zoom_shortcuts_and_factor_are_saved(qtbot, window):
    assert window.zoom_controller.factor == 1.0
    window.zoom_in_action.trigger()
    assert window.zoom_controller.factor == 1.1
    assert "<br>" not in window.counter_label.text()
    assert "Live:" in window.counter_label.toolTip()
    window._save_ui_state()
    window.zoom_reset_action.trigger()
    assert window.zoom_controller.factor == 1.0
    window._ui_state.setValue("zoom", 1.1)
    window._restore_ui_state()
    assert window.zoom_controller.factor == 1.1
    window.zoom_reset_action.trigger()
    assert window.zoom_controller.factor == 1.0


def test_about_navigation_opens_embedded_page(qtbot, window, monkeypatch):
    from syslog_monitor.ui.about_dialog import AboutDialog

    opened = []
    monkeypatch.setattr(AboutDialog, "exec", lambda self: opened.append(self))

    window.about_action.trigger()

    assert not opened
    assert window.current_page == "about"
    dialog = window._pages["about"].findChild(AboutDialog)
    assert dialog.isVisible()
    qtbot.keyClick(dialog, Qt.Key_Escape)
    assert dialog.isVisible()


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

    def checker(host, endpoints):
        calls.append((host, endpoints))
        return results[min(len(calls), len(results)) - 1]

    service = CaptureService(tmp_path / "data", Settings(bind_host="0.0.0.0", port=0))
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST, firewall_checker=checker)
    qtbot.addWidget(win)
    try:
        qtbot.waitUntil(lambda: "not allowed" in win.firewall_label.text(), timeout=3000)
        assert calls == [("0.0.0.0", (("UDP", 0),))]
        assert "Private: no allow rule" in win.firewall_label.toolTip()
        win.check_firewall()
        qtbot.waitUntil(lambda: "Firewall ✓" in win.firewall_label.text(), timeout=3000)
    finally:
        win.shutdown()
        service.shutdown()


def test_firewall_monitor_survives_broken_checker(qtbot):
    from syslog_monitor.firewall import Level
    from syslog_monitor.ui.firewall_status import FirewallMonitor

    def broken(host, endpoints):
        raise RuntimeError("boom")

    monitor = FirewallMonitor(broken)
    with qtbot.waitSignal(monitor.checked, timeout=3000) as blocker:
        monitor.request("0.0.0.0", (("UDP", 514),))
    assert blocker.args[0].level == Level.UNKNOWN
    assert "boom" in blocker.args[0].details[0]


def test_firewall_monitor_coalesces_requests(qtbot):
    import threading

    from syslog_monitor.firewall import FirewallCheck, Level
    from syslog_monitor.ui.firewall_status import FirewallMonitor

    gate = threading.Event()
    seen = []

    def slow(host, endpoints):
        gate.wait(3)
        port = endpoints[0][1]
        seen.append(port)
        return FirewallCheck(Level.OK, str(port))

    monitor = FirewallMonitor(slow)
    received = []
    monitor.checked.connect(lambda c: received.append(c.summary))
    for port in (1, 2, 3):
        monitor.request("0.0.0.0", (("UDP", port),))
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
        win.apply_settings(new)
        assert not mcp.running and mcp.tools.boot_marker == "booted; started"
        assert "MCP off" in win.mcp_label.text()

        new = replace(new, mcp_enabled=True)
        win.apply_settings(new)
        assert mcp.running and "MCP ✓" in win.mcp_label.text()
    finally:
        win.shutdown()
        mcp.stop()
        service.shutdown()


def test_without_mcp_the_status_label_is_hidden(window):
    assert window.mcp is None and window.mcp_label.isHidden()


def test_listener_settings_controls_and_validation(qtbot):
    from syslog_monitor.ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(Settings())
    qtbot.addWidget(dialog)
    assert dialog.udp_enabled.isChecked() and dialog.port.isEnabled()
    assert not dialog.tcp_enabled.isChecked() and not dialog.tcp_port.isEnabled()

    dialog.tcp_enabled.setChecked(True)
    dialog.tcp_port.setValue(6514)
    dialog.udp_enabled.setChecked(False)
    assert not dialog.port.isEnabled() and dialog.tcp_port.isEnabled()
    result = dialog.result_settings()
    assert not result.udp_enabled and result.tcp_enabled and result.tcp_port == 6514
    assert result.validate() == []

    dialog.tcp_enabled.setChecked(False)
    dialog.accept()
    assert "Enable at least one UDP, TCP or TLS listener" in dialog.error_label.text()
    assert not dialog.result()


def test_tls_settings_controls_check_certificate_files(qtbot, tls_certs):
    from syslog_monitor.ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(Settings())
    qtbot.addWidget(dialog)
    assert not dialog.tls_enabled.isChecked()
    assert not dialog.tls_port.isEnabled() and not dialog.tls_cert.isEnabled()
    dialog.tls_enabled.setChecked(True)
    assert dialog.tls_port.isEnabled() and dialog.tls_cert.isEnabled() and dialog.tls_ca.isEnabled()
    assert dialog.tls_port.value() == 6514

    dialog.accept()
    assert "TLS needs a certificate file" in dialog.error_label.text() and not dialog.result()
    dialog.tls_cert.setText(tls_certs.server_cert)
    dialog.tls_key.setText(tls_certs.rogue_key)
    dialog.accept()
    assert "Could not load TLS certificate" in dialog.error_label.text() and not dialog.result()

    dialog.tls_key.setText(f"  {tls_certs.server_key} ")
    dialog.tls_ca.setText(tls_certs.ca)
    dialog.tls_port.setValue(16514)
    dialog.accept()
    assert dialog.result()
    result = dialog.result_settings()
    assert result.tls_enabled and result.tls_port == 16514
    assert result.tls_files == (tls_certs.server_cert, tls_certs.server_key, tls_certs.ca)
    assert result.listener_endpoints == (("UDP", 514), ("TLS", 16514))


def test_gui_applies_tcp_settings_and_keeps_udp_running_on_error(qtbot, tmp_path, monkeypatch):
    import socket
    from dataclasses import replace

    from syslog_monitor.config import load_settings
    from syslog_monitor.ui import main_window as main_window_module

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        udp_port = probe.getsockname()[1]
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    tcp_port = blocker.getsockname()[1]
    settings = Settings(bind_host="127.0.0.1", port=udp_port)
    new = replace(settings, tcp_enabled=True, tcp_port=tcp_port)
    service = CaptureService(tmp_path / "data", settings, tuning=WriterTuning(flush_interval_s=0.05))
    assert service.start_listener()
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST)
    qtbot.addWidget(win)
    warnings = []
    monkeypatch.setattr(main_window_module.QMessageBox, "warning", lambda *args: warnings.append(args[2]))

    class FakeDialog:
        def __init__(self, *_):
            pass

        def exec(self):
            return True

        def result_settings(self):
            return new

    monkeypatch.setattr(main_window_module, "SettingsDialog", FakeDialog)
    try:
        win.show()
        win.apply_settings(new)
        assert load_settings(tmp_path / "settings.json") == new
        assert warnings and "TCP port" in warnings[0]
        assert service.bound_ports == {"UDP": udp_port}
        assert win.listen_action.isChecked()
        assert "Still receiving on UDP" in win.listener_label.text()

        blocker.close()
        win.listen_action.trigger()
        assert not service.listening
        win.listen_action.trigger()
        assert service.bound_ports == {"UDP": udp_port, "TCP": tcp_port}
        assert "UDP" in win.listener_label.text() and "TCP" in win.listener_label.text()

        with socket.create_connection(("127.0.0.1", tcp_port), timeout=3) as client:
            client.sendall(b"<14>1 - host app - - - tcp in the GUI\n")
            qtbot.waitUntil(lambda: win.model.rowCount() == 1, timeout=5000)
        assert win.model.row_at(0).message == "tcp in the GUI"
    finally:
        blocker.close()
        win.shutdown()
        service.shutdown()
