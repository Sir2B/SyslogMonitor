"""Main-window integration tests: layout, pages, state and lifecycle."""

import time
import pytest
from PySide6.QtCore import QPoint, QSettings, Qt
from PySide6.QtWidgets import QApplication
from syslog_monitor.query import FilterRule, HighlightRule
from ui_test_helpers import send


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
        "logs", "analysis", "export", "validation", "receive", "settings", "about", "quit"]
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
    for name in ("analysis", "export", "settings", "about", "validation", "quit", "logs"):
        qtbot.mouseClick(window.sidebar.buttons[name], Qt.LeftButton)
        assert window.current_page == name
        assert window.pages.currentWidget() is window._pages[name]
        assert window.sidebar.buttons[name].isChecked()
        assert sum(window.sidebar.buttons[key].isChecked()
                   for key in ("logs", "analysis", "export", "settings", "about", "validation", "quit")) == 1
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
