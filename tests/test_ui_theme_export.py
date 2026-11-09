import csv
import sys
from dataclasses import replace
from threading import Event

import pytest
from conftest import BASE_MS, make_event
from PySide6.QtCore import QDateTime, QSettings, QThread, Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QFileDialog, QStyle, QStyleOptionSlider

from syslog_monitor.config import Settings, load_settings, save_settings
from syslog_monitor.export import DEFAULT_EXPORT_COLUMNS, EXPORT_COLUMNS, ExportCancelled
from syslog_monitor.query import EventFilter, EventRow, HighlightRule
from syslog_monitor.storage import db_path
from syslog_monitor.service import CaptureService
from syslog_monitor.ui.event_model import EventTableModel, ROW_BACKGROUND, ROW_BACKGROUND_DARK
from syslog_monitor.ui.export_dialog import ExportDialog
from syslog_monitor.ui.minimap import MinimapWidget
from syslog_monitor.ui.main_window import MainWindow, Timings
from syslog_monitor.ui.palette import apply_theme, highlight_text_color, is_dark
from syslog_monitor.ui.settings_dialog import SettingsDialog
from ui_test_helpers import isolated_firewall_checker


@pytest.fixture
def restore_theme(qapp):
    palette = QPalette(qapp.palette())
    style = qapp.style().objectName()
    scheme = qapp.styleHints().colorScheme()
    yield
    qapp.styleHints().setColorScheme(scheme)
    qapp.setStyle(style)
    qapp.setPalette(palette)
    for widget in qapp.allWidgets():
        widget.setPalette(QPalette())


def test_theme_settings_roundtrip_migration_validation(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text('{"port": 5514}')
    assert load_settings(path).theme == "system"
    for theme in ("light", "dark", "system"):
        settings = Settings(theme=theme)
        assert not settings.validate()
        save_settings(path, settings)
        assert load_settings(path) == settings
    for theme in ("invalid", None, 1, []):
        assert replace(Settings(), theme=theme).validate() == ["Theme must be system, light or dark."]


def test_settings_dialog_has_theme_and_preserves_other_settings(qtbot):
    settings = Settings(port=5514, theme="dark")
    dialog = SettingsDialog(settings)
    qtbot.addWidget(dialog)
    assert dialog.theme.currentData() == "dark"
    dialog.theme.setCurrentIndex(dialog.theme.findData("light"))
    assert dialog.result_settings() == replace(settings, theme="light")


def test_embedded_settings_recover_after_invalid_input_without_closing(qtbot):
    dialog = SettingsDialog(Settings(), embedded=True)
    qtbot.addWidget(dialog)
    applied = []
    dialog.applied.connect(applied.append)
    dialog.show()
    dialog.host.setText("invalid")
    dialog.accept()
    assert dialog.error_label.text() and not applied
    dialog.host.setText("127.0.0.1")
    dialog.accept()
    assert len(applied) == 1 and applied[0].bind_host == "127.0.0.1"
    assert not dialog.error_label.text() and dialog.isVisible()
    dialog.reject()
    assert dialog.isVisible()


@pytest.mark.parametrize("color", ["#202020", "#f0f0f0"])
def test_navigation_icons_use_theme_and_selected_foreground(qapp, color):
    from PySide6.QtGui import QIcon
    from syslog_monitor.ui.icons import navigation_icon

    palette = QPalette()
    palette.setColor(QPalette.WindowText, QColor(color))
    palette.setColor(QPalette.HighlightedText, QColor("#00aaff"))
    for name in ("logs", "analysis", "export", "validation", "settings", "about", "quit",
                 "start", "stop", "expand", "collapse"):
        icon = navigation_icon(name, palette)
        for state, expected in ((QIcon.Off, color), (QIcon.On, "#00aaff")):
            image = icon.pixmap(24, 24, QIcon.Normal, state).toImage()
            assert any(image.pixelColor(x, y) == QColor(expected)
                       for x in range(image.width()) for y in range(image.height())), (name, state)


def test_dark_light_system_and_model_contrast(qtbot, restore_theme):
    app = QApplication.instance()
    apply_theme("system")
    original = QPalette(app.palette())
    style = app.style()
    apply_theme("system")
    assert app.style() is style
    model = EventTableModel()
    model.set_highlight_rules(())
    model.reset_rows([EventRow(i, i, "192.0.2.1", 1, severity, "h", "app", None, "hello", "")
                      for i, severity in enumerate((3, 4, 6, 7, None))],
                     has_older=False, has_newer=False)
    apply_theme("dark")
    style = app.style()
    apply_theme("dark")
    assert app.style() is style
    assert is_dark()
    assert app.palette().color(QPalette.Text).lightness() > 200
    def luminance(color):
        channels = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
                    for v in (color.redF(), color.greenF(), color.blueF())]
        return sum(c * weight for c, weight in zip(channels, (0.2126, 0.7152, 0.0722)))
    for i in range(5):
        background = model.data(model.index(i, 0), Qt.BackgroundRole).color()
        foreground = model.data(model.index(i, 0), Qt.ForegroundRole).color()
        assert background in ROW_BACKGROUND_DARK.values()
        assert background.lightness() <= 50
        assert foreground == highlight_text_color(background)
        assert (luminance(foreground) + 0.05) / (luminance(background) + 0.05) >= 4.5
    from syslog_monitor.ui.minimap import CLASS_COLORS
    for color in CLASS_COLORS.values():
        assert ((luminance(color.lighter(150)) + 0.05) /
                (luminance(app.palette().color(QPalette.Window)) + 0.05)) >= 4.5
    model.set_highlight_rules((HighlightRule("hello", "#ffff00"),))
    assert model.data(model.index(0, 0), Qt.ForegroundRole).color() == QColor("#000000")
    model.set_highlight_rules(())
    apply_theme("light")
    assert not is_dark()
    assert model.data(model.index(0, 0), Qt.BackgroundRole).color() in ROW_BACKGROUND.values()
    assert model.data(model.index(0, 0), Qt.ForegroundRole) is None
    apply_theme("system")
    assert app.palette() == original


def test_live_theme_switch_updates_existing_windows_and_styled_children(qtbot, tmp_path, restore_theme):
    service = CaptureService(tmp_path / "data", Settings(theme="light"))
    window = MainWindow(service, settings_path=tmp_path / "settings.json",
                        ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                        tray_enabled=False, timings=Timings(live_ms=60_000, histogram_ms=60_000),
                        firewall_checker=isolated_firewall_checker)
    qtbot.addWidget(window)
    window.resize(1400, 860)
    window.show()
    try:
        qtbot.waitUntil(lambda: not window.queries.busy)
        window.model.reset_rows(
            [EventRow(i, i, "192.0.2.1", 1, 7, "h", "app", None, "test", "")
             for i in range(200)], has_older=False, has_newer=False)
        highlight = window.highlights.rule_rows[0]
        for theme in ("dark", "light", "dark", "system"):
            apply_theme(theme)
            QApplication.processEvents()
            dark = is_dark()
            widgets = (
                window.filter_bar, window.filters_scroll.viewport(),
                window.highlights, window.highlights_scroll.viewport(),
                window.table.horizontalHeader(), window.table.verticalScrollBar(),
                window.range_combo, window.minimap_range_label, window.minimap,
                window.details, highlight.summary_button,
            )
            for widget in widgets:
                palette = widget.palette()
                assert (palette.color(QPalette.Window).lightness() < 128) == dark, type(widget).__name__
                assert (palette.color(QPalette.Text).lightness() > 128) == dark, type(widget).__name__
            if dark:
                for widget in (window.filters_scroll.viewport(), window.highlights_scroll.viewport()):
                    image = widget.grab().toImage()
                    assert image.pixelColor(image.width() - 3, image.height() - 3).lightness() < 60
                assert window.table.horizontalHeader().grab().toImage().pixelColor(5, 5).lightness() < 70
                scroll = window.table.verticalScrollBar()
                option = QStyleOptionSlider()
                scroll.initStyleOption(option)
                slider = scroll.style().subControlRect(
                    QStyle.CC_ScrollBar, option, QStyle.SC_ScrollBarSlider, scroll)
                image = scroll.grab().toImage()
                assert image.pixelColor(slider.center()).lightness() < 100
                assert "gridline-color: palette(mid)" in window.table.styleSheet()
                assert window.minimap_range_label.palette().color(QPalette.WindowText).lightness() > 200
            handle = window.rules_splitter.handle(1)
            image = handle.grab().toImage()
            color = image.pixelColor(image.width() // 2, image.height() // 2)
            assert (color.lightness() < 128) == dark
            assert QColor(highlight._color).name() in highlight.color_button.styleSheet()
            window.highlights.edit_rule(highlight)
            QApplication.processEvents()
            image = highlight.color_button.grab().toImage()
            color = image.pixelColor(5, image.height() // 2)
            assert abs(color.hue() - QColor(highlight._color).hue()) < 10
            window.highlights._editors.hide()
            QApplication.processEvents()
    finally:
        window.shutdown()
        service.shutdown()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows title-bar integration")
def test_native_windows_title_bars_follow_theme(qtbot, restore_theme):
    import ctypes
    from ctypes import wintypes
    from PySide6.QtWidgets import QDialog, QMainWindow
    if QApplication.platformName() != "windows":
        pytest.skip("Needs the native Windows platform plugin, not offscreen")
    get_attribute = ctypes.windll.dwmapi.DwmGetWindowAttribute
    get_attribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    get_attribute.restype = ctypes.c_long
    apply_theme("light")
    window = QMainWindow()
    qtbot.addWidget(window)
    window.show()
    apply_theme("dark")
    dialog = QDialog(window)
    qtbot.addWidget(dialog)
    dialog.show()
    for theme in ("dark", "light", "dark"):
        apply_theme(theme)
        QApplication.processEvents()
        for widget in (window, dialog):
            def title_matches():
                value = wintypes.BOOL()
                result = get_attribute(int(widget.winId()), 20, ctypes.byref(value), ctypes.sizeof(value))
                assert result == 0
                return bool(value.value) == (theme == "dark")
            qtbot.waitUntil(title_matches)


def test_minimap_dark_background_and_readable_selection(qtbot, restore_theme):
    from syslog_monitor.query import Histogram
    apply_theme("dark")
    widget = MinimapWidget()
    qtbot.addWidget(widget)
    widget.resize(401, 80)
    widget.set_histogram(Histogram(0, 400_000, [[0, 0, 0, 0, 0] for _ in range(4)]))
    widget.show()
    before = widget.grab().toImage()
    assert before.pixelColor(100, 25).lightness() < 60
    widget.set_selected_times((100_000, 300_000))
    assert widget.grab().toImage().pixelColor(100, 25).lightness() > 128


def test_export_defaults_custom_bounds_and_filter_opt_in(qtbot, tmp_path):
    filters = EventFilter(severities=frozenset({3}))
    dialog = ExportDialog(db_path(tmp_path), "Startup", filters)
    qtbot.addWidget(dialog)
    assert dialog.period.currentData() == "boot"
    assert dialog.format.currentData() == "csv"
    assert not dialog.start.isEnabled() and not dialog.end.isEnabled()
    assert dialog.options().filters.severities is None
    assert dialog.options().columns == DEFAULT_EXPORT_COLUMNS
    assert not dialog.column_checks["source_ip"].isChecked()
    assert not dialog.column_checks["raw_base64"].isChecked()
    dialog.use_filters.setChecked(True)
    assert dialog.options().filters.severities == filters.severities
    dialog.period.setCurrentIndex(dialog.period.findData("custom"))
    assert dialog.start.isEnabled() and dialog.end.isEnabled()
    dialog.start.setDateTime(QDateTime.fromMSecsSinceEpoch(BASE_MS + 456))
    dialog.end.setDateTime(QDateTime.fromMSecsSinceEpoch(BASE_MS + 2000))
    options = dialog.options()
    assert options.filters.start_ms == BASE_MS
    assert options.filters.end_ms == BASE_MS + 3000
    dialog.end.setDateTime(dialog.start.dateTime().addSecs(-1))
    with pytest.raises(ValueError):
        dialog.options()


@pytest.mark.parametrize("format", ["csv", "jsonl"])
def test_export_dialog_background_success_and_failure(qtbot, tmp_path, store, monkeypatch, format):
    store.insert([make_event(0, message="Initializing system"), make_event(1, message="Grüße")])
    output = tmp_path / f"logs.{format}"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args: (str(output), "CSV"))
    dialog = ExportDialog(db_path(tmp_path), "Initializing system", EventFilter())
    qtbot.addWidget(dialog)
    dialog.format.setCurrentIndex(dialog.format.findData(format))
    selected = ("received_at", "message")
    for column, check in dialog.column_checks.items():
        check.setChecked(column in selected)
    dialog.show()
    dialog.export_button.click()
    assert not dialog.export_button.isEnabled()
    assert not dialog.columns_group.isEnabled()
    qtbot.waitUntil(lambda: dialog.worker is None)
    assert dialog.export_button.isEnabled()
    assert dialog.columns_group.isEnabled()
    assert "Exported 2 messages" in dialog.status.text()
    with output.open(encoding="utf-8-sig", newline="") as stream:
        if format == "csv":
            reader = csv.DictReader(stream)
            assert tuple(reader.fieldnames) == selected
            assert len(list(reader)) == 2
        else:
            import json
            rows = [json.loads(line) for line in stream]
            assert len(rows) == 2
            assert all(tuple(row) == selected for row in rows)
    bad = ExportDialog(db_path(tmp_path), "missing marker", EventFilter())
    qtbot.addWidget(bad)
    bad.export_button.click()
    qtbot.waitUntil(lambda: bad.worker is None)
    assert "Export failed: No stored boot marker" in bad.status.text()
    assert bad.export_button.isEnabled()
    assert output.exists()


def test_export_column_selection_applies_to_both_formats_and_requires_one(qtbot, tmp_path, monkeypatch):
    dialog = ExportDialog(db_path(tmp_path), "Startup", EventFilter())
    qtbot.addWidget(dialog)
    assert tuple(dialog.column_checks) == EXPORT_COLUMNS
    for check in dialog.column_checks.values():
        check.setChecked(False)
    def unexpected_file_picker(*args):
        pytest.fail("Invalid column selection should be rejected before choosing a file")
    monkeypatch.setattr(QFileDialog, "getSaveFileName", unexpected_file_picker)
    dialog.export_button.click()
    assert "Select at least one column" in dialog.status.text()
    assert dialog.worker is None
    for format in ("csv", "jsonl"):
        dialog.format.setCurrentIndex(dialog.format.findData(format))
        dialog.column_checks["message"].setChecked(True)
        assert dialog.options().columns == ("message",)
        dialog.column_checks["raw_base64"].setChecked(True)
        assert dialog.options().columns == ("message", "raw_base64")
        for check in dialog.column_checks.values():
            check.setChecked(False)


def test_export_cancel_file_picker_does_not_start_worker(qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args: ("", ""))
    dialog = ExportDialog(db_path(tmp_path), "boot", EventFilter())
    qtbot.addWidget(dialog)
    dialog.start_export()
    assert dialog.worker is None
    assert dialog.export_button.isEnabled()


@pytest.mark.parametrize("embedded", [False, True])
def test_export_dialog_cancel_waits_for_worker(qtbot, tmp_path, monkeypatch, embedded):
    from syslog_monitor.ui import export_dialog
    entered = Event()
    def wait_for_cancel(*args, cancel, **kwargs):
        assert QThread.currentThread() != QApplication.instance().thread()
        entered.set()
        if not cancel.wait(10):
            raise OSError("Timed out waiting for cancellation")
        raise ExportCancelled()
    monkeypatch.setattr(export_dialog, "export_events", wait_for_cancel)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args: (str(tmp_path / "logs.csv"), ""))
    dialog = ExportDialog(db_path(tmp_path), "boot", EventFilter(), embedded=embedded)
    qtbot.addWidget(dialog)
    dialog.show()
    try:
        dialog.start_export()
        qtbot.waitUntil(entered.is_set)
        dialog.reject()
        qtbot.waitUntil(lambda: dialog.worker is None)
        assert dialog.isVisible() == embedded
        assert "cancelled" in dialog.status.text()
    finally:
        dialog.shutdown()


def test_window_loads_persisted_theme_and_applies_changes_without_restarting_listener(
        qtbot, tmp_path, restore_theme):
    import json
    path = tmp_path / "settings.json"
    save_settings(path, Settings(bind_host="127.0.0.1", theme="dark"))
    service = CaptureService(tmp_path / "data", load_settings(path))
    window = MainWindow(service, settings_path=path,
                        ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                        tray_enabled=False, firewall_checker=isolated_firewall_checker)
    qtbot.addWidget(window)
    try:
        assert is_dark()
        service.apply_settings(replace(service.settings, port=0))
        assert service.start_listener()
        original_port = service.bound_port
        window.apply_settings(replace(service.settings, theme="light"))
        assert not is_dark()
        assert service.bound_port == original_port and service.listening
        assert service.settings.theme == "light"
        assert json.loads(path.read_text())["theme"] == "light"
        assert window.sidebar.buttons["export"].defaultAction() is window.export_action
        window.export_action.trigger()
        assert window.current_page == "export"
        assert window._export_dialog._db_path == service.db_path
        assert window._export_dialog.period.currentData() == "boot"
    finally:
        window.shutdown()
        service.shutdown()
