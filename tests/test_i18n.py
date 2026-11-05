from pathlib import Path

import pytest
from PySide6.QtCore import Qt

from syslog_monitor import app
from syslog_monitor.config import Settings, load_settings, save_settings
from syslog_monitor.i18n import detect_language, set_language, tr


def test_language_translation_and_formatting():
    set_language("de")
    try:
        assert tr("Settings") == "Einstellungen"
        assert tr("Severity: {count} selected", count=3) == "Schweregrad: 3 ausgewählt"
    finally:
        set_language("en")


def test_language_setting_persists_and_is_validated(tmp_path: Path):
    path = tmp_path / "settings.json"
    save_settings(path, Settings(language="de"))

    assert load_settings(path).language == "de"
    assert Settings(language="fr").validate()[-1] == "Language must be en or de."


@pytest.mark.parametrize(("locale_name", "expected"), [
    ("de_DE", "de"),
    ("de-DE", "de"),
    ("en_US", "en"),
    ("fr_FR", "en"),
])
def test_detect_language_supports_german_and_falls_back_to_english(locale_name, expected):
    assert detect_language(locale_name) == expected


def test_startup_language_is_detected_only_without_settings_file(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    monkeypatch.setattr(app, "detect_language", lambda: "de")
    assert app.load_startup_settings(path).language == "de"

    save_settings(path, Settings(language="en"))
    assert app.load_startup_settings(path).language == "en"


def test_settings_dialog_returns_selected_language(qtbot):
    from syslog_monitor.ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(Settings())
    qtbot.addWidget(dialog)
    dialog.language.setCurrentIndex(dialog.language.findData("de"))

    assert dialog.result_settings().language == "de"


def test_common_ui_labels_follow_selected_language(qtbot):
    from syslog_monitor.ui.event_model import EventTableModel
    from syslog_monitor.ui.filter_bar import FilterBar

    set_language("de")
    try:
        filters = FilterBar()
        qtbot.addWidget(filters)
        model = EventTableModel()

        assert filters.reset_button.text() == "Filter zurücksetzen"
        assert filters.facility.itemText(0) == "Alle Facilities"
        assert model.headerData(0, Qt.Horizontal) == "Zeit"
        assert model.headerData(2, Qt.Horizontal) == "Facility"
        assert tr("Facility:") == "Facility:"
        assert tr("Apply current severity, facility and filter rules") == (
            "Aktuelle Schweregrade, Facility und Filterregeln anwenden")
    finally:
        set_language("en")
