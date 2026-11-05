"""Language selection and translation lookup."""

from __future__ import annotations

from PySide6.QtCore import QLocale

from syslog_monitor.translations_de import GERMAN_TRANSLATIONS as _GERMAN

LANGUAGES = {"en": "English", "de": "Deutsch"}
_language = "en"


def detect_language(locale_name: str | None = None) -> str:
    """Choose a supported language from the system locale, defaulting to English."""
    name = QLocale.system().name() if locale_name is None else locale_name
    language_code = name.replace("-", "_").split("_", 1)[0].lower()
    return "de" if language_code == "de" else "en"


def set_language(language: str) -> None:
    global _language
    if language not in LANGUAGES:
        raise ValueError(f"Unsupported language: {language}")
    _language = language


def language() -> str:
    return _language


def tr(text: str, **values: object) -> str:
    translated = _GERMAN.get(text, text) if _language == "de" else text
    return translated.format(**values) if values else translated
