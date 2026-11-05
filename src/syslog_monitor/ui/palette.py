"""Colours shared by the table, minimap and legend."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

from syslog_monitor.query import DEFAULT_HIGHLIGHT_COLOR

HIGHLIGHT_COLOR = QColor(DEFAULT_HIGHLIGHT_COLOR)
HIGHLIGHT_TEXT_COLOR = QColor("#ffffff")


def is_dark() -> bool:
    return QApplication.palette().color(QPalette.Window).lightness() < 128


def status_color(color: str) -> str:
    if not is_dark():
        return color
    return {"#555": "#b8b8b8", "#666": "#b8b8b8", "#1a7f37": "#70d88b",
            "#9a6700": "#ffc45c", "#b00020": "#ff8999"}.get(color, color)


def apply_theme(theme: str) -> None:
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        raise RuntimeError("A QApplication is required to apply the theme.")
    if app.property("system_palette") is None:
        app.setProperty("system_palette", QPalette(app.palette()))
        app.setProperty("system_style", app.style().objectName())
    if theme not in ("system", "light", "dark"):
        raise ValueError(f"Unknown theme: {theme}")
    app.styleHints().setColorScheme({
        "system": Qt.ColorScheme.Unknown,
        "light": Qt.ColorScheme.Light,
        "dark": Qt.ColorScheme.Dark,
    }[theme])
    if theme == "system":
        if app.style().objectName() != app.property("system_style"):
            app.setStyle(app.property("system_style"))
        palette = app.property("system_palette")
    else:
        if app.style().objectName() != "fusion":
            app.setStyle("Fusion")
        palette = app.style().standardPalette()
    if theme == "dark":
        for role, color in (
            (QPalette.Window, "#202328"), (QPalette.WindowText, "#eeeeee"),
            (QPalette.Base, "#171a1f"), (QPalette.AlternateBase, "#20252c"),
            (QPalette.Text, "#eeeeee"), (QPalette.Button, "#292e35"),
            (QPalette.ButtonText, "#eeeeee"), (QPalette.ToolTipBase, "#34383f"),
            (QPalette.ToolTipText, "#ffffff"), (QPalette.Highlight, "#386ca8"),
            (QPalette.HighlightedText, "#ffffff"), (QPalette.Link, "#8cc4ff"),
            (QPalette.BrightText, "#ff8999"), (QPalette.Mid, "#353b44"),
            (QPalette.Light, "#3b424c"), (QPalette.Midlight, "#30363e"),
            (QPalette.Dark, "#111418"), (QPalette.Shadow, "#0e1013"),
            (QPalette.PlaceholderText, "#aaaaaa"),
        ):
            palette.setColor(role, QColor(color))
        for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
            palette.setColor(QPalette.Disabled, role, QColor("#90949c"))
    if app.palette() != palette:
        app.setPalette(palette)
    # Qt stylesheets can retain the old inherited palette after a style change.
    # Reset inheritance; local highlight/error stylesheets still supply their own colours.
    widgets = app.allWidgets()
    for widget in widgets:
        widget.setPalette(QPalette())
    for widget in widgets:
        if stylesheet := widget.styleSheet():
            widget.setStyleSheet(stylesheet)


def highlight_text_color(background: QColor) -> QColor:
    """Choose black or white using WCAG relative luminance/contrast."""
    channels = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
                for v in (background.redF(), background.greenF(), background.blueF())]
    luminance = sum(c * weight for c, weight in zip(channels, (0.2126, 0.7152, 0.0722)))
    return QColor("#000000") if luminance > 0.179 else QColor("#ffffff")
