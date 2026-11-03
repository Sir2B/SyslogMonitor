"""Colours shared by the table, minimap and legend."""

from PySide6.QtGui import QColor

from syslog_monitor.query import DEFAULT_HIGHLIGHT_COLOR

HIGHLIGHT_COLOR = QColor(DEFAULT_HIGHLIGHT_COLOR)
HIGHLIGHT_TEXT_COLOR = QColor("#ffffff")


def highlight_text_color(background: QColor) -> QColor:
    """Choose black or white using WCAG relative luminance/contrast."""
    channels = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
                for v in (background.redF(), background.greenF(), background.blueF())]
    luminance = sum(c * weight for c, weight in zip(channels, (0.2126, 0.7152, 0.0722)))
    return QColor("#000000") if luminance > 0.179 else QColor("#ffffff")
