"""Programmatically drawn icons (no binary assets to maintain)."""

from __future__ import annotations

import struct

from PySide6.QtCore import QBuffer, QIODevice, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap

STATE_COLORS = {
    "running": QColor(40, 160, 70),
    "stopped": QColor(130, 130, 130),
    "error": QColor(214, 39, 40),
}
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
_DESIGN_SIZE = 64


def app_pixmap(size: int = _DESIGN_SIZE, state: str = "running") -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.scale(size / _DESIGN_SIZE, size / _DESIGN_SIZE)
    painter.setBrush(QColor(40, 60, 90))
    painter.setPen(Qt.NoPen)
    painter.drawRoundedRect(4, 4, 56, 56, 10, 10)
    for i, (width, color) in enumerate(((40, QColor(220, 230, 240)), (28, QColor(245, 150, 20)),
                                        (34, QColor(220, 230, 240)))):
        painter.setBrush(color)
        painter.drawRect(12, 14 + i * 11, width, 6)
    painter.setBrush(STATE_COLORS.get(state, STATE_COLORS["stopped"]))
    painter.drawEllipse(38, 38, 22, 22)
    painter.end()
    return pixmap


def app_icon(state: str = "running") -> QIcon:
    return QIcon(app_pixmap(_DESIGN_SIZE, state))


def app_ico_bytes(sizes: tuple[int, ...] = ICO_SIZES) -> bytes:
    """Multi-resolution Windows .ico (PNG-compressed entries) for the packaged executable."""
    images = []
    for size in sizes:
        buffer = QBuffer()
        buffer.open(QIODevice.WriteOnly)
        app_pixmap(size).save(buffer, "PNG")
        images.append((size, bytes(buffer.data())))
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    directory, data = b"", b""
    for size, png in images:
        dim = 0 if size >= 256 else size  # 0 means 256 in the ICO directory
        directory += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(data))
        data += png
    return header + directory + data
