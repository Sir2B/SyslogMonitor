"""Programmatically drawn icons (no binary assets to maintain)."""

from __future__ import annotations

import struct

from PySide6.QtCore import QBuffer, QIODevice, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPalette, QPen, QPixmap

STATE_COLORS = {
    "running": QColor(40, 160, 70),
    "stopped": QColor(130, 130, 130),
    "error": QColor(214, 39, 40),
}
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
_DESIGN_SIZE = 64


def navigation_icon(name: str, palette: QPalette) -> QIcon:
    paths = {
        "logs": (((5, 3), (19, 3), (19, 21), (5, 21), (5, 3)),
                 ((8, 8), (16, 8)), ((8, 12), (16, 12)), ((8, 16), (14, 16))),
        "analysis": (((3, 20.5), (21, 20.5)), ((6.5, 17), (6.5, 11)), ((11.5, 17), (11.5, 5)),
                     ((16.5, 17), (16.5, 9)), ((21, 17), (21, 14))),
        "export": (((4, 14), (4, 20), (20, 20), (20, 14)),
                   ((12, 3), (12, 15)), ((7, 10), (12, 15), (17, 10))),
        "import": (((4, 14), (4, 20), (20, 20), (20, 14)),
                   ((12, 15), (12, 3)), ((7, 8), (12, 3), (17, 8))),
        "validation": (((12, 2), (21, 6), (19, 16), (12, 22), (5, 16), (3, 6), (12, 2)),
                       ((7, 11), (11, 15), (17, 8))),
        "quit": (((12, 2), (12, 11)),),
        "about": (((12, 10), (12, 17)), ((12, 6), (12, 7))),
        "start": (((8, 4), (20, 12), (8, 20), (8, 4)),),
        "stop": (((5, 5), (19, 5), (19, 19), (5, 19), (5, 5)),),
        "expand": (((8, 5), (15, 12), (8, 19)),),
        "collapse": (((16, 5), (9, 12), (16, 19)),),
        "settings": (),
    }
    strokes = paths[name]
    icon = QIcon()
    for mode, state, role in (
        (QIcon.Normal, QIcon.Off, QPalette.WindowText),
        (QIcon.Normal, QIcon.On, QPalette.HighlightedText),
        (QIcon.Disabled, QIcon.Off, QPalette.PlaceholderText),
    ):
        for size in (24, 48, 96):
            pixmap = QPixmap(size, size)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.scale(size / 24, size / 24)
            painter.setPen(QPen(palette.color(role), 1.8, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            for points in strokes:
                path = QPainterPath()
                path.moveTo(*points[0])
                for point in points[1:]:
                    path.lineTo(*point)
                painter.drawPath(path)
            if name == "about":
                painter.drawEllipse(2, 2, 20, 20)
            elif name == "quit":
                painter.drawArc(3, 3, 18, 18, 135 * 16, 270 * 16)
            elif name == "settings":
                painter.drawEllipse(8, 8, 8, 8)
                painter.drawEllipse(5, 5, 14, 14)
                painter.translate(12, 12)
                for _ in range(8):
                    painter.drawLine(0, -9, 0, -11)
                    painter.rotate(45)
            painter.end()
            icon.addPixmap(pixmap, mode, state)
    return icon


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
