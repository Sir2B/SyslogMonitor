"""Shared traffic and interaction helpers for GUI integration tests."""

import pytest
from conftest import send_udp
from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QTextDocument
from syslog_monitor.firewall import FirewallCheck, Level
from syslog_monitor.ui.main_window import Timings

FAST = Timings(live_ms=50, histogram_ms=200, status_ms=100)


def isolated_firewall_checker(bind_host, endpoints):
    return FirewallCheck(Level.OK, "Synthetic firewall result for GUI tests")


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


def selected_message(window):
    row = window.model.row_at(window.table.currentIndex().row())
    return None if row is None else row.message


def send(win, *messages: str):
    send_udp(win.service.bound_port, *(m.encode() for m in messages))
