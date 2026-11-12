"""Toggleable quick filter: pick exact values of one column (sender IP, host, application)."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtGui import QAction, QMouseEvent
from PySide6.QtWidgets import QMenu, QToolButton, QWidget

from syslog_monitor.i18n import tr
from syslog_monitor.ui.formatting import format_count

QUICK_LABELS = {"source_ip": "IP", "hostname": "Host", "app_name": "App"}
QUICK_TOOLTIPS = {
    "source_ip": "Quick filter by sender IP address",
    "hostname": "Quick filter by host name from the message",
    "app_name": "Quick filter by application (tag) from the message",
}
EMPTY_LABEL = "(none)"


class _StayOpenMenu(QMenu):
    """Checkable entries toggle without closing the menu, so several values can be picked."""

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        action = self.actionAt(event.position().toPoint())
        if action is not None and action.isCheckable() and action.isEnabled():
            action.trigger()
            return
        super().mouseReleaseEvent(event)


class QuickFilterButton(QToolButton):
    """Shows the values present in the current view; no checked value means no restriction."""

    changed = Signal()
    values_requested = Signal(str)

    def __init__(self, column: str, parent: QWidget | None = None) -> None:
        super().__init__(parent, popupMode=QToolButton.InstantPopup)
        self.column = column
        self._selected: set[str] = set()
        self._values: list[tuple[str, int]] = []
        self._menu = _StayOpenMenu(self)
        self._menu.aboutToShow.connect(self._menu_opening)
        self.setMenu(self._menu)
        self.setToolTip(tr(QUICK_TOOLTIPS[column]) + "\n" + tr("Check one or more values; nothing checked shows all."))
        self._rebuild()
        self._update_label()

    @property
    def name(self) -> str:
        return tr(QUICK_LABELS[self.column])

    def selected(self) -> set[str]:
        return set(self._selected)

    def set_selected(self, values: set[str], *, emit: bool = True) -> None:
        if values == self._selected:
            return
        self._selected = set(values)
        self._rebuild()
        self._update_label()
        if emit:
            self.changed.emit()

    def set_values(self, values: list[tuple[str, int]]) -> None:
        """Values (with counts) from the database, shown next time or immediately if open."""
        self._values = list(values)
        self._rebuild()

    def _menu_opening(self) -> None:
        self._rebuild()
        self.values_requested.emit(self.column)

    def _rebuild(self) -> None:
        menu = self._menu
        menu.clear()
        clear = menu.addAction(tr("All (no restriction)"), lambda: self.set_selected(set()))
        clear.setEnabled(bool(self._selected))
        menu.addSeparator()
        counts = dict(self._values)
        shown = [value for value, _count in self._values]
        shown += sorted(value for value in self._selected if value not in counts)
        if not shown:
            placeholder = menu.addAction(tr("Loading…") if not self._values else tr("No values"))
            placeholder.setEnabled(False)
        for value in shown:
            label = value or tr(EMPTY_LABEL)
            if value in counts:
                label += f"\t{format_count(counts[value])}"
            action = QAction(label, menu, checkable=True, checked=value in self._selected)
            action.toggled.connect(lambda checked, v=value: self._toggle(v, checked))
            menu.addAction(action)

    def _toggle(self, value: str, checked: bool) -> None:
        values = set(self._selected)
        if checked:
            values.add(value)
        else:
            values.discard(value)
        self._selected = values
        self._update_label()
        self._menu.actions()[0].setEnabled(bool(values))
        self.changed.emit()

    def _update_label(self) -> None:
        if not self._selected:
            text = self.name
        elif len(self._selected) == 1:
            value = next(iter(self._selected)) or tr(EMPTY_LABEL)
            text = f"{self.name}: {value}"
        else:
            text = tr("{name}: {count} selected", name=self.name, count=len(self._selected))
        self.setText(text)
        font = self.font()
        font.setBold(bool(self._selected))
        self.setFont(font)
