"""Uniform filter rules with separate severity and facility controls."""

from __future__ import annotations

import logging
from dataclasses import asdict

from PySide6.QtCore import QTimer, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QLineEdit, QMenu, QPushButton, QToolButton, QVBoxLayout, QWidget,
)

from syslog_monitor.events import FACILITY_NAMES, SEVERITY_NAMES
from syslog_monitor.query import TEXT_MODE_WORDS, EventFilter, FilterRule

log = logging.getLogger(__name__)

DEBOUNCE_MS = 300
ALL_SEVERITIES: tuple[int | None, ...] = (*range(len(SEVERITY_NAMES)), None)


class RuleRow(QWidget):
    changed = Signal()
    remove_requested = Signal()

    def __init__(self, rule: FilterRule, parent: QWidget) -> None:
        super().__init__(parent)
        self.field = QComboBox()
        for label, value in (("Text (all fields)", "text"), ("Message", "message"),
                             ("Sender/IP or host", "sender"), ("Host", "hostname"),
                             ("Application", "app")):
            self.field.addItem(label, value)
        self.operator = QComboBox()
        for label, value in (("contains", "contains"), ("does not contain", "not_contains"),
                             ("equals", "equals"), ("does not equal", "not_equals")):
            self.operator.addItem(label, value)
        self.required = QCheckBox("Always AND")
        self.required.setToolTip("This rule must always match, even when rules are combined with OR.")
        self.required.setChecked(rule.required)
        self.value = QLineEdit(placeholderText="Filter value …", clearButtonEnabled=True)
        self.remove_button = QPushButton("Remove")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        for widget in (self.field, self.operator, self.value, self.required, self.remove_button):
            layout.addWidget(widget)
        layout.setStretch(2, 1)
        self.field.setCurrentIndex(self.field.findData(rule.field))
        self._update_operators()
        self.operator.setCurrentIndex(self.operator.findData(rule.operator))
        self.value.setText(rule.value)
        self.field.currentIndexChanged.connect(self._field_changed)
        self.operator.currentIndexChanged.connect(self.changed)
        self.value.textChanged.connect(self.changed)
        self.required.toggled.connect(self.changed)
        self.remove_button.clicked.connect(self.remove_requested)

    def rule(self) -> FilterRule:
        return FilterRule(self.field.currentData(), self.operator.currentData(), self.value.text(),
                          self.required.isChecked())

    def _update_operators(self) -> None:
        self.operator.blockSignals(True)
        try:
            if self.field.currentData() == "text":
                if self.operator.findData("words") < 0:
                    self.operator.addItem("contains all words", "words")
                    self.operator.addItem("does not contain all words", "not_words")
            else:
                for value in ("not_words", "words"):
                    index = self.operator.findData(value)
                    if index >= 0:
                        self.operator.removeItem(index)
        finally:
            self.operator.blockSignals(False)

    def _field_changed(self) -> None:
        self._update_operators()
        self.changed.emit()


class FilterBar(QWidget):
    changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._debounce = QTimer(self, singleShot=True, interval=DEBOUNCE_MS)
        self._debounce.timeout.connect(self.changed)

        self.severity_button = QToolButton(popupMode=QToolButton.InstantPopup)
        self._severity_actions: dict[int | None, QAction] = {}
        self.severity_button.setMenu(self._build_severity_menu())

        self.facility = QComboBox()
        self.facility.addItem("All facilities", None)
        for code, name in enumerate(FACILITY_NAMES):
            self.facility.addItem(f"{name} ({code})", code)

        self.reset_button = QPushButton("Reset filters")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.rule_rows: list[RuleRow] = []
        controls = QHBoxLayout()
        self.add_rule_button = QPushButton("+ Filter rule")
        self.add_rule_button.setToolTip("Add a filter rule. Empty rules are inactive.")
        self.rules_match = QComboBox()
        self.rules_match.addItem("All rules (AND)", "all")
        self.rules_match.addItem("Any rule (OR)", "any")
        controls.addWidget(self.add_rule_button)
        controls.addWidget(self.rules_match)
        controls.addWidget(self.severity_button)
        controls.addWidget(self.facility)
        controls.addWidget(self.reset_button)
        controls.addStretch()
        outer.addLayout(controls)
        self._rules_layout = QVBoxLayout()
        outer.addLayout(self._rules_layout)
        self.add_rule_button.clicked.connect(lambda: self.add_rule())
        self.rules_match.currentIndexChanged.connect(self.changed)

        self.facility.currentIndexChanged.connect(self.changed)
        self.reset_button.clicked.connect(self.reset)
        self._update_severity_label()

    def add_rule(self, rule: FilterRule = FilterRule()) -> RuleRow:
        row = RuleRow(rule, self)
        self.rule_rows.append(row)
        self._rules_layout.addWidget(row)
        row.changed.connect(self._debounce.start)
        row.remove_requested.connect(lambda: self.remove_rule(row))
        self._debounce.start()
        return row

    def remove_rule(self, row: RuleRow) -> None:
        self.rule_rows.remove(row)
        self._rules_layout.removeWidget(row)
        row.deleteLater()
        self._debounce.start()

    def _build_severity_menu(self) -> QMenu:
        menu = QMenu(self)
        presets = (("All", ALL_SEVERITIES), ("Errors only (Emergency–Error)", (0, 1, 2, 3)),
                   ("Warning and above", (0, 1, 2, 3, 4)))
        for label, values in presets:
            menu.addAction(label, lambda v=values: self.set_severities(set(v)))
        menu.addSeparator()
        for sev in ALL_SEVERITIES:
            label = "Unknown (no PRI)" if sev is None else f"{sev} {SEVERITY_NAMES[sev]}"
            action = menu.addAction(label)
            action.setCheckable(True)
            action.setChecked(True)
            action.toggled.connect(self._severity_toggled)
            self._severity_actions[sev] = action
        return menu

    def _severity_toggled(self) -> None:
        self._update_severity_label()
        self.changed.emit()

    def selected_severities(self) -> set[int | None]:
        return {sev for sev, action in self._severity_actions.items() if action.isChecked()}

    def set_severities(self, values: set[int | None]) -> None:
        for sev, action in self._severity_actions.items():
            action.blockSignals(True)
            action.setChecked(sev in values)
            action.blockSignals(False)
        self._severity_toggled()

    def _update_severity_label(self) -> None:
        selected = self.selected_severities()
        if len(selected) == len(ALL_SEVERITIES):
            text = "Severity: all"
        elif not selected:
            text = "Severity: none"
        elif selected == {0, 1, 2, 3}:
            text = "Severity: errors"
        elif selected == {0, 1, 2, 3, 4}:
            text = "Severity: ≥ warning"
        else:
            text = f"Severity: {len(selected)} selected"
        self.severity_button.setText(text)

    def current_filter(self) -> EventFilter:
        selected = self.selected_severities()
        return EventFilter(
            severities=None if len(selected) == len(ALL_SEVERITIES) else frozenset(selected),
            facility=self.facility.currentData(),
            rules=tuple(row.rule() for row in self.rule_rows if row.value.text().strip()),
            rules_match=self.rules_match.currentData(),
        )

    def reset(self) -> None:
        self.restore_state({})
        self.changed.emit()

    def state(self) -> dict:
        return {
            "severities": [-1 if s is None else s for s in self.selected_severities()],
            "facility": self.facility.currentData(),
            "rules": [asdict(row.rule()) for row in self.rule_rows],
            "rules_match": self.rules_match.currentData(),
        }

    def restore_state(self, state: dict) -> None:
        """Restore without emitting ``changed`` for every widget."""
        widgets = (self.facility, self.rules_match)
        for widget in widgets:
            widget.blockSignals(True)
        try:
            self.facility.setCurrentIndex(max(0, self.facility.findData(state.get("facility"))))
            for row in list(self.rule_rows):
                self.remove_rule(row)
            for rule in state.get("rules", []):
                try:
                    self.add_rule(FilterRule(**rule))
                except (TypeError, ValueError):
                    log.warning("Invalid stored filter rule: %r", rule)
            # Legacy basic filters were always ANDed with the existing rule group.
            for key, field in (("text", "text"), ("sender", "sender"), ("app", "app")):
                value = state.get(key, "")
                if value.strip():
                    operator = ("words" if key == "text" and
                                state.get("mode", TEXT_MODE_WORDS) == TEXT_MODE_WORDS else "contains")
                    self.add_rule(FilterRule(field, operator, value,
                                             required=state.get("rules_match") == "any"))
            self.rules_match.setCurrentIndex(max(
                0, self.rules_match.findData(state.get("rules_match", "all"))))
            severities = state.get("severities")
            values = ALL_SEVERITIES if severities is None else [None if s == -1 else s for s in severities]
            for sev, action in self._severity_actions.items():
                action.blockSignals(True)
                action.setChecked(sev in values)
                action.blockSignals(False)
            self._update_severity_label()
        finally:
            for widget in widgets:
                widget.blockSignals(False)
        self._debounce.stop()
