"""Uniform filter rules with separate severity and facility controls."""

from __future__ import annotations

import logging
from dataclasses import asdict

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QLineEdit, QMenu, QPushButton, QStackedWidget,
    QToolButton, QVBoxLayout, QWidget,
)

from syslog_monitor.events import FACILITY_NAMES, SEVERITY_NAMES
from syslog_monitor.query import TEXT_MODE_WORDS, EventFilter, FilterRule
from syslog_monitor.ui.flow_layout import FlowLayout

log = logging.getLogger(__name__)

DEBOUNCE_MS = 300
ALL_SEVERITIES: tuple[int | None, ...] = (*range(len(SEVERITY_NAMES)), None)


class RuleRow(QWidget):
    changed = Signal()
    remove_requested = Signal()
    edit_requested = Signal()

    def __init__(self, rule: FilterRule, parent: QWidget) -> None:
        super().__init__(parent)
        self.summary_button = QToolButton()
        self.summary_button.setToolButtonStyle(Qt.ToolButtonTextOnly)
        self.summary_button.setStyleSheet(
            "QToolButton { text-align: left; border: none; padding: 3px 5px; }"
        )
        self.edit_button = QToolButton(text="✎")
        self.edit_button.setFixedSize(20, 20)
        self.edit_button.setToolTip("Edit filter rule")
        self.remove_button = QToolButton(text="×")
        self.remove_button.setFixedSize(20, 20)
        self.remove_button.setToolTip("Remove filter rule")
        self.remove_button.setAccessibleName("Remove filter rule")
        self.chip = QWidget(self)
        self.chip.setObjectName("filter_chip")
        self.chip.setStyleSheet(
            "QWidget#filter_chip { border: 1px solid #9aa3ad; border-radius: 3px; }"
        )
        chip_layout = QHBoxLayout(self.chip)
        chip_layout.setContentsMargins(3, 0, 3, 0)
        chip_layout.setSpacing(2)
        chip_layout.addWidget(self.summary_button, 1)
        chip_layout.addWidget(self.edit_button)
        chip_layout.addWidget(self.remove_button)
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
        self.editor = QWidget()
        editor_layout = QHBoxLayout(self.editor)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        for widget in (self.field, self.operator, self.value, self.required):
            editor_layout.addWidget(widget)
        editor_layout.setStretch(2, 1)
        self.editor.hide()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.chip)
        self.field.setCurrentIndex(self.field.findData(rule.field))
        self._update_operators()
        self.operator.setCurrentIndex(self.operator.findData(rule.operator))
        self.value.setText(rule.value)
        self.field.currentIndexChanged.connect(self._field_changed)
        self.operator.currentIndexChanged.connect(self._rule_changed)
        self.value.textChanged.connect(self._rule_changed)
        self.required.toggled.connect(self._rule_changed)
        self.remove_button.clicked.connect(self.remove_requested)
        self.edit_button.clicked.connect(self.edit_requested)
        self._update_summary()

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
        self._rule_changed()

    def _rule_changed(self, *_args) -> None:
        self._update_summary()
        self.changed.emit()

    def _update_summary(self) -> None:
        value = self.value.text().strip() or "…"
        required = " · Always AND" if self.required.isChecked() else ""
        text = f"{self.field.currentText()} {self.operator.currentText()}: {value}{required}"
        self.summary_button.setText(text)
        self.summary_button.setToolTip(text)

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
        self._flow_layout = FlowLayout()
        outer.addLayout(self._flow_layout)
        self.add_rule_button = QPushButton("+ Filter rule")
        self.add_rule_button.setToolTip("Add a filter rule. Empty rules are inactive.")
        self.rules_match = QComboBox()
        self.rules_match.addItem("All rules (AND)", "all")
        self.rules_match.addItem("Any rule (OR)", "any")
        dropdown_height = max(self.facility.sizeHint().height(), self.rules_match.sizeHint().height())
        for widget in (self.severity_button, self.facility, self.rules_match):
            widget.setFixedHeight(dropdown_height)
        self._empty_editor = QWidget()
        self._editors = QStackedWidget()
        self._editors.addWidget(self._empty_editor)
        self._editors.hide()
        outer.addWidget(self._editors)
        self.add_rule_button.clicked.connect(lambda: self.add_rule())
        self.rules_match.currentIndexChanged.connect(self.changed)

        self.facility.currentIndexChanged.connect(self.changed)
        self.reset_button.clicked.connect(self.reset)
        self._update_severity_label()
        self._rebuild_flow()

    def add_rule(self, rule: FilterRule = FilterRule(), *, expand: bool = False) -> RuleRow:
        row = RuleRow(rule, self)
        self.rule_rows.append(row)
        self._editors.addWidget(row.editor)
        row.changed.connect(self._debounce.start)
        row.remove_requested.connect(lambda: self.remove_rule(row))
        row.edit_requested.connect(lambda: self.edit_rule(row))
        self._rebuild_flow()
        if expand:
            self.edit_rule(row)
        self._debounce.start()
        return row

    def remove_rule(self, row: RuleRow) -> None:
        if self._editors.currentWidget() is row.editor:
            self._editors.setCurrentWidget(self._empty_editor)
            self._editors.hide()
        self._editors.removeWidget(row.editor)
        row.editor.deleteLater()
        self.rule_rows.remove(row)
        row.deleteLater()
        self._rebuild_flow()
        self._debounce.start()

    def edit_rule(self, row: RuleRow) -> None:
        if self._editors.currentWidget() is row.editor:
            self._editors.setCurrentWidget(self._empty_editor)
            self._editors.hide()
            row.edit_button.setToolTip("Edit filter rule")
            return
        for current in self.rule_rows:
            if self._editors.currentWidget() is current.editor:
                current.edit_button.setToolTip("Edit filter rule")
                break
        self._editors.setCurrentWidget(row.editor)
        self._editors.show()
        row.edit_button.setToolTip("Hide filter options")

    def _rebuild_flow(self) -> None:
        while self._flow_layout.count():
            self._flow_layout.takeAt(0)
        for widget in (self.add_rule_button, *self.rule_rows, self.rules_match,
                       self.severity_button, self.facility, self.reset_button):
            self._flow_layout.addWidget(widget)

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
