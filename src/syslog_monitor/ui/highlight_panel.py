"""Editable, ordered highlight rules; presentation only, matching lives in query.py."""

from __future__ import annotations

from dataclasses import asdict

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox, QColorDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QToolButton,
    QVBoxLayout, QWidget,
)

from syslog_monitor.query import DEFAULT_HIGHLIGHT, HighlightRule, Histogram, active_highlights
from syslog_monitor.ui.formatting import format_count
from syslog_monitor.ui.palette import highlight_text_color

RULE_COLORS = ("#7b1fa2", "#00796b", "#1565c0", "#f9a825", "#c62828", "#ef6c00")


class HighlightRow(QWidget):
    changed = Signal()
    remove_requested = Signal()
    move_up_requested = Signal()
    move_down_requested = Signal()

    def __init__(self, rule: HighlightRule, parent: QWidget) -> None:
        super().__init__(parent)
        self.enabled = QCheckBox("Enabled", checked=rule.enabled)
        self.value = QLineEdit(rule.text, clearButtonEnabled=True)
        self.value.setPlaceholderText("Message contains …")
        self.value.setToolTip(
            "Literal substring in the message (ASCII, case-insensitive).\n"
            "Optionally separate multiple strings with ;. Empty rules are inactive.\n"
            "When several rules match, the highest active rule takes precedence.")
        self.color_button = QPushButton()
        self.set_color(QColor(rule.color))
        self.color_button.setToolTip("Choose highlight color")
        self.count_label = QLabel("…", textFormat=Qt.PlainText, alignment=Qt.AlignRight | Qt.AlignVCenter)
        self.count_label.setToolTip("Counting matches…")
        self.up_button = QToolButton(text="↑")
        self.up_button.setToolTip("Move up (higher priority)")
        self.down_button = QToolButton(text="↓")
        self.down_button.setToolTip("Move down (lower priority)")
        self.remove_button = QToolButton(text="×")
        self.remove_button.setToolTip("Remove highlight rule")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        for widget in (self.enabled, self.value, self.count_label, self.color_button, self.up_button,
                       self.down_button, self.remove_button):
            layout.addWidget(widget)
        layout.setStretch(1, 1)
        self.enabled.toggled.connect(self.changed)
        self.value.textChanged.connect(self.changed)
        self.color_button.clicked.connect(self._choose_color)
        self.up_button.clicked.connect(self.move_up_requested)
        self.down_button.clicked.connect(self.move_down_requested)
        self.remove_button.clicked.connect(self.remove_requested)

    def set_color(self, color: QColor) -> None:
        if not color.isValid():
            raise ValueError("Invalid highlight color")
        self._color = color.name()
        self.color_button.setText(self._color)
        self.color_button.setStyleSheet(
            f"background-color:{self._color}; color:{highlight_text_color(color).name()}")
        self.changed.emit()

    def _choose_color(self) -> None:
        color = QColorDialog.getColor(QColor(self._color), self, "Highlight color")
        if color.isValid():
            self.set_color(color)

    def rule(self) -> HighlightRule:
        return HighlightRule(self.value.text(), self._color, self.enabled.isChecked())


class HighlightPanel(QWidget):
    changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.rule_rows: list[HighlightRow] = []
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(3)
        controls = QHBoxLayout()
        self.add_rule_button = QPushButton("+ Highlight")
        self.add_rule_button.setToolTip("Add another highlight rule with its own color")
        self.popup = QCheckBox("Popup", checked=True)
        self.summary = QLabel(textFormat=Qt.PlainText)
        self.setToolTip("The highest-priority matching rule determines the color.")
        for widget in (self.add_rule_button, self.popup):
            controls.addWidget(widget)
        controls.addWidget(self.summary)
        controls.addStretch()
        outer.addLayout(controls)
        self._rows_layout = QVBoxLayout()
        self._rows_layout.setSpacing(3)
        outer.addLayout(self._rows_layout)
        outer.addStretch(1)
        self.add_rule_button.clicked.connect(lambda: self.add_rule())
        self.add_rule(HighlightRule(DEFAULT_HIGHLIGHT))

    def rules(self) -> tuple[HighlightRule, ...]:
        return tuple(row.rule() for row in self.rule_rows)

    def active_rules(self) -> tuple[HighlightRule, ...]:
        return active_highlights(self.rules())

    def notification_text(self) -> str:
        return ";".join(rule.text for rule in self.active_rules())

    def invalidate_counts(self) -> None:
        for row in self.rule_rows:
            active = bool(active_highlights((row.rule(),)))
            row.count_label.setText("…" if active else "–")
            row.count_label.setToolTip(
                "Updating match count…" if active else "Rule is disabled or empty.")

    def set_counts(self, histogram: Histogram) -> None:
        if histogram.highlight_rules != self.active_rules():
            return  # A query for an earlier rule configuration may still finish.
        index = 0
        for row in self.rule_rows:
            if not active_highlights((row.rule(),)):
                row.count_label.setText("–")
                row.count_label.setToolTip("Rule is disabled or empty.")
                continue
            count = sum(bucket[index] for bucket in histogram.highlight_counts)
            row.count_label.setText(format_count(count))
            row.count_label.setToolTip(
                f"{format_count(count)} matches in the active filters and time range.\n"
                "Counts all stored messages in the range, not just the loaded rows.\n"
                "When several rules match, only the highest active rule is counted.")
            index += 1

    def add_rule(self, rule: HighlightRule | None = None) -> HighlightRow:
        if rule is None:
            used = {row.rule().color for row in self.rule_rows}
            color = next((color for color in RULE_COLORS if color not in used),
                         RULE_COLORS[len(self.rule_rows) % len(RULE_COLORS)])
            rule = HighlightRule(color=color)
        row = HighlightRow(rule, self)
        self.rule_rows.append(row)
        self._rows_layout.addWidget(row)
        row.changed.connect(self.changed)
        row.remove_requested.connect(lambda: self.remove_rule(row))
        row.move_up_requested.connect(lambda: self.move_rule(row, -1))
        row.move_down_requested.connect(lambda: self.move_rule(row, 1))
        self._update_buttons()
        self.changed.emit()
        return row

    def remove_rule(self, row: HighlightRow) -> None:
        self.rule_rows.remove(row)
        self._rows_layout.removeWidget(row)
        row.hide()
        row.deleteLater()
        self._update_buttons()
        self.changed.emit()

    def move_rule(self, row: HighlightRow, offset: int) -> None:
        old = self.rule_rows.index(row)
        new = old + offset
        if not 0 <= new < len(self.rule_rows):
            return
        self.rule_rows.insert(new, self.rule_rows.pop(old))
        self._rows_layout.removeWidget(row)
        self._rows_layout.insertWidget(new, row)
        self._update_buttons()
        self.changed.emit()

    def _update_buttons(self) -> None:
        for i, row in enumerate(self.rule_rows):
            row.up_button.setEnabled(i > 0)
            row.down_button.setEnabled(i < len(self.rule_rows) - 1)

    def state(self) -> list[dict]:
        return [asdict(rule) for rule in self.rules()]

    def restore_state(self, state: object) -> None:
        if not isinstance(state, list):
            raise ValueError("Stored highlights must be a list")
        rules = []
        for item in state:
            if not isinstance(item, dict):
                raise ValueError("Stored highlight rule is invalid")
            rules.append(HighlightRule(**item))
        self.blockSignals(True)
        try:
            for row in list(self.rule_rows):
                self.remove_rule(row)
            for rule in rules:
                self.add_rule(rule)
        finally:
            self.blockSignals(False)
        self.changed.emit()
