"""Editable, ordered highlight rules; presentation only, matching lives in query.py."""

from __future__ import annotations

from dataclasses import asdict

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox, QColorDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy,
    QStackedWidget, QToolButton, QVBoxLayout, QWidget,
)

from syslog_monitor.query import DEFAULT_HIGHLIGHT, HighlightRule, Histogram, active_highlights
from syslog_monitor.i18n import tr
from syslog_monitor.ui.flow_layout import FlowLayout
from syslog_monitor.ui.formatting import format_count
from syslog_monitor.ui.palette import highlight_text_color

RULE_COLORS = ("#7b1fa2", "#00796b", "#1565c0", "#f9a825", "#c62828", "#ef6c00")


class HighlightRow(QWidget):
    changed = Signal()
    remove_requested = Signal()
    select_requested = Signal()
    edit_requested = Signal()
    move_up_requested = Signal()
    move_down_requested = Signal()

    def __init__(self, rule: HighlightRule, parent: QWidget) -> None:
        super().__init__(parent)
        self._selected = False
        self.summary_button = QToolButton()
        self.summary_button.setToolButtonStyle(Qt.ToolButtonTextOnly)
        self.summary_button.setCheckable(True)
        self.summary_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.summary_button.setToolTip(tr("Select this highlight for match navigation"))
        self.edit_button = QToolButton(text="✎")
        self.edit_button.setFixedSize(20, 20)
        self.edit_button.setToolTip(tr("Edit highlight rule"))
        self.enabled = QCheckBox(tr("Enabled"), checked=rule.enabled)
        self.popup_checkbox = QCheckBox(tr("Popup"), checked=rule.popup)
        self.value = QLineEdit(rule.text, clearButtonEnabled=True)
        self.value.setPlaceholderText(tr("Message contains …"))
        self.value.setToolTip(
            tr("Literal substring in the message (ASCII, case-insensitive).\n"
            "Optionally separate multiple strings with ;. Empty rules are inactive.\n"
            "When several rules match, the highest active rule takes precedence."))
        self.color_button = QPushButton()
        self.color_button.setToolTip(tr("Choose highlight color"))
        self.count_label = QLabel("…", textFormat=Qt.PlainText, alignment=Qt.AlignRight | Qt.AlignVCenter)
        self.count_label.setToolTip(tr("Counting matches…"))
        self.chip = QWidget(self)
        self.chip.setObjectName("highlight_chip")
        chip_layout = QHBoxLayout(self.chip)
        chip_layout.setContentsMargins(3, 0, 3, 0)
        chip_layout.setSpacing(2)
        chip_layout.addWidget(self.summary_button, 1)
        chip_layout.addWidget(self.count_label)
        chip_layout.addWidget(self.edit_button)
        self.up_button = QToolButton(text="↑")
        self.up_button.setToolTip(tr("Move up (higher priority)"))
        self.down_button = QToolButton(text="↓")
        self.down_button.setToolTip(tr("Move down (lower priority)"))
        self.remove_button = QToolButton(text="×")
        self.remove_button.setFixedSize(20, 20)
        self.remove_button.setToolTip(tr("Remove highlight rule"))
        self.remove_button.setAccessibleName(tr("Remove highlight rule"))
        chip_layout.addWidget(self.remove_button)
        self.editor = QWidget()
        editor_layout = QHBoxLayout(self.editor)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.setSpacing(3)
        for widget in (self.enabled, self.popup_checkbox, self.value, self.color_button, self.up_button,
                       self.down_button):
            editor_layout.addWidget(widget)
        editor_layout.setStretch(2, 1)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        layout.addWidget(self.chip)
        self.enabled.toggled.connect(self._rule_changed)
        self.popup_checkbox.toggled.connect(self._rule_changed)
        self.value.textChanged.connect(self._rule_changed)
        self.color_button.clicked.connect(self._choose_color)
        self.up_button.clicked.connect(self.move_up_requested)
        self.down_button.clicked.connect(self.move_down_requested)
        self.remove_button.clicked.connect(self.remove_requested)
        self.summary_button.clicked.connect(self._request_select)
        self.edit_button.clicked.connect(self.edit_requested)
        self.set_color(QColor(rule.color))

    def _request_select(self, *_args) -> None:
        self.select_requested.emit()

    def set_color(self, color: QColor) -> None:
        if not color.isValid():
            raise ValueError("Invalid highlight color")
        self._color = color.name()
        self.color_button.setText(self._color)
        self.color_button.setStyleSheet(
            f"background-color:{self._color}; color:{highlight_text_color(color).name()}")
        self._refresh_summary()
        self.changed.emit()

    def set_selected(self, selected: bool) -> None:
        self._selected = selected
        self.summary_button.setChecked(selected)
        self._refresh_summary()

    def _refresh_summary(self) -> None:
        text = self.value.text().strip() or tr("Empty highlight")
        self.summary_button.setText(text)
        border = "2px" if self._selected else "1px"
        style = "solid" if self.enabled.isChecked() else "dashed"
        self.summary_button.setStyleSheet("QToolButton { text-align: left; border: none; padding: 3px 5px; }")
        self.chip.setStyleSheet(
            f"QWidget#highlight_chip {{ border: {border} {style} {self._color}; border-radius: 3px; }}"
        )

    def _rule_changed(self, *_args) -> None:
        self._refresh_summary()
        self.changed.emit()

    def _choose_color(self) -> None:
        color = QColorDialog.getColor(QColor(self._color), self, tr("Highlight color"))
        if color.isValid():
            self.set_color(color)

    def rule(self) -> HighlightRule:
        return HighlightRule(self.value.text(), self._color, self.enabled.isChecked(),
                             self.popup_checkbox.isChecked())


class HighlightPanel(QWidget):
    changed = Signal()
    selected_rule_changed = Signal(str)
    find_requested = Signal(str, bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.rule_rows: list[HighlightRow] = []
        self.selected_row: HighlightRow | None = None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(3)
        controls = QHBoxLayout()
        self.add_rule_button = QPushButton(tr("+ Highlight"))
        self.add_rule_button.setToolTip(tr("Add another highlight rule with its own color"))
        self.summary = QLabel(textFormat=Qt.PlainText)
        self.previous_button = QToolButton(text="▲")
        self.previous_button.setToolTip(tr("Find previous (newer) match for the selected highlight"))
        self.next_button = QToolButton(text="▼")
        self.next_button.setToolTip(tr("Find next (older) match for the selected highlight"))
        self.previous_button.setEnabled(False)
        self.next_button.setEnabled(False)
        self.setToolTip(tr("The highest-priority matching rule determines the color."))
        self._flow_layout = FlowLayout()
        outer.addLayout(self._flow_layout)
        self._empty_editor = QWidget()
        self._editors = QStackedWidget()
        self._editors.addWidget(self._empty_editor)
        self._editors.hide()
        outer.addWidget(self._editors)
        outer.addStretch(1)
        self.add_rule_button.clicked.connect(lambda: self.add_rule())
        self.previous_button.clicked.connect(lambda: self._find_selected(newer=True))
        self.next_button.clicked.connect(self._find_selected)
        self._rebuild_flow()
        self.add_rule(HighlightRule(DEFAULT_HIGHLIGHT))

    def rules(self) -> tuple[HighlightRule, ...]:
        return tuple(row.rule() for row in self.rule_rows)

    def active_rules(self) -> tuple[HighlightRule, ...]:
        return active_highlights(self.rules())

    def notification_text(self) -> str:
        return ";".join(rule.text for rule in self.rules()
                         if rule.popup and active_highlights((rule,)))

    def invalidate_counts(self) -> None:
        for row in self.rule_rows:
            active = bool(active_highlights((row.rule(),)))
            row.count_label.setText("…" if active else "–")
            row.count_label.setToolTip(tr("Updating match count…") if active
                                        else tr("Rule is disabled or empty."))

    def set_counts(self, histogram: Histogram) -> None:
        if histogram.highlight_rules != self.active_rules():
            return  # A query for an earlier rule configuration may still finish.
        index = 0
        for row in self.rule_rows:
            if not active_highlights((row.rule(),)):
                row.count_label.setText("–")
                row.count_label.setToolTip(tr("Rule is disabled or empty."))
                continue
            count = sum(bucket[index] for bucket in histogram.highlight_counts)
            row.count_label.setText(format_count(count))
            row.count_label.setToolTip(
                tr("{count} matches in the active filters and time range.\n"
                "Counts all stored messages in the range, not just the loaded rows.\n"
                "When several rules match, only the highest active rule is counted.",
                   count=format_count(count)))
            if histogram.highlight_hourly_counts:
                mean, deviation = histogram.highlight_hourly_statistics(index)
                row.count_label.setToolTip(row.count_label.toolTip() + "\n" + tr(
                    "Average: {mean:.2f} matches/hour; standard deviation: {deviation:.2f} matches/hour.\n"
                    "Hourly intervals start at the displayed minimap range. Empty hours count; "
                    "partial hours are time-weighted. This is variation, not a confidence interval.",
                    mean=mean, deviation=deviation))
            index += 1

    def add_rule(self, rule: HighlightRule | None = None) -> HighlightRow:
        if rule is None:
            used = {row.rule().color for row in self.rule_rows}
            color = next((color for color in RULE_COLORS if color not in used),
                         RULE_COLORS[len(self.rule_rows) % len(RULE_COLORS)])
            rule = HighlightRule(color=color)
        row = HighlightRow(rule, self)
        self.rule_rows.append(row)
        self._editors.addWidget(row.editor)
        row.changed.connect(self.changed)
        row.remove_requested.connect(lambda: self.remove_rule(row))
        row.select_requested.connect(lambda: self.select_rule(row))
        row.edit_requested.connect(lambda: self.edit_rule(row))
        row.move_up_requested.connect(lambda: self.move_rule(row, -1))
        row.move_down_requested.connect(lambda: self.move_rule(row, 1))
        self._update_buttons()
        self._rebuild_flow()
        self.select_rule(row)
        self.changed.emit()
        return row

    def remove_rule(self, row: HighlightRow) -> None:
        old_index = self.rule_rows.index(row)
        was_selected = row is self.selected_row
        was_editing = self._editors.currentWidget() is row.editor
        self._editors.removeWidget(row.editor)
        row.editor.deleteLater()
        self.rule_rows.remove(row)
        self._rebuild_flow()
        row.hide()
        row.deleteLater()
        self._update_buttons()
        if was_editing:
            self._editors.setCurrentWidget(self._empty_editor)
            self._editors.hide()
        if was_selected:
            replacement = self.rule_rows[min(old_index, len(self.rule_rows) - 1)] if self.rule_rows else None
            self.select_rule(replacement)
        self.changed.emit()

    def edit_rule(self, row: HighlightRow) -> None:
        if self._editors.currentWidget() is row.editor:
            self._editors.setCurrentWidget(self._empty_editor)
            self._editors.hide()
            row.edit_button.setToolTip(tr("Edit highlight rule"))
            return
        for current in self.rule_rows:
            if self._editors.currentWidget() is current.editor:
                current.edit_button.setToolTip(tr("Edit highlight rule"))
                break
        self.select_rule(row)
        self._editors.setCurrentWidget(row.editor)
        self._editors.show()
        row.edit_button.setToolTip(tr("Hide highlight options"))

    def select_rule(self, row: HighlightRow | None) -> None:
        self.selected_row = row
        for current in self.rule_rows:
            current.set_selected(current is row)
        self.selected_rule_changed.emit(row.rule().text if row else "")
        self._update_navigation_buttons()

    def _find_selected(self, *, newer: bool = False) -> None:
        if self.selected_row is None:
            return
        rule = self.selected_row.rule()
        if active_highlights((rule,)):
            self.find_requested.emit(rule.text, newer)

    def move_rule(self, row: HighlightRow, offset: int) -> None:
        old = self.rule_rows.index(row)
        new = old + offset
        if not 0 <= new < len(self.rule_rows):
            return
        self.rule_rows.insert(new, self.rule_rows.pop(old))
        self._rebuild_flow()
        self._update_buttons()
        self.changed.emit()

    def _rebuild_flow(self) -> None:
        while self._flow_layout.count():
            self._flow_layout.takeAt(0)
        for widget in (self.add_rule_button, *self.rule_rows, self.previous_button,
                       self.next_button, self.summary):
            self._flow_layout.addWidget(widget)

    def _update_buttons(self) -> None:
        for i, row in enumerate(self.rule_rows):
            row.up_button.setEnabled(i > 0)
            row.down_button.setEnabled(i < len(self.rule_rows) - 1)
        self._update_navigation_buttons()

    def _update_navigation_buttons(self) -> None:
        can_find = self.selected_row is not None and bool(active_highlights((self.selected_row.rule(),)))
        self.previous_button.setEnabled(can_find)
        self.next_button.setEnabled(can_find)

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
