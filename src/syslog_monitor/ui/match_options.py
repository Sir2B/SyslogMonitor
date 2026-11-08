"""VS Code-style toggles: Match Case, Match Whole Word, Use Regular Expression."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import QHBoxLayout, QLineEdit, QToolButton, QWidget

from syslog_monitor.i18n import tr
from syslog_monitor.matching import PLAIN_MATCH, MatchOptions, match_error

_BUTTON_STYLE = (
    "QToolButton { border: 1px solid transparent; border-radius: 3px; padding: 0px; }"
    "QToolButton:hover { border-color: palette(mid); }"
    "QToolButton:checked { background: palette(highlight); color: palette(highlighted-text); "
    "border-color: palette(highlight); }"
    "QToolButton:disabled { color: palette(mid); }"
)
INVALID_STYLE = "QLineEdit { border: 1px solid #d62728; }"


def options_label(options: MatchOptions) -> str:
    """Compact suffix such as ``" · Aa .*"`` for rule summaries; empty for plain matching."""
    flags = [label for label, active in (("Aa", options.case_sensitive), ("ab", options.whole_word),
                                         (".*", options.regex)) if active]
    return f" · {' '.join(flags)}" if flags else ""


class MatchOptionsBar(QWidget):
    """Three checkable buttons; optionally validates and binds Alt+C/W/R to ``line_edit``."""

    changed = Signal()

    def __init__(self, options: MatchOptions = PLAIN_MATCH, line_edit: QLineEdit | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(1)
        self.case_button = self._button("Aa", tr("Match Case"), "Alt+C", options.case_sensitive)
        self.word_button = self._button("ab", tr("Match Whole Word"), "Alt+W", options.whole_word)
        font = self.word_button.font()
        font.setUnderline(True)
        self.word_button.setFont(font)
        self.regex_button = self._button(".*", tr("Use Regular Expression"), "Alt+R", options.regex)
        for button in (self.case_button, self.word_button, self.regex_button):
            layout.addWidget(button)
            button.toggled.connect(self._toggled)
        self._line_edit = line_edit
        self._tooltip = ""
        if line_edit is not None:
            self._tooltip = line_edit.toolTip()
            for button, key in ((self.case_button, "Alt+C"), (self.word_button, "Alt+W"),
                                (self.regex_button, "Alt+R")):
                action = QAction(line_edit, shortcut=QKeySequence(key))
                action.setShortcutContext(Qt.WidgetShortcut)
                action.triggered.connect(lambda _checked=False, b=button: b.isEnabled() and b.toggle())
                line_edit.addAction(action)
            line_edit.textChanged.connect(self.validate)
            self.validate()

    def _button(self, text: str, name: str, shortcut: str, checked: bool) -> QToolButton:
        button = QToolButton(text=text, checkable=True, checked=checked)
        button.setToolTip(f"{name} ({shortcut})")
        button.setAccessibleName(name)
        button.setFixedSize(24, 22)
        button.setFocusPolicy(Qt.TabFocus)
        button.setStyleSheet(_BUTTON_STYLE)
        return button

    def _toggled(self, *_args) -> None:
        self.validate()
        self.changed.emit()

    def options(self) -> MatchOptions:
        return MatchOptions(self.case_button.isChecked(), self.word_button.isChecked(),
                            self.regex_button.isChecked())

    def set_options(self, options: MatchOptions) -> None:
        for button, checked in ((self.case_button, options.case_sensitive),
                                (self.word_button, options.whole_word),
                                (self.regex_button, options.regex)):
            button.blockSignals(True)
            button.setChecked(checked)
            button.blockSignals(False)
        self.validate()

    def error(self) -> str | None:
        if self._line_edit is None or not self.isEnabled():
            return None
        return match_error(self._line_edit.text(), self.options())

    def validate(self, *_args) -> None:
        if self._line_edit is None:
            return
        error = self.error()
        self._line_edit.setStyleSheet("" if error is None else INVALID_STYLE)
        self._line_edit.setToolTip(self._tooltip if error is None
                                   else tr("Invalid regex: {error}", error=error))

    def setEnabled(self, enabled: bool) -> None:  # noqa: N802 - Qt naming
        super().setEnabled(enabled)
        self.validate()
