"""Analysis page: how often each message occurred, with number-insensitive and similar-text grouping."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel, QPushButton, QSpinBox,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from syslog_monitor.analysis import (
    DEFAULT_SIMILARITY, MIN_SIMILARITY, MODE_EXACT, MODE_NUMBERS, MODE_SIMILAR, FrequencyReport,
)
from syslog_monitor.i18n import tr
from syslog_monitor.query import EventFilter
from syslog_monitor.ui.formatting import format_count, format_ts
from syslog_monitor.ui.query_worker import QueryClient

COL_COUNT, COL_SHARE, COL_VARIANTS, COL_FIRST, COL_LAST, COL_MESSAGE = range(6)


class _SortItem(QTableWidgetItem):
    """Sorts by the value stored in ``Qt.UserRole`` instead of the displayed text."""

    def __lt__(self, other: QTableWidgetItem) -> bool:
        return self.data(Qt.UserRole) < other.data(Qt.UserRole)


def _item(text: str, key, align=Qt.AlignRight | Qt.AlignVCenter) -> QTableWidgetItem:
    item = _SortItem(text)
    item.setData(Qt.UserRole, key)
    item.setTextAlignment(align)
    return item


class AnalysisPage(QWidget):
    def __init__(self, db_path: Path, filter_provider: Callable[[], EventFilter],
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Message analysis"))
        self._filter_provider = filter_provider
        self.queries = QueryClient(db_path, self)
        self.queries.error.connect(self._failed)
        self._request: int | None = None
        self.report: FrequencyReport | None = None

        self.mode = QComboBox()
        for label, value, tip in (
            (tr("Exact text"), MODE_EXACT, tr("Only identical messages are counted together.")),
            (tr("Ignore numbers"), MODE_NUMBERS,
             tr("Messages that differ only in numbers are counted together; numbers are shown as #.")),
            (tr("Similar texts"), MODE_SIMILAR,
             tr("Messages are counted together when their words match at least the chosen "
                "similarity.")),
        ):
            self.mode.addItem(label, value)
            self.mode.setItemData(self.mode.count() - 1, tip, Qt.ToolTipRole)
        self.mode.setCurrentIndex(self.mode.findData(MODE_NUMBERS))
        self.similarity = QSpinBox(minimum=round(MIN_SIMILARITY * 100), maximum=100,
                                   value=round(DEFAULT_SIMILARITY * 100), suffix=" %", singleStep=5)
        self.similarity.setToolTip(tr("Minimum share of matching words for similar texts"))
        self.similarity_label = QLabel(tr("Similarity:"))
        self.analyze_button = QPushButton(tr("Analyze"))
        self.analyze_button.setToolTip(tr("Count the messages again"))
        self.analyze_button.clicked.connect(self.analyze)
        self._debounce = QTimer(self, singleShot=True, interval=300)
        self._debounce.timeout.connect(self.analyze)
        self.mode.currentIndexChanged.connect(self._mode_changed)
        self.similarity.valueChanged.connect(lambda _value: self._debounce.start())

        controls = QHBoxLayout()
        controls.addWidget(QLabel(tr("Grouping:")))
        controls.addWidget(self.mode)
        controls.addWidget(self.similarity_label)
        controls.addWidget(self.similarity)
        controls.addWidget(self.analyze_button)
        controls.addStretch(1)

        hint = QLabel(tr("Uses the current filters and time range of the log view."))
        hint.setWordWrap(True)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.PlainText)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            [tr("Count"), tr("Share"), tr("Variants"), tr("First"), tr("Last"), tr("Message")])
        self.table.horizontalHeaderItem(COL_VARIANTS).setToolTip(
            tr("Number of different exact messages in this group"))
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setWordWrap(False)
        self.table.verticalHeader().hide()
        header = self.table.horizontalHeader()
        for column in range(COL_MESSAGE):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(COL_MESSAGE, QHeaderView.Stretch)
        self.table.setMinimumHeight(240)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(controls)
        layout.addWidget(hint)
        layout.addWidget(self.summary)
        layout.addWidget(self.table, 1)
        self._mode_changed()
        self._debounce.stop()  # the owner starts the first analysis when the page is shown

    @property
    def busy(self) -> bool:
        return self.queries.is_pending(self._request)

    def _mode_changed(self) -> None:
        similar = self.mode.currentData() == MODE_SIMILAR
        self.similarity.setEnabled(similar)
        self.similarity_label.setEnabled(similar)
        self.table.setColumnHidden(COL_VARIANTS, self.mode.currentData() == MODE_EXACT)
        self._debounce.start()

    def analyze(self) -> None:
        self._debounce.stop()
        self.queries.new_generation()
        filters = self._filter_provider()
        mode = self.mode.currentData()
        similarity = self.similarity.value() / 100
        self.summary.setText(tr("Analyzing…"))
        self._request = self.queries.submit(
            lambda runner: runner.message_frequencies(filters, mode, similarity), self._show)

    def _show(self, report: FrequencyReport) -> None:
        self._request = None
        self.report = report
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(report.groups))
        for row, group in enumerate(report.groups):
            share = group.count / report.total if report.total else 0.0
            message = _item(group.pattern, group.pattern, Qt.AlignLeft | Qt.AlignVCenter)
            tip = group.pattern if group.variants == 1 else tr(
                "{pattern}\n\nExample: {example}", pattern=group.pattern, example=group.example)
            if group.patterns > 1:
                tip += "\n" + tr("{count} similar patterns", count=format_count(group.patterns))
            message.setToolTip(tip)
            for column, item in (
                (COL_COUNT, _item(format_count(group.count), group.count)),
                (COL_SHARE, _item(f"{share * 100:.1f} %", share)),
                (COL_VARIANTS, _item(format_count(group.variants), group.variants)),
                (COL_FIRST, _item(format_ts(group.first_ms), group.first_ms, Qt.AlignLeft | Qt.AlignVCenter)),
                (COL_LAST, _item(format_ts(group.last_ms), group.last_ms, Qt.AlignLeft | Qt.AlignVCenter)),
                (COL_MESSAGE, message),
            ):
                self.table.setItem(row, column, item)
        self.table.setSortingEnabled(True)
        self.table.sortItems(COL_COUNT, Qt.DescendingOrder)
        text = tr("{groups} groups from {total} messages",
                  groups=format_count(len(report.groups)), total=format_count(report.total))
        if report.truncated:
            text += " " + (tr("Similar texts were grouped from the {limit} most frequent patterns.",
                              limit=format_count(report.limit)) if report.mode == MODE_SIMILAR
                           else tr("Only the {limit} most frequent groups are shown.",
                                   limit=format_count(report.limit)))
        self.summary.setText(text)

    def _failed(self, message: str) -> None:
        self._request = None
        self.summary.setText(tr("Analysis failed: {error}", error=message))

    def shutdown(self) -> None:
        self._debounce.stop()
        self.queries.shutdown()
