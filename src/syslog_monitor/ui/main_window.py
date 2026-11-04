"""Main window: filters, minimap, paged live/history event list and details."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QDateTime, QEvent, QSettings, Qt, QTimer, Slot
from PySide6.QtGui import QAction, QCloseEvent, QFont, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDateTimeEdit, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QMainWindow,
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QSplitter, QTableView, QToolBar,
    QToolButton, QVBoxLayout, QWidget,
)

from syslog_monitor import APP_DISPLAY_NAME
from syslog_monitor.config import Settings, save_settings
from syslog_monitor.events import SEVERITY_CLASS_LABELS, SeverityClass, severity_class
from syslog_monitor.firewall import FirewallCheck, Level, check_firewalls, current_programs, remedy
from syslog_monitor.mcp_server import McpService, client_config
from syslog_monitor.query import (
    DEFAULT_HIGHLIGHT, TEXT_MODE_SUBSTRING, TEXT_MODE_WORDS, Cursor, EventFilter, HighlightBatch, Histogram,
    HighlightRule, QueryRunner,
)
from syslog_monitor.service import CaptureService
from syslog_monitor.stats import RateTracker, StatsSnapshot
from syslog_monitor.ui.event_model import EventTableModel
from syslog_monitor.ui.filter_bar import ALL_SEVERITIES, FilterBar
from syslog_monitor.ui.firewall_status import Checker, FirewallMonitor
from syslog_monitor.ui.formatting import format_bytes, format_count, format_event_details, format_ts
from syslog_monitor.ui.highlight_alerts import MAX_LISTED, MIN_INTERVAL_S, HighlightAlerter
from syslog_monitor.ui.highlight_panel import HighlightPanel
from syslog_monitor.ui.icons import app_icon
from syslog_monitor.ui.minimap import CLASS_COLORS, MinimapWidget
from syslog_monitor.ui.query_worker import QueryClient
from syslog_monitor.ui.settings_dialog import SettingsDialog
from syslog_monitor.ui.tray import TrayController

log = logging.getLogger(__name__)

MINUTE = 60_000
HOUR = 60 * MINUTE
DAY = 24 * HOUR
RANGE_PRESETS: tuple[tuple[str, int | None], ...] = (
    ("15 minutes", 15 * MINUTE), ("1 hour", HOUR), ("6 hours", 6 * HOUR),
    ("24 hours", DAY), ("7 days", 7 * DAY), ("30 days", 30 * DAY), ("All", None),
)
DEFAULT_RANGE_INDEX = 3
CUSTOM_RANGE_INDEX = len(RANGE_PRESETS)  # extra combo entry "From / To"
DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss"
PAGE_SIZE = 500
MAX_ROWS = 5000
LIVE_FETCH_LIMIT = 1000
SCROLL_PREFETCH_ROWS = 50


@dataclass(frozen=True, slots=True)
class Timings:
    live_ms: int = 1000
    histogram_ms: int = 5000
    status_ms: int = 1000
    firewall_ms: int = 5 * 60_000


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


Bounds = tuple[int | None, int | None]  # (inclusive start, exclusive end), None = open


def _range_bounds(now_ms: int, duration: int | None, custom: Bounds | None) -> Bounds:
    """Time limits of the selected range: a preset relative to now or fixed From/To values."""
    if custom is not None:
        return custom
    return (None if duration is None else now_ms - duration), None


class MainWindow(QMainWindow):
    def __init__(self, service: CaptureService, *, settings_path: Path, ui_state: QSettings,
                 tray_enabled: bool, timings: Timings = Timings(),
                 firewall_checker: Checker = check_firewalls, mcp: McpService | None = None) -> None:
        super().__init__()
        self.service = service
        self.mcp = mcp
        self._settings_path = settings_path
        self._ui_state = ui_state
        self._quitting = False
        self._live = True
        self._zoom: tuple[int, int] | None = None
        self._range_index = DEFAULT_RANGE_INDEX
        self._persisted_at_pause = 0
        self._older_request: int | None = None
        self._newer_request: int | None = None
        self._live_request: int | None = None
        self._hist_request: int | None = None
        self._adjusting_scroll = False
        self._search_cursor: Cursor | None = None
        self._search_revision = 0
        self._highlight_cursor: Cursor | None = None
        self._highlight_revision = 0
        self._watch_after_id: int | None = None
        self._watch_request: int | None = None
        self._rate_tracker = RateTracker()

        self.setWindowTitle(APP_DISPLAY_NAME)
        self.setWindowIcon(app_icon())
        self.queries = QueryClient(service.db_path, self)
        self.queries.error.connect(self._on_query_error)

        self._build_ui()
        self.tray = TrayController(self) if tray_enabled else None
        if self.tray:
            self.tray.open_requested.connect(self.show_and_raise)
            self.tray.quit_requested.connect(self.quit_application)
        self.highlight_alerts = HighlightAlerter(self._show_highlight_alert)
        self.firewall = FirewallMonitor(firewall_checker, self)
        self.firewall.checked.connect(self._apply_firewall)
        self._firewall_check: FirewallCheck | None = None
        self._firewall_warned_level = Level.OK

        self._timers = []
        for interval, slot in ((timings.live_ms, self._live_tick),
                               (timings.live_ms, self._highlight_watch_tick),
                               (timings.histogram_ms, self._histogram_tick),
                               (timings.status_ms, self._update_status),
                               (timings.firewall_ms, self.check_firewall)):
            timer = QTimer(self, interval=interval)
            timer.timeout.connect(slot)
            timer.start()
            self._timers.append(timer)

        self._restore_ui_state()
        self._update_status()
        self.refresh_all()
        self.check_firewall()

    # ------------------------------------------------------------------ UI setup
    def _build_ui(self) -> None:
        toolbar = QToolBar("Controls", objectName="main_toolbar", movable=False)
        self.addToolBar(toolbar)
        self.listen_action = QAction("Receive", self, checkable=True)
        self.listen_action.setToolTip("Start/stop the enabled UDP, TCP and TLS listeners")
        self.listen_action.triggered.connect(self._toggle_listener)
        self.live_action = QAction("● Live", self, checkable=True, checked=True)
        self.live_action.setToolTip("Live: automatically show the newest messages.\n"
                                    "Off: pause the view; receiving and storage continue.")
        self.live_action.toggled.connect(self.set_live)
        self.range_combo = QComboBox()
        for label, _ in RANGE_PRESETS:
            self.range_combo.addItem(label)
        self.range_combo.addItem("From / To…")
        self.range_combo.setCurrentIndex(DEFAULT_RANGE_INDEX)
        self.range_combo.currentIndexChanged.connect(self._range_index_changed)
        self.range_from_check = QCheckBox("From")
        self.range_to_check = QCheckBox("To")
        self.range_from = QDateTimeEdit(calendarPopup=True, displayFormat=DATETIME_FORMAT)
        self.range_to = QDateTimeEdit(calendarPopup=True, displayFormat=DATETIME_FORMAT)
        self.range_from_check.setToolTip("Optional start time (inclusive). Unchecked: from the oldest message.")
        self.range_to_check.setToolTip("Optional end time (includes the displayed second).\n"
                                       "Unchecked: until now; new messages appear live.")
        self._custom_timer = QTimer(self, singleShot=True, interval=400)  # wait until typing pauses
        self._custom_timer.timeout.connect(self._range_changed)
        for widget in (self.range_from_check, self.range_to_check):
            widget.toggled.connect(self._custom_edited)
        for widget in (self.range_from, self.range_to):
            widget.dateTimeChanged.connect(self._custom_edited)
        self.reset_zoom_action = QAction("Reset zoom", self, enabled=False)
        self.reset_zoom_action.triggered.connect(self.reset_zoom)
        self.clear_view_action = QAction("🧹 Clear view", self, shortcut=QKeySequence("Ctrl+L"))
        self.clear_view_action.setToolTip(
            "Show only messages from now on (Ctrl+L) by setting “From” to the current time.\n"
            "Nothing is deleted. Choose another range or uncheck “From” to show older messages again.")
        self.clear_view_action.triggered.connect(self.clear_view)
        settings_action = QAction("Settings…", self)
        settings_action.triggered.connect(self.open_settings)
        quit_action = QAction("Quit", self, shortcut=QKeySequence.Quit)
        quit_action.triggered.connect(self.quit_application)
        refresh_action = QAction("Refresh", self, shortcut=QKeySequence.Refresh)
        refresh_action.triggered.connect(self.refresh_all)
        self.mode_label = QLabel()
        self.mode_label.setTextFormat(Qt.RichText)
        for item in (self.listen_action, self.live_action, None, refresh_action, None,
                     settings_action, quit_action):
            if item is None:
                toolbar.addSeparator()
            elif isinstance(item, QAction):
                toolbar.addAction(item)
            else:
                toolbar.addWidget(item)

        self.filter_bar = FilterBar()
        self.filter_bar.changed.connect(self.refresh_all)
        self.search_text = QLineEdit(placeholderText="Find matches while keeping context…",
                                     clearButtonEnabled=True)
        self.search_text.setToolTip(
            "Navigate matches within the active filters without hiding other messages.\n"
            "Enter/F3: next (older) match; Shift+F3: previous (newer) match.")
        self.search_mode = QComboBox()
        self.search_mode.addItem("Words", TEXT_MODE_WORDS)
        self.search_mode.addItem("Substring", TEXT_MODE_SUBSTRING)
        self.search_previous = QPushButton("▲ Newer")
        self.search_previous.setToolTip("Previous (newer) match – Shift+F3")
        self.search_next = QPushButton("▼ Older")
        self.search_next.setToolTip("Next (older) match – Enter/F3")
        self.search_result = QLabel()
        self.search_result.setTextFormat(Qt.PlainText)
        self.search_previous.clicked.connect(lambda: self.find_text(newer=True))
        self.search_next.clicked.connect(self.find_text)
        self.search_text.returnPressed.connect(self.find_text)
        self.search_text.textChanged.connect(self._reset_search)
        self.search_mode.currentIndexChanged.connect(self._reset_search)
        self._reset_search()
        search_row = QHBoxLayout()
        for widget in (QLabel("Search:"), self.search_text, self.search_mode,
                       self.search_previous, self.search_next, self.search_result):
            search_row.addWidget(widget)
        search_row.setStretch(1, 3)
        focus_search = QAction(self, shortcut=QKeySequence.Find)
        focus_search.triggered.connect(lambda: self.search_text.setFocus())
        self.addAction(focus_search)
        for shortcut, newer in (("F3", False), ("Shift+F3", True)):
            action = QAction(self, shortcut=QKeySequence(shortcut))
            action.triggered.connect(lambda _checked=False, n=newer: self.find_text(newer=n))
            self.addAction(action)

        self.minimap = MinimapWidget()
        self.minimap.time_clicked.connect(self.jump_to_time)
        self.minimap.range_selected.connect(self.zoom_to)
        self.minimap_range_label = QLabel()
        self.minimap_range_label.setStyleSheet("color:#555")
        # may be clipped on narrow windows; start/end are also on the minimap axis
        self.minimap_range_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        minimap_section = QGroupBox()
        minimap_layout = QVBoxLayout(minimap_section)
        minimap_layout.setContentsMargins(6, 4, 6, 4)
        minimap_layout.setSpacing(2)
        time_controls = QHBoxLayout()
        range_label = QLabel("Time range:")
        range_label.setBuddy(self.range_combo)
        time_controls.addWidget(range_label)
        time_controls.addWidget(self.range_combo)
        self.custom_range = QWidget()
        custom_layout = QHBoxLayout(self.custom_range)
        custom_layout.setContentsMargins(0, 0, 0, 0)
        for widget in (self.range_from_check, self.range_from, self.range_to_check, self.range_to):
            custom_layout.addWidget(widget)
        self.custom_range.setVisible(False)
        time_controls.addWidget(self.custom_range)
        self.clear_view_button = QToolButton()
        self.clear_view_button.setDefaultAction(self.clear_view_action)
        time_controls.addWidget(self.clear_view_button)
        self.reset_zoom_button = QToolButton()
        self.reset_zoom_button.setDefaultAction(self.reset_zoom_action)
        time_controls.addWidget(self.reset_zoom_button)
        time_controls.addWidget(self.minimap_range_label, 1)
        minimap_layout.addLayout(time_controls)
        minimap_layout.addWidget(self.minimap)
        self.legend = QLabel()
        self.legend.setTextFormat(Qt.RichText)
        self.legend.setTextInteractionFlags(Qt.LinksAccessibleByMouse | Qt.LinksAccessibleByKeyboard)
        self.legend.linkActivated.connect(self._filter_severity)
        self.legend.setToolTip(
            "Click: show only this severity group; click again: show all.\n"
            "Ctrl+click: add/remove groups. All: reset the severity filter.\n"
            "Counts apply to the active filters.")
        time_controls.addWidget(self.legend)

        self.model = EventTableModel(MAX_ROWS, self)
        self.highlights = HighlightPanel()
        self.highlights.find_requested.connect(self.find_highlight)
        self.highlights.selected_rule_changed.connect(self._reset_highlight_navigation)
        self.highlight_label = self.highlights.summary
        self._highlight_timer = QTimer(self, singleShot=True, interval=300)
        self._highlight_timer.timeout.connect(self._request_histogram)
        self.highlights.changed.connect(self._highlight_changed)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setStyleSheet(
            "QTableView::item:selected { background-color: #505050; color: #ffffff; "
            "border-top: 1px solid #303030; border-bottom: 1px solid #303030; }"
        )
        self.table.setToolTip("Ctrl/Shift: select multiple rows. Ctrl+C: copy selection.")
        self.copy_action = QAction("Copy selected rows", self.table,
                                   shortcut=QKeySequence.Copy, enabled=False)
        self.copy_action.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        self.copy_action.triggered.connect(self.copy_selected_rows)
        self.select_all_action = QAction("Select all loaded rows", self.table,
                                         shortcut=QKeySequence.SelectAll)
        self.select_all_action.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        self.select_all_action.triggered.connect(self.table.selectAll)
        self.table.addActions([self.copy_action, self.select_all_action])
        self.table.setContextMenuPolicy(Qt.ActionsContextMenu)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerItem)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.Interactive)
        for column, width in enumerate((170, 80, 70, 110, 120, 130)):
            self.table.setColumnWidth(column, width)
        self.table.verticalScrollBar().valueChanged.connect(self._on_scroll)
        self._visible_range_timer = QTimer(self, singleShot=True)
        self._visible_range_timer.timeout.connect(self._update_marker)
        self.table.viewport().installEventFilter(self)
        for signal in (self.model.modelReset, self.model.rowsInserted, self.model.rowsRemoved,
                       self.table.verticalScrollBar().rangeChanged):
            signal.connect(lambda *_args: self._visible_range_timer.start(0))
        self.table.selectionModel().currentRowChanged.connect(self._on_current_row)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)

        self.details = QPlainTextEdit(readOnly=True)
        self.details.setFont(QFont("Consolas", 9))
        self.details.setPlaceholderText("Select a message to view its details and raw data.")

        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.details)
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 1)

        self.filters_scroll = QScrollArea(widgetResizable=True)
        self.highlights_scroll = QScrollArea(widgetResizable=True)
        self.filter_bar.layout().setAlignment(Qt.AlignTop)
        self.rules_splitter = QSplitter(Qt.Horizontal)
        self.rules_splitter.setHandleWidth(17)
        self.rules_splitter.setStyleSheet(
            "QSplitter::handle:horizontal { background: palette(mid); "
            "border-left: 8px solid palette(window); border-right: 8px solid palette(window); }"
        )
        self._rules_height_timer = QTimer(self, singleShot=True)
        self._rules_height_timer.timeout.connect(self._update_rules_height)
        for scroll, panel in ((self.filters_scroll, self.filter_bar),
                              (self.highlights_scroll, self.highlights)):
            scroll.setFrameShape(QScrollArea.NoFrame)
            scroll.setWidget(panel)
            scroll.setMinimumWidth(200)
            panel.installEventFilter(self)
            scroll.viewport().installEventFilter(self)
            self.rules_splitter.addWidget(scroll)
        for index in (0, 1):
            self.rules_splitter.setCollapsible(index, False)
            self.rules_splitter.setStretchFactor(index, 1)
        self.rules_splitter.setSizes([750, 550])
        self._rules_height_timer.start(0)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setSpacing(4)
        layout.addWidget(self.rules_splitter)
        layout.addLayout(search_row)
        layout.addWidget(minimap_section)
        layout.addWidget(self.splitter, 1)
        self.setCentralWidget(central)

        self.listener_label = QLabel()
        self.firewall_label = QLabel()
        self.firewall_label.setTextInteractionFlags(Qt.LinksAccessibleByMouse | Qt.LinksAccessibleByKeyboard)
        self.firewall_label.linkActivated.connect(self.show_firewall_details)
        self.counter_label = QLabel()
        self.storage_label = QLabel()
        self.mcp_label = QLabel()
        self.mcp_label.setTextInteractionFlags(Qt.LinksAccessibleByMouse | Qt.LinksAccessibleByKeyboard)
        self.mcp_label.linkActivated.connect(self.show_mcp_details)
        self.statusBar().addWidget(self.mode_label)
        for widget in (self.listener_label, self.firewall_label, self.mcp_label, self.counter_label,
                       self.storage_label):
            widget.setTextFormat(Qt.RichText)
            self.statusBar().addPermanentWidget(widget)
        self._show_mcp_state()
        self._update_mode_label()

    # ------------------------------------------------------------- time window
    def _range_duration(self) -> int | None:
        index = self.range_combo.currentIndex()
        return RANGE_PRESETS[index][1] if index < len(RANGE_PRESETS) else None

    def eventFilter(self, watched, event) -> bool:
        if watched is self.table.viewport():
            if event.type() == QEvent.Resize:
                self._visible_range_timer.start(0)
        elif event.type() in (QEvent.Resize, QEvent.LayoutRequest):
            self._rules_height_timer.start(0)
        return super().eventFilter(watched, event)

    def _update_rules_height(self) -> None:
        required_heights = []
        row_height = 0
        for scroll, panel in ((self.filters_scroll, self.filter_bar),
                              (self.highlights_scroll, self.highlights)):
            flow = panel._flow_layout
            width = max(1, scroll.viewport().width())
            required = flow.heightForWidth(width)
            row_height = max(row_height, max(
                (flow.itemAt(index).sizeHint().height() for index in range(flow.count())),
                default=0))
            if not panel._editors.isHidden():
                required += panel.layout().spacing() + panel._editors.sizeHint().height()
            panel.setMinimumHeight(required)
            required_heights.append(required)
        height = min(max(required_heights), 3 * row_height + 6)
        if self.rules_splitter.height() != height:
            self.rules_splitter.setFixedHeight(height)

    def custom_bounds(self) -> Bounds | None:
        """From/To bounds of the custom range; To includes the whole displayed second."""
        if self.range_combo.currentIndex() != CUSTOM_RANGE_INDEX:
            return None
        start = self.range_from.dateTime().toMSecsSinceEpoch() if self.range_from_check.isChecked() else None
        end = None
        if self.range_to_check.isChecked():
            end = (self.range_to.dateTime().toMSecsSinceEpoch() // 1000 + 1) * 1000
        return start, end

    def list_filter(self) -> EventFilter:
        base = self.filter_bar.current_filter()
        if self._zoom:
            return base.with_time(*self._zoom)
        return base.with_time(*_range_bounds(_now_ms(), self._range_duration(), self.custom_bounds()))

    def _histogram_job(self, buckets: int):
        base = self.filter_bar.current_filter()
        zoom, duration, custom = self._zoom, self._range_duration(), self.custom_bounds()
        highlight = self.highlights.active_rules()

        def job(runner: QueryRunner) -> Histogram:
            if zoom:
                start, end = zoom
            else:
                now_end = _now_ms() + 1
                limit_start, limit_end = _range_bounds(now_end, duration, custom)
                limit_end = now_end if limit_end is None else min(limit_end, now_end)
                bounds = runner.time_bounds(base.with_time(limit_start, limit_end))
                if bounds:
                    first, last = bounds
                    span = last - first
                    padding = max(1000, span // 20, (10_000 - span) // 2)
                    start = first - padding
                    end = min(limit_end, last + padding + 1)
                else:
                    end = limit_end
                    start = end - min(duration or MINUTE, MINUTE)
                if limit_start is not None:
                    start = max(start, limit_start)
                end = max(end, start + 1000)  # empty, future, or inverted From/To range
            return runner.histogram(base, start, end, buckets, highlight)
        return job

    # ---------------------------------------------------------------- loading
    def _on_query_error(self, message: str) -> None:
        self.statusBar().showMessage(f"Query error: {message}", 10000)
        if self.search_result.text() == "Searching…":
            self.search_result.setText(f"Search failed: {message}")

    @Slot()
    def refresh_all(self) -> None:
        """Discard all in-flight queries and reload list and minimap."""
        self.queries.new_generation()
        self._reset_search()
        self._reset_highlight_navigation()
        self._older_request = self._newer_request = self._live_request = self._hist_request = None
        f = self.list_filter()
        self.queries.submit(lambda r: r.fetch_older(f, None, PAGE_SIZE + 1), self._apply_head)
        self._request_histogram()

    def _apply_head(self, rows) -> None:
        self.model.reset_rows(rows[:PAGE_SIZE], has_older=len(rows) > PAGE_SIZE, has_newer=False)
        self.details.clear()
        self._scroll_to(0)

    def _request_histogram(self) -> None:
        job = self._histogram_job(self.minimap.preferred_buckets())
        highlight = self.highlights.active_rules()
        self._hist_request = self.queries.submit(
            job, lambda hist: self._apply_histogram(hist)
            if highlight == self.highlights.active_rules() else None)

    def _highlight_changed(self) -> None:
        self.model.set_highlight_rules(self.highlights.rules())
        self.highlights.invalidate_counts()
        self.highlight_label.setText("Updating…" if self.highlights.active_rules() else "Off")
        self.highlight_label.setToolTip("")
        self._highlight_timer.start()

    # ---------------------------------------------------------- highlight alerts
    @Slot()
    def _highlight_watch_tick(self) -> None:
        """Runs even while hidden in the tray: popups must not depend on the view."""
        self.highlight_alerts.flush()
        if self.queries.is_pending(self._watch_request):
            return
        after = self._watch_after_id
        if after is None:  # first tick: only rows received from now on are "new"
            self._watch_request = self.queries.submit(
                lambda r: r.max_id(), lambda last: self._apply_highlight_batch(HighlightBatch(last, 0, [])))
            return
        highlight = self.highlights.notification_text()
        self._watch_request = self.queries.submit(
            lambda r: r.new_highlights(after, highlight, MAX_LISTED), self._apply_highlight_batch)

    def _apply_highlight_batch(self, batch: HighlightBatch) -> None:
        self._watch_after_id = max(batch.last_id, self._watch_after_id or 0)
        if batch.count:
            self.highlight_alerts.add(batch)
            self.highlight_alerts.flush()

    def _show_highlight_alert(self, title: str, body: str) -> None:
        if self.tray:
            self.tray.show_highlight(title, body)
        else:
            self.statusBar().showMessage(f"{title} – {body.splitlines()[0]}", 15000)

    def _apply_histogram(self, hist: Histogram) -> None:
        self.minimap.set_histogram(hist)
        self.highlights.set_counts(hist)
        total_highlights = sum(hist.highlights)
        self.highlight_label.setText(
            f"{format_count(total_highlights)} matches"
            if self.highlights.active_rules() else "Off")
        self.highlight_label.setToolTip("\n".join(
            f"{rule.text}: {format_count(sum(bucket[i] for bucket in hist.highlight_counts))}"
            for i, rule in enumerate(hist.highlight_rules)))
        mode = "Zoom" if self._zoom else "automatic"
        start, end = format_ts(hist.start_ms)[:19], format_ts(hist.end_ms)[:19]
        if start[:10] == end[:10]:
            end = end[11:]
        self.minimap_range_label.setText(f"Minimap: {start} – {end} ({mode})")
        self.minimap_range_label.setToolTip(
            f"Minimap: {format_ts(hist.start_ms)} – {format_ts(hist.end_ms)}\n"
            + ("Zoom: exact selected range" if self._zoom
               else "Automatically fitted to the available data in the selected range"))
        parts = [f"Total <b>{format_count(hist.total)}</b>",
                 "<a href='all'>All</a>"]
        selected = self.filter_bar.selected_severities()
        for cls in SeverityClass:
            color = CLASS_COLORS[cls].name()
            active = selected != set(ALL_SEVERITIES) and any(
                severity_class(sev) == cls for sev in selected)
            weight = "bold" if active else "normal"
            parts.append(f"<a href='{int(cls)}' style='color:{color};font-weight:{weight}'>"
                         f"■ {SEVERITY_CLASS_LABELS[cls]} {format_count(hist.class_total(cls))}</a>")
        self.legend.setText(" &nbsp; ".join(parts))
        if self.highlights.active_rules():
            swatches = " ".join(
                f"<span style='color:{rule.color}'>■</span>" for rule in hist.highlight_rules)
            self.legend.setText(self.legend.text() +
                f" &nbsp; {swatches} "
                f"Highlight {format_count(total_highlights)}")

    def _filter_severity(self, link: str) -> None:
        if link == "all":
            self.filter_bar.set_severities(set(ALL_SEVERITIES))
            return
        cls = SeverityClass(int(link))
        group = {sev for sev in ALL_SEVERITIES if severity_class(sev) == cls}
        selected = self.filter_bar.selected_severities()
        if QApplication.keyboardModifiers() & Qt.ControlModifier:
            values = selected - group if group <= selected else selected | group
        else:
            values = set(ALL_SEVERITIES) if selected == group else group
        self.filter_bar.set_severities(values)

    @Slot()
    def _histogram_tick(self) -> None:
        if self._zoom is None and not self.queries.is_pending(self._hist_request) and self.isVisible():
            self._request_histogram()

    @Slot()
    def _live_tick(self) -> None:
        if not self._live or self.queries.is_pending(self._live_request) or not self.isVisible():
            return
        cursor = self.model.top_cursor
        if cursor is None:
            self.refresh_all()
            return
        f = self.list_filter()
        self._live_request = self.queries.submit(
            lambda r: r.fetch_newer(f, cursor, LIVE_FETCH_LIMIT), self._apply_live)

    def _apply_live(self, rows) -> None:
        if not self._live:
            return
        if len(rows) >= LIVE_FETCH_LIMIT:
            self.refresh_all()  # too far behind: start again from the newest rows
            return
        self.model.prepend(rows)

    def _on_scroll(self, value: int) -> None:
        if self._adjusting_scroll:
            return
        self._update_marker()
        bar = self.table.verticalScrollBar()
        if self._live and value > 0:
            self.live_action.setChecked(False)  # user scrolled away: pause the live view
        if (value >= bar.maximum() - SCROLL_PREFETCH_ROWS and self.model.has_older
                and not self.queries.is_pending(self._older_request)):
            self._request_older()
        if (value <= SCROLL_PREFETCH_ROWS // 5 and self.model.has_newer and not self._live
                and not self.queries.is_pending(self._newer_request)):
            self._request_newer()

    def _request_older(self) -> None:
        cursor, f = self.model.bottom_cursor, self.list_filter()
        if cursor is None:
            return
        self._older_request = self.queries.submit(
            lambda r: r.fetch_older(f, cursor, PAGE_SIZE + 1), self._apply_older)

    def _apply_older(self, rows) -> None:
        removed = self.model.append(rows[:PAGE_SIZE])
        self.model.has_older = len(rows) > PAGE_SIZE
        if removed:
            self._scroll_to(self.table.verticalScrollBar().value() - removed)

    def _request_newer(self) -> None:
        cursor, f = self.model.top_cursor, self.list_filter()
        if cursor is None:
            return
        self._newer_request = self.queries.submit(
            lambda r: r.fetch_newer(f, cursor, PAGE_SIZE + 1), self._apply_newer)

    def _apply_newer(self, rows) -> None:
        has_more = len(rows) > PAGE_SIZE
        inserted = self.model.prepend(rows[-PAGE_SIZE:])  # the rows closest to the cursor
        self.model.has_newer = has_more
        self._scroll_to(self.table.verticalScrollBar().value() + inserted)

    def _scroll_to(self, value: int) -> None:
        self._adjusting_scroll = True
        try:
            self.table.verticalScrollBar().setValue(max(0, value))
        finally:
            self._adjusting_scroll = False
        self._update_marker()

    def _update_marker(self) -> None:
        top = self.model.row_at(self.table.rowAt(0))
        bottom_index = self.table.rowAt(self.table.viewport().height() - 1)
        bottom = self.model.row_at(bottom_index if bottom_index >= 0 else self.model.rowCount() - 1)
        self.minimap.set_visible_range(bottom.received_at if top and bottom else None,
                                      top.received_at if top else None)
        self._update_selection_marker()

    # ------------------------------------------------------------ navigation
    def _reset_search(self) -> None:
        self._search_revision += 1
        self._search_cursor = None
        self.search_result.clear()
        enabled = bool(self.search_text.text().strip())
        self.search_next.setEnabled(enabled)
        self.search_previous.setEnabled(enabled)

    def _reset_highlight_navigation(self, *_args) -> None:
        self._highlight_revision += 1
        self._highlight_cursor = None

    def find_highlight(self, text: str, newer: bool = False) -> None:
        if not text.strip():
            return
        self.set_live(False)
        self.queries.new_generation()
        self._older_request = self._newer_request = self._live_request = None
        self._highlight_revision += 1
        revision = self._highlight_revision
        cursor = self._highlight_cursor
        f = self.list_filter()
        self.search_result.setText("Searching highlight matches…")

        def job(runner: QueryRunner):
            hit = runner.find_highlight_match(f, text, cursor, newer=bool(cursor and newer))
            context = None if hit is None else runner.fetch_context(
                f, hit.cursor, PAGE_SIZE + 1, PAGE_SIZE // 2 + 1)
            return hit, context

        def apply(result) -> None:
            if revision != self._highlight_revision:
                return
            hit, context = result
            if hit is None:
                self.search_result.setText("No more highlight matches" if cursor else "No highlight matches")
                return
            self._highlight_cursor = hit.cursor
            self._apply_jump(context, PAGE_SIZE, PAGE_SIZE // 2)
            self.search_result.setText("Highlight match selected")

        self.queries.submit(job, apply)
        self._request_histogram()

    def find_text(self, *, newer: bool = False) -> None:
        text = self.search_text.text().strip()
        if not text:
            return
        self.set_live(False)
        self.queries.new_generation()
        self._older_request = self._newer_request = self._live_request = None
        revision = self._search_revision
        f, mode, cursor = self.list_filter(), self.search_mode.currentData(), self._search_cursor
        self.search_result.setText("Searching…")

        def job(runner: QueryRunner):
            hit = runner.find_match(f, text, mode, cursor, newer=newer if cursor else False)
            context = None if hit is None else runner.fetch_context(
                f, hit.cursor, PAGE_SIZE + 1, PAGE_SIZE // 2 + 1)
            return hit, context

        def apply(result) -> None:
            if revision != self._search_revision:
                return
            hit, context = result
            if hit is None:
                self.search_result.setText("No more matches" if cursor else "No matches")
                return
            self._search_cursor = hit.cursor
            self._apply_jump(context, PAGE_SIZE, PAGE_SIZE // 2)
            self.search_result.setText("Match selected")

        self.queries.submit(job, apply)
        self._request_histogram()

    @Slot(bool)
    def set_live(self, live: bool) -> None:
        if live == self._live:
            return
        self._live = live
        self.live_action.setChecked(live)
        if live:
            self._zoom = None
            self.reset_zoom_action.setEnabled(False)
            self.refresh_all()
        else:
            self._persisted_at_pause = self.service.snapshot().persisted
        self._update_mode_label()

    @Slot("qlonglong")
    def jump_to_time(self, time_ms: int) -> None:
        self.set_live(False)
        self.queries.new_generation()
        self._reset_search()
        self._older_request = self._newer_request = self._live_request = None
        f, before, after = self.list_filter(), PAGE_SIZE, PAGE_SIZE // 2
        self.queries.submit(lambda r: r.fetch_around(f, time_ms, before + 1, after + 1),
                            lambda result: self._apply_jump(result, before, after))
        self._request_histogram()

    def _apply_jump(self, result, before: int, after: int) -> None:
        newer, older = result
        rows = newer[-after:] + older[:before]
        self._adjusting_scroll = True
        try:
            self.model.reset_rows(rows, has_older=len(older) > before, has_newer=len(newer) > after)
            anchor = min(len(newer[-after:]), max(len(rows) - 1, 0))
            if rows:
                self.table.selectRow(anchor)
                self.table.scrollTo(self.model.index(anchor, 0), QAbstractItemView.PositionAtCenter)
        finally:
            self._adjusting_scroll = False
        self._update_marker()

    @Slot("qlonglong", "qlonglong")
    def zoom_to(self, start_ms: int, end_ms: int) -> None:
        if end_ms <= start_ms:
            return
        self.set_live(False)
        self._zoom = (start_ms, end_ms)
        self.reset_zoom_action.setEnabled(True)
        self._update_mode_label()
        self.refresh_all()

    @Slot()
    def reset_zoom(self) -> None:
        self._zoom = None
        self.reset_zoom_action.setEnabled(False)
        self._update_mode_label()
        self.refresh_all()

    def _range_index_changed(self, index: int) -> None:
        if index == CUSTOM_RANGE_INDEX and self._range_index != CUSTOM_RANGE_INDEX:
            # continue from what was visible: preset start as Von, Bis open
            now = _now_ms()
            duration = RANGE_PRESETS[self._range_index][1]
            self._set_custom(None if duration is None else now - duration, None)
        self._range_changed()

    def _range_changed(self) -> None:
        self._custom_timer.stop()
        self._range_index = self.range_combo.currentIndex()
        self.custom_range.setVisible(self._range_index == CUSTOM_RANGE_INDEX)
        self._zoom = None
        self.reset_zoom_action.setEnabled(False)
        self._update_mode_label()
        self.refresh_all()

    def _set_custom(self, start_ms: int | None, end_ms: int | None) -> None:
        now = QDateTime.fromMSecsSinceEpoch(_now_ms())
        for check, edit, value in ((self.range_from_check, self.range_from, start_ms),
                                   (self.range_to_check, self.range_to, end_ms)):
            for widget in (check, edit):
                widget.blockSignals(True)
            check.setChecked(value is not None)
            edit.setDateTime(now if value is None else QDateTime.fromMSecsSinceEpoch(value))
            edit.setEnabled(value is not None)
            for widget in (check, edit):
                widget.blockSignals(False)

    def _custom_edited(self) -> None:
        self.range_from.setEnabled(self.range_from_check.isChecked())
        self.range_to.setEnabled(self.range_to_check.isChecked())
        if (self.range_from_check.isChecked() and self.range_to_check.isChecked()
                and self.range_to.dateTime() < self.range_from.dateTime()):
            sender = self.sender()
            moved, anchor = ((self.range_from, self.range_to) if sender is self.range_to
                             else (self.range_to, self.range_from))
            moved.blockSignals(True)
            moved.setDateTime(anchor.dateTime())
            moved.blockSignals(False)
        self._custom_timer.start()

    @Slot()
    def clear_view(self) -> None:
        """Show only rows received from now on; storage is untouched."""
        self._set_custom(_now_ms(), None)
        self.range_combo.blockSignals(True)
        self.range_combo.setCurrentIndex(CUSTOM_RANGE_INDEX)
        self.range_combo.blockSignals(False)
        self.model.reset_rows([], has_older=False, has_newer=False)
        self.details.clear()
        if not self._live:
            self._live = True  # avoid a second reload from set_live
            self.live_action.setChecked(True)
        self._range_changed()

    def _update_mode_label(self) -> None:
        if self._live:
            text = "&nbsp;<b style='color:#1a7f37'>● LIVE</b>"
            tip = "The newest messages appear at the top."
        else:
            text = "&nbsp;<b style='color:#9a6700'>⏸ PAUSED</b>"
            tip = "View paused; receiving and storage continue.\nSelect “Live” to show the newest messages again."
        if self._zoom:
            text += f" · Zoom {format_ts(self._zoom[0])[11:19]} – {format_ts(self._zoom[1])[11:19]}"
            tip += f"\nZoom: {format_ts(self._zoom[0])[:19]} – {format_ts(self._zoom[1])[:19]}"
        custom = self.custom_bounds()
        if custom and custom[0] is not None and custom[1] is None:
            text += f" · from {format_ts(custom[0])[11:19]}"
            tip += (f"\nRange from {format_ts(custom[0])[:19]}; older messages are "
                    "hidden but still stored.")
        self.mode_label.setText(text)
        self.mode_label.setToolTip(tip)

    # ---------------------------------------------------------------- details
    def _selection_changed(self) -> None:
        selected = self.table.selectionModel().selectedRows()
        self.copy_action.setEnabled(bool(selected))
        self._update_selection_marker()
        if len(selected) > 1:
            self.set_live(False)

    def _update_selection_marker(self) -> None:
        times = []
        for index in self.table.selectionModel().selectedRows():
            row = self.model.row_at(index.row())
            if row is not None:
                times.append(row.received_at)
        self.minimap.set_selected_times(tuple(times))

    def copy_selected_rows(self) -> None:
        rows = [index.row() for index in self.table.selectionModel().selectedRows()]
        if not rows:
            return
        QApplication.clipboard().setText(self.model.copy_text(rows))
        self.statusBar().showMessage(f"Copied {len(rows)} rows", 5000)

    def _on_current_row(self, current, _previous) -> None:
        row = self.model.row_at(current.row())
        if row is None:
            self.details.clear()
            return
        event_id = row.id
        self.queries.submit(lambda r: r.get_event(event_id), self._show_details)

    def _show_details(self, event) -> None:
        if event is None:
            self.details.setPlainText("Message no longer exists (deleted by retention).")
        else:
            self.details.setPlainText(format_event_details(event))

    # ----------------------------------------------------------------- status
    @Slot()
    def _update_status(self) -> None:
        snap = self.service.snapshot()
        rates = self._rate_tracker.update(snap)
        self._show_listener_state(snap)
        self._show_mcp_state()
        self.counter_label.setText(
            f"Received {format_count(snap.received)} · stored {format_count(snap.persisted)} · "
            f"queued {format_count(snap.queued)}<br>"
            f"<span style='color:#555'>Live: {rates.received:.1f}/s received · "
            f"{rates.persisted:.1f}/s stored · {rates.dropped:.1f}/s dropped</span>")
        losses = snap.dropped_queue_full + snap.dropped_write_error + snap.dropped_tcp_framing
        if losses:
            self.counter_label.setText(self.counter_label.text() +
                                       f" · <b style='color:#b00020'>dropped {format_count(losses)}</b>")
        if snap.tcp_connections_rejected:
            self.counter_label.setText(
                self.counter_label.text() +
                f" · <b style='color:#b00020'>TCP connections rejected "
                f"{format_count(snap.tcp_connections_rejected)}</b>")
        if snap.tls_handshake_failures:
            self.counter_label.setText(
                self.counter_label.text() +
                f" · <b style='color:#9a6700'>TLS handshakes failed "
                f"{format_count(snap.tls_handshake_failures)}</b>")
        storage = f"DB {format_bytes(snap.storage_bytes)} / {format_bytes(self.service.settings.max_storage_bytes)}"
        if snap.writer_error:
            storage = f"<b style='color:#b00020'>{snap.writer_error}</b> · {storage}"
        elif snap.storage_budget_exceeded:
            storage = f"<b style='color:#9a6700'>Budget exceeded</b> · {storage}"
        self.storage_label.setText(storage)
        if not self._live:
            new = snap.persisted - self._persisted_at_pause
            self.statusBar().showMessage(f"Paused — {format_count(new)} new messages stored since pausing")
        else:
            self.statusBar().clearMessage()
        if self.tray:
            self.tray.update_status(snap)

    def _show_listener_state(self, snap: StatsSnapshot) -> None:
        listening = self.service.listening
        self.listen_action.setChecked(listening)
        self.listen_action.setText("■ Stop receiving" if listening else "▶ Start receiving")
        if snap.listener_state == "error":
            text = f"<b style='color:#b00020'>{snap.listener_error}</b>"
            if listening:
                text += f" · Still receiving on {snap.listener_display_address}"
        elif listening:
            text = f"<span style='color:#1a7f37'>{snap.listener_display_address} active</span>"
        else:
            text = "<span style='color:#666'>Receiving stopped</span>"
        self.listener_label.setText(text)

    def _toggle_listener(self, checked: bool) -> None:
        if checked:
            if not self.service.start_listener():
                QMessageBox.warning(self, "Receiving", self.service.snapshot().listener_error +
                                    "\n\nChange the port in Settings or stop the process using it.")
        else:
            self.service.stop_listener()
        self._update_status()
        self.check_firewall()

    # --------------------------------------------------------------- firewall
    @Slot()
    def check_firewall(self) -> None:
        settings = self.service.settings
        self.firewall.request(settings.bind_host, settings.listener_endpoints)

    @Slot(object)
    def _apply_firewall(self, check: FirewallCheck) -> None:
        self._firewall_check = check
        text, color = {
            Level.OK: ("Firewall ✓", "#1a7f37"),
            Level.WARNING: ("⚠ Firewall: port not allowed", "#9a6700"),
            Level.ERROR: ("✖ Firewall blocked", "#b00020"),
            Level.UNKNOWN: ("Firewall ?", "#666"),
        }[check.level]
        weight = "bold" if check.level >= Level.WARNING else "normal"
        self.firewall_label.setText(
            f"<a href='firewall' style='color:{color};font-weight:{weight};text-decoration:none'>{text}</a>")
        self.firewall_label.setToolTip("\n".join((check.summary, *check.details, "Click for details")))
        if check.level >= Level.WARNING and check.level > self._firewall_warned_level:
            log.warning("Firewall: %s – %s", check.summary, "; ".join(check.details))
            if self.tray:
                self.tray.show_warning(f"{APP_DISPLAY_NAME} – Firewall", check.summary)
        if check.level != Level.UNKNOWN:
            self._firewall_warned_level = check.level

    @Slot()
    def show_firewall_details(self, _link: str = "") -> None:
        check = self._firewall_check
        if check is None:
            return
        box = QMessageBox(self)
        box.setWindowTitle("Firewall check")
        box.setIcon({Level.OK: QMessageBox.Information, Level.WARNING: QMessageBox.Warning,
                     Level.ERROR: QMessageBox.Critical}.get(check.level, QMessageBox.Question))
        box.setText(check.summary)
        lines, command = remedy(check, self.service.settings.port, current_programs()[0])
        hints = [*check.details, *([""] if lines else []), *lines,
                 "", "Reading requires no administrator rights; nothing is changed."]
        box.setInformativeText("\n".join(hints))
        box.setTextInteractionFlags(Qt.TextSelectableByMouse)
        copy_button = box.addButton("Copy command", QMessageBox.ActionRole) if command else None
        recheck_button = box.addButton("Check again", QMessageBox.ActionRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if copy_button is not None and box.clickedButton() is copy_button:
            QApplication.clipboard().setText(command)
        elif box.clickedButton() is recheck_button:
            self.check_firewall()

    # -------------------------------------------------------------------- MCP
    def _show_mcp_state(self) -> None:
        mcp = self.mcp
        self.mcp_label.setVisible(mcp is not None)
        if mcp is None or not mcp.enabled:
            text, color, tip = "MCP off", "#666", "MCP server for AI assistants is disabled."
        elif mcp.running:
            text, color = f"MCP ✓ :{mcp.port}", "#1a7f37"
            tip = f"MCP server (local only, read-only, no authentication): {mcp.url}"
        elif mcp.starting:
            text, color, tip = "MCP …", "#666", "MCP server is starting"
        else:
            text, color, tip = "✖ MCP", "#b00020", mcp.error
        html = f"<a href='mcp' style='color:{color};text-decoration:none'>{text}</a>"
        if html != self.mcp_label.text():
            self.mcp_label.setText(html)
            self.mcp_label.setToolTip(f"{tip}\nClick for details")

    @Slot()
    def show_mcp_details(self, _link: str = "") -> None:
        mcp = self.mcp
        if mcp is None:
            return
        port = mcp.port or self.service.settings.mcp_port
        snippet = json.dumps(client_config(port), indent=2)
        box = QMessageBox(self)
        box.setWindowTitle("MCP server")
        box.setIcon(QMessageBox.Information if mcp.running or not mcp.enabled else QMessageBox.Warning)
        if mcp.running:
            box.setText(f"MCP server is running: {mcp.url}")
        elif mcp.enabled:
            box.setText(f"MCP server is not running: {mcp.error}")
        else:
            box.setText("MCP server is disabled (Settings).")
        box.setInformativeText(
            "AI assistants (e.g. GitHub Copilot in VS Code) can read stored syslog messages, "
            "for example “show all messages since the last reboot.”\n\n"
            "Only accessible locally (127.0.0.1), read-only, and unauthenticated: other local "
            "programs can also retrieve messages. Depending on the AI integration, queried "
            "messages may be sent to an external provider.\n\n"
            "VS Code: run “MCP: Open User Configuration” and add:\n\n" + snippet)
        box.setTextInteractionFlags(Qt.TextSelectableByMouse)
        copy_button = box.addButton("Copy configuration", QMessageBox.ActionRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if box.clickedButton() is copy_button:
            QApplication.clipboard().setText(snippet)

    # --------------------------------------------------------------- settings
    @Slot()
    def open_settings(self) -> None:
        dialog = SettingsDialog(self.service.settings, self)
        if not dialog.exec():
            return
        new: Settings = dialog.result_settings()
        old = self.service.settings
        try:
            save_settings(self._settings_path, new)
        except OSError as exc:
            QMessageBox.critical(self, "Settings", f"Could not save settings: {exc}")
            return
        if not self.service.apply_settings(new):
            QMessageBox.warning(self, "Receiving", self.service.snapshot().listener_error)
        if self.mcp is not None and not self.mcp.apply(new):
            QMessageBox.warning(self, "MCP server", self.mcp.error)
        self._show_mcp_state()
        if new.data_dir != old.data_dir:
            QMessageBox.information(self, "Data directory",
                                    "The new data directory will be used after restarting the application.")
        self._update_status()
        self.check_firewall()

    # -------------------------------------------------------------- lifecycle
    def show_and_raise(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()
        self.refresh_all()

    @Slot()
    def quit_application(self) -> None:
        self._quitting = True
        self.close()
        QApplication.quit()

    def closeEvent(self, event: QCloseEvent) -> None:
        self._save_ui_state()
        if self.tray and not self._quitting:
            event.ignore()
            self.hide()
            self.tray.notify_hidden_once()
            return
        event.accept()

    def shutdown(self) -> None:
        """Stop timers and the query thread; the capture service is closed by the caller."""
        for timer in self._timers:
            timer.stop()
        self._highlight_timer.stop()
        self._visible_range_timer.stop()
        self.queries.shutdown()
        if self.tray:
            self.tray.hide()

    def _save_ui_state(self) -> None:
        s = self._ui_state
        s.setValue("geometry", self.saveGeometry())
        s.setValue("window_state", self.saveState())
        s.setValue("splitter", self.splitter.saveState())
        s.setValue("rules_splitter", self.rules_splitter.saveState())
        s.setValue("columns", self.table.horizontalHeader().saveState())
        s.setValue("range_index", self.range_combo.currentIndex())
        custom = self.custom_bounds() or (None, None)
        s.setValue("range_from", "" if custom[0] is None else str(custom[0]))
        s.setValue("range_to", "" if custom[1] is None else str(custom[1] - 1))
        s.setValue("filters", json.dumps(self.filter_bar.state()))
        s.setValue("highlight_rules", json.dumps(self.highlights.state()))
        s.sync()

    def _restore_ui_state(self) -> None:
        s = self._ui_state
        stored_rules = s.value("highlight_rules")
        legacy_popup = str(s.value("highlight_popup", True)).lower() not in ("false", "0")
        try:
            if stored_rules is None:
                # Existing installations retain their texts and purple colour.
                legacy = str(s.value("highlight_text", DEFAULT_HIGHLIGHT))
                self.highlights.restore_state([
                    {"text": legacy, "color": HighlightRule().color, "enabled": True,
                     "popup": legacy_popup}])
            else:
                rules = json.loads(stored_rules)
                if isinstance(rules, list):
                    for rule in rules:
                        if isinstance(rule, dict):
                            rule.setdefault("popup", legacy_popup)
                self.highlights.restore_state(rules)
        except (TypeError, ValueError):
            log.warning("Could not read stored highlights; using defaults")
            self.statusBar().showMessage("Could not read stored highlights — using defaults", 10000)
            self.highlights.restore_state([{"text": DEFAULT_HIGHLIGHT,
                                           "color": HighlightRule().color, "enabled": True,
                                           "popup": legacy_popup}])
        self.model.set_highlight_rules(self.highlights.rules())
        for key, restore in (("geometry", self.restoreGeometry), ("window_state", self.restoreState),
                             ("splitter", self.splitter.restoreState),
                             ("rules_splitter", self.rules_splitter.restoreState),
                             ("columns", self.table.horizontalHeader().restoreState)):
            value = s.value(key)
            if value is not None:
                restore(value)
        index = int(s.value("range_index", DEFAULT_RANGE_INDEX))
        if 0 <= index <= CUSTOM_RANGE_INDEX:
            if index == CUSTOM_RANGE_INDEX:
                stored = [str(s.value(key, "")) for key in ("range_from", "range_to")]
                self._set_custom(*(int(v) if v.lstrip("-").isdigit() else None for v in stored))
            self.range_combo.blockSignals(True)
            self.range_combo.setCurrentIndex(index)
            self.range_combo.blockSignals(False)
            self._range_index = index
            self.custom_range.setVisible(index == CUSTOM_RANGE_INDEX)
            self._update_mode_label()
        try:
            self.filter_bar.restore_state(json.loads(s.value("filters", "{}")))
        except (TypeError, ValueError):
            log.warning("Could not read stored filters; using defaults")
