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
    QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QSplitter, QTableView,
    QMenu, QStackedWidget, QToolButton, QVBoxLayout, QWidget,
)

from syslog_monitor import APP_DISPLAY_NAME
from syslog_monitor.config import Settings, save_settings
from syslog_monitor.events import SEVERITY_CLASS_LABELS, SeverityClass, severity_class
from syslog_monitor.firewall import FirewallCheck, Level, check_firewalls, current_programs, remedy
from syslog_monitor.i18n import language, tr
from syslog_monitor.mcp_server import McpService, client_config
from syslog_monitor.query import (
    DEFAULT_HIGHLIGHT, TEXT_MODE_SUBSTRING, TEXT_MODE_WORDS, Cursor, EventFilter, HighlightBatch, Histogram,
    EventRow, HighlightRule, QueryRunner,
)
from syslog_monitor.service import CaptureService
from syslog_monitor.stats import RateTracker, StatsSnapshot
from syslog_monitor.ui.event_model import EventTableModel
from syslog_monitor.ui.about_dialog import AboutDialog
from syslog_monitor.ui.diagnostics_dialog import DiagnosticsDialog
from syslog_monitor.ui.export_dialog import ExportDialog
from syslog_monitor.ui.filter_bar import ALL_SEVERITIES, FilterBar
from syslog_monitor.ui.firewall_status import Checker, FirewallMonitor
from syslog_monitor.ui.formatting import format_bytes, format_count, format_event_details, format_ts
from syslog_monitor.ui.highlight_alerts import MAX_LISTED, MIN_INTERVAL_S, HighlightAlerter
from syslog_monitor.ui.highlight_panel import HighlightPanel
from syslog_monitor.ui.icons import app_icon
from syslog_monitor.ui.minimap import CLASS_COLORS, MinimapWidget
from syslog_monitor.ui.message_inspector import MessageInspector
from syslog_monitor.ui.navigation import NavigationRail
from syslog_monitor.ui.palette import apply_theme, is_dark, status_color
from syslog_monitor.ui.query_worker import QueryClient
from syslog_monitor.ui.settings_dialog import SettingsDialog
from syslog_monitor.ui.tray import TrayController
from syslog_monitor.ui.zoom import MAX_ZOOM, MIN_ZOOM, ZoomController

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
        apply_theme(service.settings.theme)
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
        self._export_dialog: ExportDialog | None = None
        self._diagnostics_dialog: DiagnosticsDialog | None = None
        self._settings_page: SettingsDialog | None = None
        self._pages: dict[str, QWidget] = {}
        self.current_page = "logs"
        app = QApplication.instance()
        if not isinstance(app, QApplication):
            raise RuntimeError("A QApplication is required to create the main window.")
        self.zoom_controller = ZoomController(app, self)
        self.zoom_controller.zoom_changed.connect(self._zoom_changed)

        self.setWindowTitle(APP_DISPLAY_NAME)
        self.setWindowIcon(app_icon())
        self.queries = QueryClient(service.db_path, self)
        self.queries.error.connect(self._on_query_error)
        self.statistics_queries = QueryClient(service.db_path, self)
        self.statistics_queries.error.connect(self._on_statistics_error)
        self._selected_stats_row: EventRow | None = None
        self._statistics_timer = QTimer(self, singleShot=True, interval=100)
        self._statistics_timer.timeout.connect(self._request_message_statistics)

        self._build_ui()
        self._install_zoom_shortcuts()
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
        self.listen_action = QAction(tr("Receive"), self, checkable=True)
        self.listen_action.setToolTip(tr("Start/stop the enabled UDP, TCP and TLS listeners"))
        self.listen_action.triggered.connect(self._toggle_listener)
        self.live_action = QAction(tr("Autoscroll to newest"), self, checkable=True, checked=True)
        self.live_action.setToolTip(tr("Follow new messages. Scrolling into history turns autoscroll off.\n"
                                      "Receiving and storage continue when autoscroll is off."))
        self.live_action.toggled.connect(self.set_live)
        self.range_combo = QComboBox()
        for label, _ in RANGE_PRESETS:
            self.range_combo.addItem(tr(label))
        self.range_combo.addItem(tr("From / To…"))
        self.range_combo.setCurrentIndex(DEFAULT_RANGE_INDEX)
        self.range_combo.currentIndexChanged.connect(self._range_index_changed)
        self.range_from_check = QCheckBox(tr("From"))
        self.range_to_check = QCheckBox(tr("To"))
        self.range_from = QDateTimeEdit(calendarPopup=True, displayFormat=DATETIME_FORMAT)
        self.range_to = QDateTimeEdit(calendarPopup=True, displayFormat=DATETIME_FORMAT)
        self.range_from_check.setToolTip(tr("Optional start time (inclusive). Unchecked: from the oldest message."))
        self.range_to_check.setToolTip(tr("Optional end time (includes the displayed second).\n"
                                          "Unchecked: until now; new messages appear live."))
        self._custom_timer = QTimer(self, singleShot=True, interval=400)  # wait until typing pauses
        self._custom_timer.timeout.connect(self._range_changed)
        for widget in (self.range_from_check, self.range_to_check):
            widget.toggled.connect(self._custom_edited)
        for widget in (self.range_from, self.range_to):
            widget.dateTimeChanged.connect(self._custom_edited)
        self.reset_zoom_action = QAction(tr("Reset zoom"), self, enabled=False)
        self.reset_zoom_action.triggered.connect(self.reset_zoom)
        self.clear_view_action = QAction(tr("🧹 Clear view"), self, shortcut=QKeySequence("Ctrl+L"))
        self.clear_view_action.setToolTip(
            tr("Show only messages from now on (Ctrl+L) by setting “From” to the current time.\n"
               "Nothing is deleted. Choose another range or uncheck “From” to show older messages again."))
        self.clear_view_action.triggered.connect(self.clear_view)
        self.settings_action = QAction(tr("Settings"), self)
        self.settings_action.triggered.connect(self.open_settings)
        self.about_action = QAction(tr("About"), self)
        self.about_action.triggered.connect(self.show_about)
        self.diagnostics_action = QAction(tr("Client validation"), self)
        self.diagnostics_action.triggered.connect(self.open_diagnostics)
        self.export_action = QAction(tr("Export"), self)
        self.export_action.triggered.connect(self.open_export)
        quit_action = QAction(tr("Quit"), self, shortcut=QKeySequence.Quit)
        quit_action.setToolTip(tr("Choose minimize or quit (Ctrl+Q)"))
        quit_action.triggered.connect(lambda: self.show_page("quit"))
        self.latest_action = QAction(tr("Go to latest"), self, shortcut=QKeySequence.Refresh)
        self.latest_action.setToolTip(tr("Jump to the newest matching messages once (F5). Autoscroll stays unchanged."))
        self.latest_action.triggered.connect(self.go_to_latest)
        self.addActions([quit_action, self.latest_action, self.clear_view_action])
        self.mode_label = QLabel()
        self.mode_label.setTextFormat(Qt.RichText)

        self.filter_bar = FilterBar()
        self.filter_bar.changed.connect(self.refresh_all)
        self.search_text = QLineEdit(placeholderText=tr("Find matches while keeping context…"),
                                     clearButtonEnabled=True)
        self.search_text.setToolTip(
            tr("Navigate matches within the active filters without hiding other messages.\n"
               "Ctrl+F: focus this field. Enter/F3: next (older) match; "
               "Shift+F3: previous (newer) match."))
        self.search_mode = QComboBox()
        self.search_mode.addItem(tr("Words"), TEXT_MODE_WORDS)
        self.search_mode.addItem(tr("Substring"), TEXT_MODE_SUBSTRING)
        self.search_previous = QPushButton(tr("▲ Newer"))
        self.search_previous.setToolTip(tr("Previous (newer) match – Shift+F3"))
        self.search_next = QPushButton(tr("▼ Older"))
        self.search_next.setToolTip(tr("Next (older) match – Enter/F3"))
        self.search_result = QLabel()
        self.search_result.setTextFormat(Qt.PlainText)
        self.search_previous.clicked.connect(lambda: self.find_text(newer=True))
        self.search_next.clicked.connect(self.find_text)
        self.search_text.returnPressed.connect(self.find_text)
        self.search_text.textChanged.connect(self._reset_search)
        self.search_mode.currentIndexChanged.connect(self._reset_search)
        self._reset_search()
        search_row = QHBoxLayout()
        for widget in (QLabel(tr("Search:")), self.search_text, self.search_mode,
                       self.search_previous, self.search_next, self.search_result):
            search_row.addWidget(widget)
        search_row.setStretch(1, 3)
        focus_search = QAction(self, shortcut=QKeySequence.Find)
        focus_search.triggered.connect(self.focus_search)
        self.addAction(focus_search)
        for shortcut, newer in (("F3", False), ("Shift+F3", True)):
            action = QAction(self, shortcut=QKeySequence(shortcut))
            action.triggered.connect(lambda _checked=False, n=newer: self.find_text(newer=n))
            self.addAction(action)

        self.minimap = MinimapWidget()
        self.minimap.time_clicked.connect(self.jump_to_time)
        self.minimap.range_selected.connect(self.zoom_to)
        self.minimap_range_label = QLabel()
        # may be clipped on narrow windows; start/end are also on the minimap axis
        self.minimap_range_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        minimap_section = QGroupBox()
        minimap_layout = QVBoxLayout(minimap_section)
        minimap_layout.setContentsMargins(6, 4, 6, 4)
        minimap_layout.setSpacing(2)
        time_controls = QHBoxLayout()
        range_label = QLabel(tr("Time range:"))
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
            tr("Click: show only this severity group; click again: show all.\n"
               "Ctrl+click: add/remove groups. All: reset the severity filter.\n"
               "Counts apply to the active filters."))
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
            "QTableView { gridline-color: palette(mid); }"
            "QTableView::item:selected { background-color: #505050; color: #ffffff; "
            "border-top: 1px solid #303030; border-bottom: 1px solid #303030; }"
        )
        self.table.setToolTip(tr("Ctrl/Shift: select multiple rows. Ctrl+C: copy selection."))
        self.copy_action = QAction(tr("Copy selected rows"), self.table,
                                   shortcut=QKeySequence.Copy, enabled=False)
        self.copy_action.setShortcutContext(Qt.WidgetWithChildrenShortcut)
        self.copy_action.triggered.connect(self.copy_selected_rows)
        self.select_all_action = QAction(tr("Select all loaded rows"), self.table,
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
        header.setContextMenuPolicy(Qt.CustomContextMenu)
        self.column_menu = QMenu(self.table)
        self.column_menu.aboutToShow.connect(self._populate_column_menu)
        header.customContextMenuRequested.connect(self._show_column_menu)
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
        self.model.modelReset.connect(self._clear_selected_message)

        self.inspector = MessageInspector()
        self.inspector.regex_changed.connect(self._set_statistics_regex)
        self._custom_regex: tuple[int, str] | None = None  # (row id, regex)
        self.details = self.inspector.details
        self.statistics = self.inspector.statistics
        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.table)
        self.splitter.addWidget(self.inspector)
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([600, 240])
        self.inspector_action = QAction(tr("Message inspector"), self, checkable=True, checked=True)
        self.inspector_action.toggled.connect(self.inspector.setVisible)
        search_row.addWidget(self._inspector_button())

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
        self.log_page = central
        self.pages = QStackedWidget()
        self.pages.addWidget(central)
        self._pages["logs"] = central
        self.sidebar = NavigationRail()
        self.logs_action = QAction(tr("Logs"), self)
        self.logs_action.triggered.connect(lambda: self.show_page("logs"))
        for name, action in (
            ("logs", self.logs_action),
            ("export", self.export_action),
            ("validation", self.diagnostics_action),
        ):
            self.sidebar.add_item(name, action)
        self.sidebar.add_stretch()
        self.sidebar.add_item("latest", self.latest_action, page=False)
        self.sidebar.add_item("autoscroll", self.live_action, page=False)
        self.sidebar.add_stretch()
        self.sidebar.add_item("receive", self.listen_action, page=False)
        self.sidebar.add_item("settings", self.settings_action)
        self.sidebar.add_item("about", self.about_action)
        self.sidebar.add_item("quit", quit_action)
        self.logs_action.setChecked(True)
        self.sidebar.expanded_changed.connect(
            lambda value: self._ui_state.setValue("sidebar_expanded", value))
        shell = QWidget()
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        shell_layout.addWidget(self.sidebar)
        shell_layout.addWidget(self.pages, 1)
        self.setCentralWidget(shell)

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

    def _install_zoom_shortcuts(self) -> None:
        self.zoom_in_action = QAction(tr("Zoom in"), self, shortcut=QKeySequence.ZoomIn)
        self.zoom_out_action = QAction(tr("Zoom out"), self, shortcut=QKeySequence.ZoomOut)
        self.zoom_reset_action = QAction(tr("Reset zoom"), self, shortcut=QKeySequence("Ctrl+0"))
        for action in (self.zoom_in_action, self.zoom_out_action, self.zoom_reset_action):
            action.setShortcutContext(Qt.ApplicationShortcut)
            self.addAction(action)
        self.zoom_in_action.triggered.connect(lambda: self.zoom_controller.adjust(1))
        self.zoom_out_action.triggered.connect(lambda: self.zoom_controller.adjust(-1))
        self.zoom_reset_action.triggered.connect(lambda: self.zoom_controller.set_zoom(1.0))

    def _zoom_changed(self, factor: float) -> None:
        self._ui_state.setValue("zoom", factor)
        self._ui_state.sync()
        self._update_status()
        self.statusBar().showMessage(
            f"Zoom: {factor:.0%} (Ctrl+0 to reset)", 2500)

    def focus_search(self) -> None:
        self.show_page("logs")
        self.search_text.setFocus()

    def _inspector_button(self) -> QToolButton:
        button = QToolButton()
        button.setDefaultAction(self.inspector_action)
        return button

    def _show_column_menu(self, position) -> None:
        header = self.table.horizontalHeader()
        self.column_menu.exec(header.mapToGlobal(position))

    def _populate_column_menu(self) -> None:
        self.column_menu.clear()
        for column in range(self.model.columnCount()):
            action = self.column_menu.addAction(str(self.model.headerData(column, Qt.Horizontal)))
            action.setCheckable(True)
            action.setChecked(not self.table.isColumnHidden(column))
            action.toggled.connect(
                lambda visible, index=column, item=action:
                    self._set_column_visible(index, visible, item))

    def _set_column_visible(self, column: int, visible: bool, action: QAction) -> None:
        if not visible and sum(
                not self.table.isColumnHidden(index) for index in range(self.model.columnCount())
        ) == 1:
            action.setChecked(True)
            self.statusBar().showMessage(tr("At least one table column must remain visible."), 4000)
            return
        self.table.setColumnHidden(column, not visible)
        self._ui_state.setValue(
            "visible_columns",
            json.dumps([not self.table.isColumnHidden(index)
                        for index in range(self.model.columnCount())]))
        self._ui_state.sync()

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
        self.statusBar().showMessage(tr("Query error: {message}", message=message), 10000)
        if self.search_result.text() == tr("Searching…"):
            self.search_result.setText(tr("Search failed: {message}", message=message))

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
        self.highlight_label.setText(tr("Updating…") if self.highlights.active_rules() else tr("Off"))
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
            self.statusBar().showMessage(f"{tr(title)} – {tr(body.splitlines()[0])}", 15000)

    def _apply_histogram(self, hist: Histogram) -> None:
        self.minimap.set_histogram(hist)
        self.highlights.set_counts(hist)
        total_highlights = sum(hist.highlights)
        self.highlight_label.setText(
            tr("{count} matches", count=format_count(total_highlights))
            if self.highlights.active_rules() else tr("Off"))
        self.highlight_label.setToolTip("\n".join(
            f"{rule.text}: {format_count(sum(bucket[i] for bucket in hist.highlight_counts))}"
            for i, rule in enumerate(hist.highlight_rules)))
        mode = tr("Zoom") if self._zoom else tr("automatic")
        start, end = format_ts(hist.start_ms)[:19], format_ts(hist.end_ms)[:19]
        if start[:10] == end[:10]:
            end = end[11:]
        self.minimap_range_label.setText(f"{tr('Minimap:')} {start} – {end} ({mode})")
        self.minimap_range_label.setToolTip(
            f"Minimap: {format_ts(hist.start_ms)} – {format_ts(hist.end_ms)}\n"
            + (tr("Zoom: exact selected range") if self._zoom
               else tr("Automatically fitted to the available data in the selected range")))
        parts = [f"{tr('Total')} <b>{format_count(hist.total)}</b>",
                 f"<a href='all'>{tr('All')}</a>"]
        selected = self.filter_bar.selected_severities()
        for cls in SeverityClass:
            color = (CLASS_COLORS[cls].lighter(150) if is_dark() else CLASS_COLORS[cls]).name()
            active = selected != set(ALL_SEVERITIES) and any(
                severity_class(sev) == cls for sev in selected)
            weight = "bold" if active else "normal"
            parts.append(f"<a href='{int(cls)}' style='color:{color};font-weight:{weight}'>"
                         f"■ {tr(SEVERITY_CLASS_LABELS[cls])} {format_count(hist.class_total(cls))}</a>")
        self.legend.setText(" &nbsp; ".join(parts))
        if self.highlights.active_rules():
            swatches = " ".join(
                f"<span style='color:{rule.color}'>■</span>" for rule in hist.highlight_rules)
            self.legend.setText(self.legend.text() +
                f" &nbsp; {swatches} "
                f"{tr('Highlight')} {format_count(total_highlights)}")

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
        self.search_result.setText(tr("Searching highlight matches…"))

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
                self.search_result.setText(tr("No more highlight matches") if cursor
                                           else tr("No highlight matches"))
                return
            self._highlight_cursor = hit.cursor
            self._apply_jump(context, PAGE_SIZE, PAGE_SIZE // 2)
            self.search_result.setText(tr("Highlight match selected"))

        self.queries.submit(job, apply)
        self._request_histogram()

    def find_text(self, *, newer: bool = False) -> None:
        self.show_page("logs")
        text = self.search_text.text().strip()
        if not text:
            return
        self.set_live(False)
        self.queries.new_generation()
        self._older_request = self._newer_request = self._live_request = None
        revision = self._search_revision
        f, mode, cursor = self.list_filter(), self.search_mode.currentData(), self._search_cursor
        self.search_result.setText(tr("Searching…"))

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
                self.search_result.setText(tr("No more matches") if cursor else tr("No matches"))
                return
            self._search_cursor = hit.cursor
            self._apply_jump(context, PAGE_SIZE, PAGE_SIZE // 2)
            self.search_result.setText(tr("Match selected"))

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
            self._update_mode_label()
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
        self.show_page("logs")
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
            text = f"&nbsp;<b style='color:{status_color('#1a7f37')}'>● {tr('Autoscroll on')}</b>"
            tip = tr("The newest messages appear at the top.")
        else:
            text = f"&nbsp;<b style='color:{status_color('#9a6700')}'>⏸ {tr('Autoscroll off')}</b>"
            tip = tr("Autoscroll is off; receiving and storage continue.\nUse “Go to latest” once or enable autoscroll.")
        if self._zoom:
            text += f" · Zoom {format_ts(self._zoom[0])[11:19]} – {format_ts(self._zoom[1])[11:19]}"
            tip += f"\nZoom: {format_ts(self._zoom[0])[:19]} – {format_ts(self._zoom[1])[:19]}"
        custom = self.custom_bounds()
        if custom and custom[0] is not None and custom[1] is None:
            text += f" · {tr('from')} {format_ts(custom[0])[11:19]}"
            tip += tr("\nRange from {time}; older messages are hidden but still stored.",
                      time=format_ts(custom[0])[:19])
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
        self.statusBar().showMessage(tr("Copied {count} rows", count=len(rows)), 5000)

    def _on_current_row(self, current, _previous) -> None:
        row = self.model.row_at(current.row())
        self._clear_selected_message()
        self._selected_stats_row = row
        if row is None:
            return
        self.queries.submit(
            lambda runner: runner.get_event(row.id),
            lambda event: self._show_details(event)
            if self._selected_stats_row is not None and self._selected_stats_row.id == row.id else None)
        self.inspector.show_statistics_message(tr("Calculating message statistics…"))
        self._statistics_timer.start(100)

    def _clear_selected_message(self) -> None:
        self._selected_stats_row = None
        self.statistics_queries.new_generation()
        self._statistics_timer.stop()
        self.inspector.clear()

    def _on_statistics_error(self, message: str) -> None:
        self.inspector.show_statistics_message(tr("Statistics failed: {message}", message=message))
        self._on_query_error(message)

    def _set_statistics_regex(self, regex: str | None) -> None:
        row = self._selected_stats_row
        if row is None:
            return
        self._custom_regex = (row.id, regex) if regex else None
        self.statistics_queries.new_generation()
        self._statistics_timer.start(0)

    def _request_message_statistics(self) -> None:
        row = self._selected_stats_row
        if row is None:
            return
        if self.statistics_queries.busy:
            self._statistics_timer.start(250)
            return
        filters, now = self.list_filter(), _now_ms()
        regex = self._custom_regex[1] if self._custom_regex and self._custom_regex[0] == row.id else None

        def job(runner):
            return runner.get_event(row.id), runner.message_statistics(filters, row, now, regex)

        def apply(result):
            if self._selected_stats_row is None or self._selected_stats_row.id != row.id:
                return
            event, stats = result
            self._show_details(event)
            if event is None:
                self.inspector.show_statistics_message(tr("Message no longer exists (deleted by retention)."))
                return
            lines = [
                tr("Same sender and application; active filters and time range (including zoom)."),
                tr("Sender: {sender} · Application: {app}", sender=row.source_ip, app=row.app_name or "–"),
                f"{format_ts(stats.start_ms)} – {format_ts(stats.end_ms)}",
                tr("Regex: {regex}", regex=stats.regex),
                tr("Only numbers vary; all other characters must match exactly. This is a heuristic, not semantic similarity."),
                tr("Rates include empty hours. Partial hours are time-weighted; minimum observation window: 1 second. For an open start, use the first matching sender/application event."),
            ]
            self.inspector.show_statistics(stats, lines, row.received_at)
            self._statistics_timer.start(5000)

        self.statistics_queries.submit(job, apply)

    def _show_details(self, event) -> None:
        if event is None:
            self.details.setPlainText(tr("Message no longer exists (deleted by retention)."))
        else:
            self.inspector.show_event(event)

    # ----------------------------------------------------------------- status
    @Slot()
    def _update_status(self) -> None:
        snap = self.service.snapshot()
        rates = self._rate_tracker.update(snap)
        self._show_listener_state(snap)
        self._show_mcp_state()
        counts = tr("Received {received} · stored {stored} · queued {queued}",
                    received=format_count(snap.received), stored=format_count(snap.persisted),
                    queued=format_count(snap.queued))
        live_rates = tr("Live: {received:.1f}/s received · {stored:.1f}/s stored · {dropped:.1f}/s dropped",
                        received=rates.received, stored=rates.persisted, dropped=rates.dropped)
        self.counter_label.setToolTip(f"{counts}\n{live_rates}")
        if self.zoom_controller.factor > 1.0:
            self.counter_label.setText(counts)
        else:
            self.counter_label.setText(
                f"{counts}<br><span style='color:{status_color('#555')}'>{live_rates}</span>")
        losses = snap.dropped_queue_full + snap.dropped_write_error + snap.dropped_tcp_framing
        if losses:
            self.counter_label.setText(self.counter_label.text() +
                                       f" · <b style='color:{status_color('#b00020')}'>{tr('dropped')} {format_count(losses)}</b>")
        if snap.tcp_connections_rejected:
            self.counter_label.setText(
                self.counter_label.text() +
                f" · <b style='color:{status_color('#b00020')}'>{tr('TCP connections rejected')} "
                f"{format_count(snap.tcp_connections_rejected)}</b>")
        if snap.tls_handshake_failures:
            self.counter_label.setText(
                self.counter_label.text() +
                f" · <b style='color:{status_color('#9a6700')}'>{tr('TLS handshakes failed')} "
                f"{format_count(snap.tls_handshake_failures)}</b>")
        storage = f"DB {format_bytes(snap.storage_bytes)} / {format_bytes(self.service.settings.max_storage_bytes)}"
        if snap.writer_error:
            storage = f"<b style='color:{status_color('#b00020')}'>{snap.writer_error}</b> · {storage}"
        elif snap.storage_budget_exceeded:
            storage = f"<b style='color:{status_color('#9a6700')}'>{tr('Budget exceeded')}</b> · {storage}"
        self.storage_label.setText(storage)
        if not self._live:
            new = snap.persisted - self._persisted_at_pause
            self.statusBar().showMessage(tr("Paused — {count} new messages stored since pausing",
                                            count=format_count(new)))
        else:
            self.statusBar().clearMessage()
        if self.tray:
            self.tray.update_status(snap)

    def _show_listener_state(self, snap: StatsSnapshot) -> None:
        listening = self.service.listening
        self.listen_action.setChecked(listening)
        self.listen_action.setText(tr("Stop receiving") if listening else tr("Start receiving"))
        if snap.listener_state == "error":
            text = f"<b style='color:{status_color('#b00020')}'>{snap.listener_error}</b>"
            if listening:
                text += f" · {tr('Still receiving on')} {snap.listener_display_address}"
        elif listening:
            text = f"<span style='color:{status_color('#1a7f37')}'>{snap.listener_display_address} {tr('active')}</span>"
        else:
            text = f"<span style='color:{status_color('#666')}'>{tr('Receiving stopped')}</span>"
        self.listener_label.setText(text)

    def _toggle_listener(self, checked: bool) -> None:
        if checked:
            if not self.service.start_listener():
                QMessageBox.warning(self, tr("Receiving"), self.service.snapshot().listener_error +
                                    "\n\n" + tr("Change the port in Settings or stop the process using it."))
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
            Level.OK: (tr("Firewall ✓"), "#1a7f37"),
            Level.WARNING: (tr("⚠ Firewall: port not allowed"), "#9a6700"),
            Level.ERROR: (tr("✖ Firewall blocked"), "#b00020"),
            Level.UNKNOWN: (tr("Firewall ?"), "#666"),
        }[check.level]
        weight = "bold" if check.level >= Level.WARNING else "normal"
        color = status_color(color)
        self.firewall_label.setText(
            f"<a href='firewall' style='color:{color};font-weight:{weight};text-decoration:none'>{text}</a>")
        self.firewall_label.setToolTip("\n".join((check.summary, *check.details, tr("Click for details"))))
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
        box.setWindowTitle(tr("Firewall check"))
        box.setIcon({Level.OK: QMessageBox.Information, Level.WARNING: QMessageBox.Warning,
                     Level.ERROR: QMessageBox.Critical}.get(check.level, QMessageBox.Question))
        box.setText(check.summary)
        lines, command = remedy(check, self.service.settings.port, current_programs()[0])
        hints = [*check.details, *([""] if lines else []), *lines,
                 "", tr("Reading requires no administrator rights; nothing is changed.")]
        box.setInformativeText("\n".join(hints))
        box.setTextInteractionFlags(Qt.TextSelectableByMouse)
        copy_button = box.addButton(tr("Copy command"), QMessageBox.ActionRole) if command else None
        recheck_button = box.addButton(tr("Check again"), QMessageBox.ActionRole)
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
            text, color, tip = tr("MCP off"), "#666", tr("MCP server for AI assistants is disabled.")
        elif mcp.running:
            text, color = f"MCP ✓ :{mcp.port}", "#1a7f37"
            tip = tr("MCP server (local only, read-only, no authentication): {url}", url=mcp.url)
        elif mcp.starting:
            text, color, tip = "MCP …", "#666", tr("MCP server is starting")
        else:
            text, color, tip = "✖ MCP", "#b00020", mcp.error
        html = f"<a href='mcp' style='color:{status_color(color)};text-decoration:none'>{text}</a>"
        if html != self.mcp_label.text():
            self.mcp_label.setText(html)
            self.mcp_label.setToolTip(f"{tip}\n{tr('Click for details')}")

    @Slot()
    def show_mcp_details(self, _link: str = "") -> None:
        mcp = self.mcp
        if mcp is None:
            return
        port = mcp.port or self.service.settings.mcp_port
        snippet = json.dumps(client_config(port), indent=2)
        box = QMessageBox(self)
        box.setWindowTitle(tr("MCP server"))
        box.setIcon(QMessageBox.Information if mcp.running or not mcp.enabled else QMessageBox.Warning)
        if mcp.running:
            box.setText(tr("MCP server is running: {url}", url=mcp.url))
        elif mcp.enabled:
            box.setText(tr("MCP server is not running: {error}", error=mcp.error))
        else:
            box.setText(tr("MCP server is disabled (Settings)."))
        box.setInformativeText(
            tr("AI assistants (e.g. GitHub Copilot in VS Code) can read stored syslog messages, "
               "for example “show all messages since the last reboot.”\n\n"
               "Only accessible locally (127.0.0.1), read-only, and unauthenticated: other local "
               "programs can also retrieve messages. Depending on the AI integration, queried "
               "messages may be sent to an external provider.\n\n"
               "VS Code: run “MCP: Open User Configuration” and add:\n\n") + snippet)
        box.setTextInteractionFlags(Qt.TextSelectableByMouse)
        copy_button = box.addButton(tr("Copy configuration"), QMessageBox.ActionRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if box.clickedButton() is copy_button:
            QApplication.clipboard().setText(snippet)

    # --------------------------------------------------------------- settings
    def show_page(self, name: str) -> None:
        if name not in ("logs", "export", "validation", "settings", "about", "quit"):
            raise ValueError(f"Unknown page: {name}")
        if name not in self._pages:
            if name == "export":
                dialog = ExportDialog(self.service.db_path, self.service.settings.boot_marker,
                                      self.filter_bar.current_filter(), self, embedded=True)
                self._export_dialog = dialog
            elif name == "validation":
                dialog = DiagnosticsDialog(self, ui_state=self._ui_state, embedded=True)
                self._diagnostics_dialog = dialog
            elif name == "settings":
                dialog = SettingsDialog(self.service.settings, self, embedded=True)
                self._settings_page = dialog
                dialog.applied.connect(self.apply_settings)
            elif name == "about":
                dialog = AboutDialog(self, embedded=True)
            else:
                dialog = QWidget()
                dialog.setWindowTitle(tr("Minimize or quit"))
                choices = QVBoxLayout(dialog)
                cards = QWidget()
                cards.setMaximumWidth(620)
                cards_layout = QHBoxLayout(cards)
                cards_layout.setContentsMargins(0, 0, 0, 0)
                cards_layout.setSpacing(20)
                self.minimize_button = QPushButton(
                    tr("Minimize to tray") if self.tray else tr("Minimize window"))
                self.minimize_button.clicked.connect(self.minimize_application)
                minimize_hint = QLabel(tr("Receiving, storage and running jobs continue."))
                minimize_hint.setWordWrap(True)
                self.exit_button = QPushButton(tr("Quit application"))
                self.exit_button.clicked.connect(self.quit_application)
                self.exit_button.setStyleSheet(
                    "QPushButton { background: #b42318; color: white; border: 1px solid #b42318; "
                    "border-radius: 8px; padding: 12px; }"
                    "QPushButton:hover { background: #912018; }"
                    "QPushButton:pressed { background: #731912; }"
                    "QPushButton:focus { border: 3px solid palette(highlight); }")
                quit_hint = QLabel(tr("Stops receiving and running jobs, then closes the application."))
                quit_hint.setWordWrap(True)
                for button, hint in ((self.minimize_button, minimize_hint), (self.exit_button, quit_hint)):
                    button.setMinimumHeight(96)
                    button.setMinimumWidth(button.sizeHint().width())
                    font = button.font()
                    font.setBold(True)
                    button.setFont(font)
                    card = QWidget()
                    card_layout = QVBoxLayout(card)
                    card_layout.setContentsMargins(0, 0, 0, 0)
                    card_layout.setSpacing(12)
                    card_layout.addWidget(button)
                    card_layout.addWidget(hint)
                    card_layout.addStretch(1)
                    cards_layout.addWidget(card, 1)
                choices.addWidget(cards)
                choices.addStretch(1)
            page = QWidget()
            page_layout = QVBoxLayout(page)
            title = QLabel(dialog.windowTitle())
            title.setTextFormat(Qt.PlainText)
            font = title.font()
            font.setPointSizeF(font.pointSizeF() * 1.4)
            font.setBold(True)
            title.setFont(font)
            page_layout.addWidget(title)
            scroll = QScrollArea(widgetResizable=True)
            scroll.setFrameShape(QScrollArea.NoFrame)
            content_widths = {"about": 640, "settings": 860, "export": 1000, "validation": 1000}
            if name in content_widths:
                dialog.setMaximumWidth(content_widths[name])
                content = QWidget()
                content_layout = QVBoxLayout(content)
                content_layout.setContentsMargins(0, 0, 0, 0)
                content_layout.addWidget(dialog)
                content_layout.setAlignment(dialog, Qt.AlignTop)
                content_layout.addStretch(1)
                scroll.setWidget(content)
            else:
                scroll.setWidget(dialog)
            page_layout.addWidget(scroll, 1)
            self._pages[name] = page
            self.pages.addWidget(page)
        if name == "export" and self._export_dialog is not None and self._export_dialog.worker is None:
            self._export_dialog._filters = self.filter_bar.current_filter()
            self._export_dialog._boot_marker = self.service.settings.boot_marker
        self.current_page = name
        self.pages.setCurrentWidget(self._pages[name])
        for key in ("logs", "export", "validation", "settings", "about", "quit"):
            self.sidebar.buttons[key].defaultAction().setChecked(key == name)

    @Slot()
    def go_to_latest(self) -> None:
        self.show_page("logs")
        self._zoom = None
        self.reset_zoom_action.setEnabled(False)
        self.refresh_all()

    @Slot()
    def open_export(self) -> None:
        self.show_page("export")

    @Slot()
    def open_settings(self) -> None:
        self.show_page("settings")

    def apply_settings(self, new: Settings) -> None:
        old = self.service.settings
        try:
            save_settings(self._settings_path, new)
        except OSError as exc:
            QMessageBox.critical(self, tr("Settings"), tr("Could not save settings: {error}", error=exc))
            return
        if not self.service.apply_settings(new):
            QMessageBox.warning(self, tr("Receiving"), self.service.snapshot().listener_error)
        apply_theme(new.theme)
        if self.model.rowCount():
            self.model.dataChanged.emit(
                self.model.index(0, 0), self.model.index(self.model.rowCount() - 1, self.model.columnCount() - 1),
                [Qt.BackgroundRole, Qt.ForegroundRole])
        self.minimap.update()
        if self.minimap.histogram is not None:
            self._apply_histogram(self.minimap.histogram)
        self._update_mode_label()
        if self.mcp is not None and not self.mcp.apply(new):
            QMessageBox.warning(self, tr("MCP server"), self.mcp.error)
        self._show_mcp_state()
        if new.data_dir != old.data_dir:
            QMessageBox.information(self, tr("Data directory"),
                                    tr("The new data directory will be used after restarting the application."))
        if new.language != language():
            QMessageBox.information(
                self, tr("Language"),
                tr("The language will change after restarting the application."))
        self._update_status()
        self.check_firewall()

    @Slot()
    def show_about(self) -> None:
        self.show_page("about")

    def open_diagnostics(self) -> None:
        self.show_page("validation")

    # -------------------------------------------------------------- lifecycle
    @Slot()
    def minimize_application(self) -> None:
        self._save_ui_state()
        if self.tray:
            self.hide()
            self.tray.notify_hidden_once()
        else:
            self.showMinimized()

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
        if self._export_dialog is not None:
            self._export_dialog.shutdown()
        if self._diagnostics_dialog is not None:
            self._diagnostics_dialog.shutdown()
        for timer in self._timers:
            timer.stop()
        self._highlight_timer.stop()
        self._visible_range_timer.stop()
        self._statistics_timer.stop()
        self.statistics_queries.shutdown()
        self.queries.shutdown()
        if self.tray:
            self.tray.hide()

    def _save_ui_state(self) -> None:
        s = self._ui_state
        s.setValue("geometry", self.saveGeometry())
        s.setValue("window_state", self.saveState())
        s.setValue("bottom_inspector_splitter", self.splitter.saveState())
        s.setValue("inspector_visible", self.inspector_action.isChecked())
        s.setValue("statistics_mode", self.inspector.mode)
        s.setValue("rules_splitter", self.rules_splitter.saveState())
        s.setValue("columns", self.table.horizontalHeader().saveState())
        s.setValue("visible_columns", json.dumps([
            not self.table.isColumnHidden(index) for index in range(self.model.columnCount())]))
        s.setValue("zoom", self.zoom_controller.factor)
        s.setValue("sidebar_expanded", self.sidebar.expanded)
        s.setValue("range_index", self.range_combo.currentIndex())
        custom = self.custom_bounds() or (None, None)
        s.setValue("range_from", "" if custom[0] is None else str(custom[0]))
        s.setValue("range_to", "" if custom[1] is None else str(custom[1] - 1))
        s.setValue("filters", json.dumps(self.filter_bar.state()))
        s.setValue("highlight_rules", json.dumps(self.highlights.state()))
        s.sync()

    def _restore_ui_state(self) -> None:
        s = self._ui_state
        self.sidebar.set_expanded(str(s.value("sidebar_expanded", False)).lower() == "true")
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
            self.statusBar().showMessage(tr("Could not read stored highlights — using defaults"), 10000)
            self.highlights.restore_state([{"text": DEFAULT_HIGHLIGHT,
                                           "color": HighlightRule().color, "enabled": True,
                                           "popup": legacy_popup}])
        self.model.set_highlight_rules(self.highlights.rules())
        for key, restore in (("geometry", self.restoreGeometry), ("window_state", self.restoreState),
                             ("bottom_inspector_splitter", self.splitter.restoreState),
                             ("rules_splitter", self.rules_splitter.restoreState),
                             ("columns", self.table.horizontalHeader().restoreState)):
            value = s.value(key)
            if value is not None:
                restore(value)
        self.inspector_action.setChecked(str(s.value("inspector_visible", True)).lower() == "true")
        self.inspector.set_mode(str(s.value("statistics_mode", "exact")))
        stored_visibility = s.value("visible_columns")
        if stored_visibility is not None:
            try:
                visibility = json.loads(stored_visibility)
                if (not isinstance(visibility, list)
                        or len(visibility) != self.model.columnCount()
                        or any(type(value) is not bool for value in visibility)
                        or not any(visibility)):
                    raise ValueError("invalid column visibility")
            except (TypeError, ValueError):
                log.warning("Could not read stored column visibility; showing all columns")
                self.statusBar().showMessage(
                    tr("Could not read stored column visibility — showing all columns"), 10000)
                visibility = [True] * self.model.columnCount()
            for index, visible in enumerate(visibility):
                self.table.setColumnHidden(index, not visible)
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
        try:
            zoom = float(s.value("zoom", 1.0))
            if not MIN_ZOOM <= zoom <= MAX_ZOOM:
                raise ValueError("stored zoom is outside the supported range")
        except (TypeError, ValueError):
            log.warning("Could not read stored zoom; using the default")
            self.statusBar().showMessage(tr("Could not read stored zoom — using 100%"), 10000)
            zoom = 1.0
        self.zoom_controller.set_zoom(zoom)
