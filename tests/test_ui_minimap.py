from PySide6.QtCore import QPoint, Qt

from syslog_monitor.events import SeverityClass
from syslog_monitor.query import HighlightRule, Histogram
from syslog_monitor.ui.minimap import HIGHLIGHT_COLOR, MinimapWidget, bar_height


def make_widget(qtbot):
    widget = MinimapWidget()
    qtbot.addWidget(widget)
    widget.resize(401, 80)
    counts = [[0] * 5 for _ in range(4)]
    counts[1][SeverityClass.ERROR] = 1
    counts[2][SeverityClass.INFO] = 100
    widget.set_histogram(Histogram(0, 400_000, counts))
    widget.show()
    return widget


def test_bar_height_keeps_small_counts_visible():
    assert bar_height(0, 100, 50) == 0
    assert bar_height(1, 10_000, 50) >= 1
    assert bar_height(100, 100, 50) == 50


def test_coordinate_mapping(qtbot):
    w = make_widget(qtbot)
    assert w.x_to_time(0) == 0
    assert w.x_to_time(200) == 200_000
    assert w.x_to_time(10_000) == 400_000  # clamped
    assert abs(w.time_to_x(100_000) - 100) < 1
    assert w.bucket_at(150) == 1
    assert w.bucket_at(-5) is None


def test_click_emits_time(qtbot):
    w = make_widget(qtbot)
    with qtbot.waitSignal(w.time_clicked) as blocker:
        qtbot.mouseClick(w, Qt.LeftButton, pos=QPoint(100, 30))
    assert abs(blocker.args[0] - 100_000) <= 1000


def test_drag_emits_range(qtbot):
    w = make_widget(qtbot)
    with qtbot.waitSignal(w.range_selected) as blocker:
        qtbot.mousePress(w, Qt.LeftButton, pos=QPoint(300, 30))
        qtbot.mouseMove(w, QPoint(100, 30))
        qtbot.mouseRelease(w, Qt.LeftButton, pos=QPoint(100, 30))
    start, end = blocker.args
    assert abs(start - 100_000) <= 1000 and abs(end - 300_000) <= 1000


def test_paints_without_errors(qtbot):
    w = make_widget(qtbot)
    w.set_marker(150_000)
    image = w.grab().toImage()
    # error strip on top of bucket 1 (x 100..200) is red; the marker sits at x=150
    color = image.pixelColor(120, 3)
    assert color.red() > 150 and color.green() < 100
    w.set_histogram(Histogram(0, 1, []))
    w.grab()


def test_highlight_strip_is_separate_from_errors(qtbot):
    w = make_widget(qtbot)
    hist = w.histogram
    w.set_histogram(Histogram(hist.start_ms, hist.end_ms, hist.counts, [0, 1, 0, 0]))
    image = w.grab().toImage()
    assert image.pixelColor(120, 9) == HIGHLIGHT_COLOR
    assert image.pixelColor(120, 3).red() > 150
    w.set_histogram(Histogram(hist.start_ms, hist.end_ms, hist.counts, [0] * 4))
    assert w.grab().toImage().pixelColor(120, 9) != HIGHLIGHT_COLOR


def test_epoch_milliseconds_do_not_overflow(qtbot):
    w = make_widget(qtbot)
    start = 1_790_000_000_000
    w.set_histogram(Histogram(start, start + 400_000, [[1, 0, 0, 0, 0]] * 4))
    with qtbot.waitSignal(w.time_clicked) as clicked:
        qtbot.mouseClick(w, Qt.LeftButton, pos=QPoint(100, 30))
    assert clicked.args[0] == start + 100_000
    with qtbot.waitSignal(w.range_selected) as dragged:
        qtbot.mousePress(w, Qt.LeftButton, pos=QPoint(100, 30))
        qtbot.mouseMove(w, QPoint(300, 30))
        qtbot.mouseRelease(w, Qt.LeftButton, pos=QPoint(300, 30))
    assert dragged.args == [start + 100_000, start + 300_000]


def test_multiple_highlight_colors_have_separate_lanes(qtbot):
    from PySide6.QtGui import QColor

    w = make_widget(qtbot)
    hist = w.histogram
    rules = (HighlightRule("boot", "#00796b"), HighlightRule("ready", "#ffff00"))
    w.set_histogram(Histogram(hist.start_ms, hist.end_ms, hist.counts, [0, 2, 0, 0],
                              rules, [[0, 0], [1, 1], [0, 0], [0, 0]]))
    image = w.grab().toImage()
    assert image.pixelColor(120, 8) == QColor("#00796b")
    assert image.pixelColor(120, 11) == QColor("#ffff00")
    assert image.pixelColor(120, 3).red() > 150  # error strip stays intact
