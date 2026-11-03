from syslog_monitor.query import EventRow, HighlightRule
from syslog_monitor.ui.event_model import EventTableModel
from syslog_monitor.ui.palette import HIGHLIGHT_COLOR, HIGHLIGHT_TEXT_COLOR
from PySide6.QtCore import Qt


def test_severity_colors_and_highlight_without_filtering(qtbot):
    model = EventTableModel()
    base = rows([4])[0]
    model.reset_rows([
        base._replace(severity=6, message="info"),
        base._replace(severity=7, message="debug"),
        base._replace(severity=3, message="INITIALIZING SYSTEM now"),
    ], has_older=False, has_newer=False)
    color = lambda row: model.data(model.index(row, 0), Qt.BackgroundRole).color()
    foreground = lambda row: model.data(model.index(row, 0), Qt.ForegroundRole)
    assert color(0) != color(1)
    assert color(2) == HIGHLIGHT_COLOR
    assert foreground(2).color() == HIGHLIGHT_TEXT_COLOR
    assert foreground(0) is None
    with qtbot.waitSignal(model.dataChanged):
        model.set_highlight("debug")
    assert color(1) == HIGHLIGHT_COLOR
    assert color(2) != HIGHLIGHT_COLOR
    model.set_highlight("info ; Initializing system")
    assert [color(i) == HIGHLIGHT_COLOR for i in range(3)] == [True, False, True]
    model.set_highlight(" ; ")
    assert all(color(i) != HIGHLIGHT_COLOR for i in range(3))
    model.set_highlight("")
    assert color(1) != HIGHLIGHT_COLOR
    assert model.rowCount() == 3


def rows(ids):
    """Rows newest first; id doubles as timestamp."""
    return [EventRow(i, i, "192.0.2.1", 1, 3 if i % 2 else 6, "h", "app", "7", f"m{i}\nx", "")
            for i in ids]


def test_custom_highlight_color_priority_and_readable_text(qtbot):
    from PySide6.QtGui import QColor

    model = EventTableModel()
    model.reset_rows([rows([1])[0]._replace(message="boot ready")],
                     has_older=False, has_newer=False)
    yellow = HighlightRule("ready", "#ffff00")
    blue = HighlightRule("boot", "#000080")
    def color(role):
        return model.data(model.index(0, 0), role).color()
    model.set_highlight_rules((yellow, blue))
    assert color(Qt.BackgroundRole) == QColor("#ffff00")
    assert color(Qt.ForegroundRole) == QColor("#000000")
    model.set_highlight_rules((blue, yellow))
    assert color(Qt.BackgroundRole) == QColor("#000080")
    assert color(Qt.ForegroundRole) == QColor("#ffffff")
    model.set_highlight_rules((HighlightRule("boot", "#000080", False), yellow))
    assert color(Qt.BackgroundRole) == QColor("#ffff00")
    model.set_highlight_rules(())
    assert model.data(model.index(0, 0), Qt.ForegroundRole) is None


def ids(model):
    return [model.row_at(i).id for i in range(model.rowCount())]


def test_reset_and_display(qtbot):
    model = EventTableModel(max_rows=10)
    model.reset_rows(rows([5, 4, 3]), has_older=True, has_newer=False)
    assert model.rowCount() == 3 and model.columnCount() == 7
    assert model.data(model.index(0, 1)) == "Error"
    assert model.data(model.index(0, 5)) == "app[7]"
    assert model.data(model.index(0, 6)) == "m5 ⏎ x"
    assert model.data(model.index(1, 1)) == "Info"
    assert model.top_cursor == (5, 5) and model.bottom_cursor == (3, 3)
    assert model.has_older and not model.has_newer


def test_prepend_trims_bottom(qtbot):
    model = EventTableModel(max_rows=5)
    model.reset_rows(rows([5, 4, 3, 2]), has_older=False, has_newer=False)
    assert model.prepend(rows([8, 7, 6])) == 3
    assert ids(model) == [8, 7, 6, 5, 4]
    assert model.has_older


def test_append_trims_top(qtbot):
    model = EventTableModel(max_rows=5)
    model.reset_rows(rows([9, 8, 7, 6]), has_older=True, has_newer=False)
    assert model.append(rows([5, 4, 3])) == 2
    assert ids(model) == [7, 6, 5, 4, 3]
    assert model.has_newer


def test_bounded_memory_under_many_pages(qtbot):
    model = EventTableModel(max_rows=100)
    model.reset_rows([], has_older=False, has_newer=False)
    for start in range(0, 10_000, 50):
        model.prepend(rows(range(start + 49, start - 1, -1)))
    assert model.rowCount() == 100
    assert model.top_cursor == (9999, 9999)


def test_copy_thousands_of_rows_in_table_order(qtbot):
    model = EventTableModel()
    model.reset_rows(rows(range(5000, 0, -1)), has_older=False, has_newer=False)
    text = model.copy_text(list(reversed(range(5000))))
    copied = list(csv.reader(io.StringIO(text), delimiter="\t"))
    assert len(copied) == 5000
    assert copied[0][-1] == "m5000\nx"
    assert copied[-1][-1] == "m1\nx"
    assert model.copy_text([2, 0, 2]) == model.copy_text([0, 2])
    assert model.copy_text([]) == ""
import csv
import io
