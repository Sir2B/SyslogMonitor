from PySide6.QtCore import QPoint, QPointF, Qt
from PySide6.QtGui import QWheelEvent
from PySide6.QtWidgets import QApplication, QPushButton, QVBoxLayout, QWidget

from syslog_monitor.ui.filter_bar import FilterBar
from syslog_monitor.ui.zoom import ZoomController


def test_zoom_scales_fonts_fixed_sizes_and_layout(qtbot):
    panel = QWidget()
    layout = QVBoxLayout(panel)
    button = QPushButton("Zoom")
    button.setFixedSize(80, 20)
    layout.addWidget(button)
    qtbot.addWidget(panel)
    controller = ZoomController(QApplication.instance(), panel)
    original_font_size = button.font().pointSizeF()
    original_spacing = layout.spacing()
    original_margins = layout.contentsMargins()

    controller.set_zoom(1.5)

    assert button.minimumSize().width() == button.maximumSize().width() == 120
    assert button.minimumSize().height() == button.maximumSize().height() == 30
    assert button.font().pointSizeF() == original_font_size * 1.5
    assert layout.spacing() == round(original_spacing * 1.5)
    assert layout.contentsMargins().left() == round(original_margins.left() * 1.5)
    controller.set_zoom(1.0)
    assert button.minimumSize().width() == button.maximumSize().width() == 80
    assert button.font().pointSizeF() == original_font_size


def test_control_mousewheel_changes_zoom(qtbot):
    panel = QWidget()
    button = QPushButton("Zoom", panel)
    qtbot.addWidget(panel)
    controller = ZoomController(QApplication.instance(), panel)
    event = QWheelEvent(
        QPointF(1, 1), QPointF(1, 1), QPoint(), QPoint(0, 120),
        Qt.NoButton, Qt.ControlModifier, Qt.NoScrollPhase, False)

    assert QApplication.sendEvent(button, event)
    assert controller.factor == 1.1
    controller.set_zoom(1.0)


def test_filter_dropdown_heights_stay_equal_when_zoomed(qtbot):
    bar = FilterBar()
    qtbot.addWidget(bar)
    controller = ZoomController(QApplication.instance(), bar)
    original_height = bar.facility.height()

    controller.set_zoom(1.5)

    assert bar.severity_button.height() == bar.facility.height() == bar.rules_match.height()
    assert bar.facility.minimumHeight() == round(original_height * 1.5)
    controller.set_zoom(1.0)
