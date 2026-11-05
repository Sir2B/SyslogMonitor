from syslog_monitor import APP_DISPLAY_NAME, __version__
from syslog_monitor.ui.about_dialog import AboutDialog


def test_about_dialog_shows_version_runtime_license_and_project_links(qtbot):
    dialog = AboutDialog()
    qtbot.addWidget(dialog)

    assert dialog.windowTitle() == f"About {APP_DISPLAY_NAME}"
    assert __version__ in dialog.version_label.text()
    assert "MIT License" in dialog.details_label.text()
    assert "Python " in dialog.details_label.text()
    assert "Qt " in dialog.details_label.text()
    assert "https://github.com/Sir2B/SyslogMonitor" in dialog.details_label.text()
    assert "https://github.com/Sir2B/SyslogMonitor/issues" in dialog.details_label.text()
