"""Write the application icon as a multi-resolution .ico file: python make_icon.py <target>."""

import sys
from pathlib import Path

from PySide6.QtGui import QGuiApplication

from syslog_monitor.ui.icons import app_ico_bytes

if __name__ == "__main__":
    app = QGuiApplication([])
    target = Path(sys.argv[1])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(app_ico_bytes())
