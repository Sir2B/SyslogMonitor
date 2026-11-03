"""PyInstaller entry point (the package's __main__ cannot be frozen directly)."""

import sys

from syslog_monitor.app import main

if __name__ == "__main__":
    sys.exit(main())
