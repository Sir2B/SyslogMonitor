# Syslog Monitor

[![Release](https://img.shields.io/github/v/release/Sir2B/SyslogMonitor)](https://github.com/Sir2B/SyslogMonitor/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/Sir2B/SyslogMonitor/ci.yml?branch=main&label=tests)](https://github.com/Sir2B/SyslogMonitor/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/Sir2B/SyslogMonitor)](LICENSE)
[![Windows](https://img.shields.io/badge/platform-Windows-blue)](https://github.com/Sir2B/SyslogMonitor/releases/latest)

A simple Windows GUI tool for receiving and browsing syslog messages.

Keep an eye on routers, switches, servers, and other devices in one place.
Search logs, spot errors on a timeline, and highlight messages that matter.

![Syslog Monitor main window](https://github.com/Sir2B/SyslogMonitor/releases/latest/download/screenshot.png)

## Get started

1. Download the installer or portable ZIP from the
   [latest release](https://github.com/Sir2B/SyslogMonitor/releases/latest).
2. Install it, or extract the ZIP and run **SyslogMonitor.exe**. No Python required.
3. Point your devices at this PC's IP address, using **UDP port 514** by default.
4. If messages do not arrive, click the **Firewall** indicator for help, or change
   the listening address and port in **Settings**.

Installation is per user and does not require administrator rights. Adding firewall
rules may require elevation. The executable is unsigned; Windows SmartScreen may
display a warning.

## What you can do

- **Receive and keep logs** over UDP, TCP, or TLS, even while minimized to the tray.
- **Filter messages** by severity, facility, sender, application, or text.
- **Search with context** without hiding the messages around each match.
- **Explore the timeline**: click to jump to a time, or drag to zoom into a period.
- **Highlight important text** with custom colors and optional notifications.
- **Export logs** to CSV or JSONL, including a device's messages since its last reboot.
- **Make it yours**: light/dark mode, English/German, adjustable zoom, and show/hide columns.

The first launch detects German from your system language; otherwise it uses English.
You can change it in **Settings > Language** (restart required).

Hover over a highlight's count to see its average matches per hour and standard
deviation within the displayed timeline and active filters.

## Everyday controls

| Control | What it does |
|---|---|
| **Receive** | Start or stop reception. Saved messages stay available. |
| **Live** | Follow the newest messages. Pausing affects only the view, not reception. |
| **Time range** | Choose a recent period or set optional From/To boundaries. |
| **Clear view** | Show messages received from now on. **Nothing is deleted.** |
| **Table header** | Right-click to show or hide columns. |
| **Details** | Select a message to inspect its full text, raw data, and parser notes. |

| Shortcut | Action |
|---|---|
| **Ctrl+F** | Focus search |
| **Enter / F3**, **Shift+F3** | Next older / previous newer search match |
| **F5** | Go to the latest matching messages |
| **Ctrl+C**, **Ctrl+A** | Copy selected / select all loaded rows |
| **Ctrl+L** | Clear the view |
| **Ctrl++ / Ctrl+-**, **Ctrl+mouse wheel** | Zoom the interface |
| **Ctrl+0** | Reset interface zoom |
| **Ctrl+Q** | Quit |

Closing the window keeps reception running in the system tray. Use **Quit** to exit.
Your layout, filters, column visibility, and zoom are saved.

## Screenshots

<details>
<summary>Dark mode</summary>

![Syslog Monitor in dark mode](https://github.com/Sir2B/SyslogMonitor/releases/latest/download/screenshot-dark.png)

</details>

<details>
<summary>Column menu and highlight options</summary>

![Show or hide columns](https://github.com/Sir2B/SyslogMonitor/releases/latest/download/screenshot-columns.png)

![Edit a highlight rule](https://github.com/Sir2B/SyslogMonitor/releases/latest/download/screenshot-highlights.png)

</details>

<details>
<summary>Settings and export</summary>

![Listener and appearance settings](https://github.com/Sir2B/SyslogMonitor/releases/latest/download/screenshot-settings.png)

![Export messages](https://github.com/Sir2B/SyslogMonitor/releases/latest/download/screenshot-export.png)

</details>

## Storage and privacy

Logs and settings are stored locally in `%LOCALAPPDATA%\SyslogMonitor`.
By default, logs are kept for **30 days**, with a **5 GiB storage budget**.
Change these limits in **Settings**; older messages are deleted when a limit is reached.
Upgrading preserves your data and settings.

- UDP and plain TCP are **unencrypted and unauthenticated**. Use trusted networks
  and limit firewall access to known senders. TLS is available in Settings.
- The local database is not encrypted.
- Messages are ordered by reception time, not the device's clock. UDP can lose messages.

## Optional AI access

The built-in, read-only MCP server lets compatible AI assistants query stored logs.
Click the **MCP** status indicator to copy the connection configuration, or disable
the server in **Settings**.

**Privacy:** MCP is accessible only on this PC, but other local programs can read it
without authentication. Your AI integration may send queried log content to an
external provider.

## More information

- [Detailed usage, TLS setup, and troubleshooting](docs/REFERENCE.md#usage)
- [Run from source](docs/REFERENCE.md#installation)
- [Build, tests, and screenshot generation](docs/REFERENCE.md#distribution-exe--installer)
- [Report a problem](https://github.com/Sir2B/SyslogMonitor/issues)

**License:** [MIT](LICENSE). Windows packages include Qt/PySide6 and other third-party
license notices.
