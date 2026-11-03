# Syslog Monitor

A PySide6 desktop application for receiving syslog messages over **UDP**, storing them
persistently in SQLite, and browsing them with search, filters, highlights, and a
**minimap**. It is designed to run for days at a time and continues receiving messages
while minimized to the system tray.

**License:** MIT (see [LICENSE](LICENSE)). The EXE and installer bundle third-party
software, including Qt/PySide6 under LGPL-3.0. Their license texts are included in the
packages; see [Distribution](#distribution-exe--installer).

## Installation

Requires Python 3.11 or later with SQLite FTS5 (included with the python.org Windows
builds).

```powershell
# From the project directory; create the virtual environment outside synchronized folders.
python -m venv "$env:LOCALAPPDATA\SyslogMonitor-dev\.venv"
& "$env:LOCALAPPDATA\SyslogMonitor-dev\.venv\Scripts\Activate.ps1"
pip install -e ".[test]"
```

Run the application:

```powershell
syslog-monitor            # without a console window
python -m syslog_monitor   # alternatively
```

Only one instance can run at a time. A second launch reports that the application is
already running. On Windows, the application sets its own AppUserModelID so the taskbar
shows the Syslog Monitor icon rather than the Python icon.

### Firewall

By default, the application listens on the standard syslog port `0.0.0.0:514/udp`.
Administrator rights are not required to listen on this port on Windows. If another
syslog service already uses port 514, change the port in Settings. The firewall must
allow traffic from the intended senders. For example, this rule restricts access to one
sender (run in an elevated PowerShell):

```powershell
$sender = "192.0.2.50"  # Documentation-only address; replace with the actual sender IP.
New-NetFirewallRule -DisplayName "Syslog Monitor UDP 514" -Direction Inbound -Protocol UDP -LocalPort 514 -RemoteAddress $sender -Action Allow
```

The optional firewall rule created by the installer allows UDP traffic for the
application without restricting sender addresses or ports. Create a narrower rule
instead if needed.

**Firewall status:** The status bar reports whether the Windows Firewall allows inbound
UDP traffic to this process on the configured port. It is checked at startup, after
changes to the port or listener, and every five minutes in the background.

| Indicator | Meaning |
|---|---|
| `Firewall ✓` (green) | Allowed in every active network profile, for example by a port or application rule, or because inbound traffic is allowed by default. |
| `⚠ Firewall: port not allowed` (orange) | At least one active profile has no matching allow rule. Only messages from the local computer are certain to arrive. |
| `✖ Firewall blocked` (red) | A block rule applies. Block rules take precedence over allow rules. |
| `Firewall ?` (gray) | The firewall could not be checked. |

Click the indicator for per-profile details and a suggested command. A tray warning is
shown once if the status worsens. The check reads the *effective* rules, including IT
group policy (`-PolicyStore ActiveStore`); it does not require administrator rights and
does not change settings. This is an approximation: restrictions on remote addresses
or interface types are not evaluated. No firewall check is needed when listening only
on `127.0.0.1`.

If the firewall reports a block, Windows may have automatically created block rules for
the executable when it was first launched and a security prompt was dismissed or
declined. The details dialog provides a command to remove those rules and add an allow
rule (run it in an elevated PowerShell).

## Distribution (EXE / installer)

Recipients do not need Python. To build, open PowerShell in the project directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\packaging\build.ps1"   # add -SkipTests to skip tests
```

The command also works from another directory when given the absolute script path.

Requirements: Python 3.11 (`py -3.11`) and, for the installer, [Inno Setup 6](https://jrsoftware.org/isinfo.php)
(`winget install JRSoftware.InnoSetup --scope user`). Without Inno Setup, only the ZIP
is produced. The virtual environment and PyInstaller intermediates are stored in
`%LOCALAPPDATA%\SyslogMonitor-build`. Output is written to `dist\`:

| File | Purpose |
|---|---|
| `SyslogMonitor-<version>-setup.exe` | Per-user installation **without administrator rights** to `%LOCALAPPDATA%\Programs\SyslogMonitor`, with Start menu entry and uninstall support in Windows Apps. Optional desktop shortcut, autostart, and firewall rule (the latter requests elevation once). |
| `SyslogMonitor-<version>-portable.zip` | Extract and run `SyslogMonitor.exe`. No installation required. |

Notes:

- Data and settings are stored per user in `%LOCALAPPDATA%\SyslogMonitor` for both
  variants. Installing a newer version over the old one preserves them.
- The executable is unsigned. SmartScreen may show “Windows protected your PC”; choose
  “More info” → “Run anyway.” Company AppLocker policies may prohibit running from
  `%LOCALAPPDATA%`; ask your IT department if that happens.
- Email often blocks `.exe` and `.zip` attachments; share a suitable download link instead.
- The executable is a different program from `python.exe` for firewall purposes. Allow
  it using the installer option, a port rule, or the command in the firewall dialog.
- Version is defined by `__version__` in `src/syslog_monitor/__init__.py` and is used in
  the output filenames and installer.
- The build places `LICENSE.txt` (MIT), `THIRD-PARTY-NOTICES.txt`, and a `licenses\`
  directory containing license texts for every bundled package next to the executable
  (`packaging/collect_licenses.py`). The build fails if a bundled package has no license
  text. Qt/PySide6 is used under LGPL-3.0; the license texts are in
  `packaging/licenses/`. Qt DLLs are dynamically linked and replaceable. The notices
  include sources for the corresponding source code.

## Usage

| Control | Function |
|---|---|
| **Receive** | Toggle the UDP listener. Previously stored data is retained. |
| **Live** | New messages appear at the top. Pausing freezes only the view; receiving and storage continue. Scrolling down automatically pauses live updates. |
| **Clear view** | Button beside the time range or **Ctrl+L**. Sets the custom range start to the current time and enables Live. The table, minimap, counters, and search then show only new messages, and the toolbar displays the start time. **No data is deleted.** Choose another range or uncheck “From” to show older messages again. |
| **Time range** | Above the minimap, beside “Reset zoom.” Choose 15 minutes through 30 days, “All,” or **“From / To…”**. Either date/time boundary is optional: From only shows messages from that time through now (including live updates); To only shows messages up to the selected time. To includes the displayed second. If From is later than To, the values are corrected automatically. Switching to a custom range uses the current range as its initial value. The range applies to the table, search, and minimap. The minimap fits the actual data range within the selected bounds. |
| **Search** | Field below the filters. **Enter/F3** or “▼ Older” moves to the next older match; **Shift+F3** or “▲ Newer” moves to the next newer match. **Ctrl+F** focuses the field. Search starts at the newest match, selects the matching row, and shows surrounding messages even if they do not match the query. It searches beyond the currently loaded table page. Active filters and time range still apply; search does not affect the minimap. Searching pauses the view, but receiving and storage continue. At the end, “No more matches” is shown; results do not wrap around. |
| **Severity** | Click a group in the colored legend to show only that group: Error, Warning, Info, Debug, or Unknown. Click the only selected group again or click “All” to reset the severity filter. Ctrl+click adds or removes groups. Info includes Notice and Info; Error includes Emergency through Error. Active groups are bold. Counts reflect the active filters. The severity menu also provides individual severities and presets. |
| **Facility** | Separate selector, in addition to severity and text rules. |
| **Filter rules** | Add rules for text, message, sender/IP, host, or application using contains, does not contain, equals, or does not equal. For “Text (all fields),” “contains all words” and its negative form are also available. Combine rules using AND or OR; non-matching messages are hidden. |
| **Select / copy** | Shift+click selects a range; Ctrl+click selects individual rows. Ctrl+A selects all currently loaded rows; Ctrl+C copies the selection. A context menu is also available. Selecting multiple rows automatically pauses Live. |
| **Minimap** | Stacked bars per time bucket (red = errors, orange = warnings, etc.) with a red error strip above. With sparse data, the range is automatically narrowed and padded around existing messages. The displayed range appears in the header. **Click** to jump to a time. **Drag** to zoom to a selected range; “Reset zoom” restores automatic scaling. Tooltips show counts and milliseconds. |
| **Details** | Shows all fields of the selected row, including raw data and parser notes. |
| **F5** | Refresh the view. |
| **Close button** | Minimizes the window to the tray; receiving continues. Quit using the “Quit” menu item or tray menu. |

### Colors and highlights

Info/Notice rows are light blue; Debug rows are light gray. Their minimap bars are blue
and gray respectively. A scrollable **Highlight** panel appears to the right of the
filters. Add multiple rules, each with its own text, color, enabled checkbox, and remove
button. Drag the divider to adjust the width of the two panels. Highlights never hide
messages. Text color is chosen for contrast with the background.

Use **↑ / ↓** to change priority: **the highest-priority matching enabled rule wins**.
Overlapping matches are counted only once. Empty or disabled rules are inactive. A rule
can contain multiple strings separated by `;`; any one matching string triggers it.
The default rule is `Initializing system` in purple.

The minimap shows a separate color band for each enabled rule below the error strip,
regardless of the number of other messages. The same priority order applies when rules
overlap. The error strip and severity counters remain visible. Each rule shows its own
match count. Tooltips explain the count scope and priority; disabled or empty rules show
“–”, and “…” appears while counts are being updated. The legend and highlight summary
show totals; tooltips show counts per rule across all stored messages in the active
filters and time range, not just the loaded table page. Highlights search the full
message using a literal substring (ASCII case-insensitive; no wildcards or regular
expressions). Changes apply even when the view is paused. Text, colors, order, and
enabled state are saved. Existing highlight text is migrated as a purple rule when
upgrading.

**New-highlight popups:** When “Popup” is enabled, a Windows notification appears when
a newly received message matches a highlight, even if the window is minimized to the
tray and regardless of filters or Live pause. Existing messages do not trigger a
notification at startup. Notifications are grouped (at most one every 10 seconds) and
include up to the three newest messages and the total count. Click a notification to
open the window.

### Filters, table, and status

The compact header contains the toolbar, filters on the left, highlights on the right,
search, and minimap. The filter and highlight panels scroll independently and have
limited height so adding rules does not expand the header. The table below uses the
full width. The minimap header includes the time range, “Clear view,” reset zoom,
displayed range, and severity legend.

The status bar shows listener state, cumulative received/stored counts, queue size,
storage usage, and a per-second live rate for received, stored, and dropped messages.
Window size, columns, filters, and time range (including From/To) are saved.

Text, sender, and application filters use shared rule rows. Previously saved filters
are converted to rules when loaded. Search supports **Words** and **Substring** modes.
Words search and the “Text (all fields) contains all words” rule use SQLite FTS5 across
message, host, application, and structured data. Matching is case- and accent-insensitive;
word prefixes are sufficient (`disk fail` matches “Disk failure”). Punctuation is
ignored. Substring search matches arbitrary text in message, host, and application, but
can be slower over long time ranges.

Filter rules apply to the table, search, and minimap. The full rule group is combined
with severity, facility, and time range using AND. Rules marked **Always AND** remain
required even when the rest of the rules use OR:
`Severity AND Facility AND Time range AND Required rule AND (Rule 1 OR Rule 2)`.
This preserves the meaning of older saved filters that used OR. Example: application
equals `web` AND message does not contain `heartbeat`. Empty rules are inactive.
Negative rules also allow messages that do not have the selected field. “Text (all
fields)” includes message, host, application, and structured data. Values are literal,
not regular expressions; `%` and `_` are not wildcards. Like substring search, matching
is case-insensitive only for ASCII. Word search handles Unicode through FTS5. Rules are
saved with the other filters.

Copying exports all seven columns in table order, without headers, as tab-separated
text (TSV). Messages are copied in full even if the table truncates them. CSV quoting
preserves tabs and line breaks for spreadsheet applications. Selection applies to the
loaded table window (up to 5,000 rows), not the entire database; changing filters or
refreshing clears the selection.

## AI access (MCP)

While Syslog Monitor is running (including in the system tray), it provides an
[MCP](https://modelcontextprotocol.io) server. AI assistants such as GitHub Copilot in
VS Code can query and analyze stored messages, for example after an embedded Linux
device restarts: *“Analyze the syslog messages from 192.0.2.50 since the last reboot.”*
This is a reserved documentation address.

- Available locally at `http://127.0.0.1:8514/mcp` only. It is not reachable over the
  network and does not need a firewall rule.
- Local access is **unauthenticated**: other local processes can also read messages
  through MCP. Depending on the AI integration, queried messages may be sent to an
  external provider. This warning is also shown in MCP details and Settings. Disable
  the MCP server in Settings if needed.
- The server is read-only: the AI cannot delete messages or change settings.
- Status bar: **MCP ✓ :8514**. Click it to view VS Code configuration and copy it.
- **Configure in VS Code:** run the *MCP: Open User Configuration* command and add:

  ```json
  { "servers": { "syslog-monitor": { "type": "http", "url": "http://127.0.0.1:8514/mcp" } } }
  ```

- In **Settings**, enable or disable the server, choose its port, and set the
  **boot marker**—the text used to detect a device restart (default:
  `Initializing system`; separate multiple strings with `;`).
- **Privacy:** Depending on the AI integration, queried messages may be sent to an
  external provider. Log text can contain sensitive data or instructions; treat it as
  untrusted input.

| Tool | Purpose |
|---|---|
| `logs_since_boot` | Messages from a device since its latest or an earlier reboot, with severity counts. |
| `get_logs` | Messages in a time range, in chronological order, paged with `next_after`. |
| `search_logs` | Text search, optionally filtered by device, time range, and minimum severity. |
| `get_context` | Messages before and after a selected message. |
| `summarize` | Overview with counts by severity, reboots, and most frequent errors and warnings. |
| `error_timeline` | Errors, warnings, and reboots by time bucket. |
| `wait_for_message` | Wait for a new message, for example the boot marker after a reboot. |
| `status`, `list_devices` | Listener status, stored data, and active devices. |

Specify devices by exact IP address or by hostname/address substring. Time values can
be ISO 8601 or relative (`30m`, `2h`, `1d`). Results are bounded, and very long
messages are truncated.

## Storage

Data is stored in `%LOCALAPPDATA%\SyslogMonitor\`:

- `settings.json`: settings, also editable in the Settings dialog
- `data\syslog.sqlite3`: database (WAL)
- `logs\`: rotating application log, 5 × 2 MiB
- `ui.ini`: window state

Retention defaults to 30 days and the storage budget defaults to 5 GiB; both are
configurable. Older data is deleted in small batches every minute. If the budget is
exceeded, the oldest rows are deleted until usage falls to 90% of the budget.

Measured storage is about **370 bytes per message**, including the full-text index.
At 10 messages/second for 30 days, that is about 2.6 million messages or 0.9 GiB.
Messages are committed in batches approximately every 0.5 seconds, so a crash or power
loss may lose messages received during the last half-second. If the database is
temporarily unavailable for writing, the application retries before dropping and
counting messages. A changed data directory (`data_dir`) takes effect after a restart.

### Measured performance

Measured with 2.6 million messages (30 days at 1 message/second):

| Operation | Time |
|---|---|
| Latest page / paging / jump | < 20 ms |
| Errors only | ~ 7 ms |
| Common word search across all data | ~ 1.7 s |
| Rare word search | ~ 80 ms |
| 24-hour substring search | ~ 0.7 s |
| Minimap for 24 hours / 3 days | ~ 0.7 s / ~ 2.3 s |

Queries run in a background thread. A new filter input cancels a running query, keeping
the GUI responsive.

## Limitations

- UDP only; no TCP or TLS. Under network load or when the socket buffer is full, UDP can
  lose packets without the receiver detecting it.
- UDP syslog is neither encrypted nor authenticated; messages and sender addresses can
  be forged. Use only on trusted networks and restrict firewall access to the required
  senders.
- The application does not encrypt the local SQLite database. Protect operating-system
  access to the data and backups accordingly.
- Only IPv4 bind addresses are supported.
- The parser tolerates RFC 5424/3164. Non-conforming messages are still stored and
  marked with a parser note.
- Messages are sorted by reception time (newest first), not by the sender's timestamp.
- Substring search is case-insensitive only for ASCII characters (`café` and `cafe` differ).
  Word search does not have this limitation.
- If the receive queue fills (20,000 messages), messages are dropped and counted in the
  status bar.

## Architecture

```text
src/syslog_monitor/
  events.py      Data model and severity classes
  parser.py      RFC 5424/3164 parser (pure, no I/O)
  receiver.py    UDP thread → queue
  writer.py      Batch writer thread, retention/budget, retries
  storage.py     SQLite schema, migrations, deletion logic
  query.py       Read queries, filters → SQL, histogram
  service.py     CaptureService connects receiver, writer, and store
  config.py      Validated JSON settings
  mcp_tools.py   Read-only AI queries (testable without MCP/Qt dependencies)
  mcp_server.py  Background-thread MCP server (Streamable HTTP, 127.0.0.1)
  app.py         Entry point: logging, single-instance lock, startup
  ui/            Qt layer: main window, table, minimap, filters, tray, dialogs
```

Core logic (`parser`, `storage`, `query`, `writer`, `service`) does not depend on Qt and
can be tested without the GUI. The GUI reads through `QueryRunner` in a dedicated thread.

## Tests

```powershell
pytest -q                          # unit, offscreen GUI, real UDP, and MCP-over-HTTP tests
$env:SYSLOG_MONITOR_SLOW_TESTS = 1  # enable load tests (~3.5 minutes)
pytest -q -m slow
```

Load tests exercise 2.6 million messages, query performance, retention on a large data
set, and live UDP reception. A multi-day soak test is not automated. Before production
use, run the application with real sources for several days and monitor the status bar
and `logs\`.

