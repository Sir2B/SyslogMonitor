# Syslog Monitor

A PySide6 desktop application for receiving syslog messages over **UDP, TCP, and TLS**, storing them
persistently in SQLite, and browsing them with search, filters, highlights, and a
**minimap**. It is designed to run for days at a time and continues receiving messages
while minimized to the system tray.

![Syslog Monitor main window](https://github.com/Sir2B/SyslogMonitor/releases/latest/download/screenshot.png)

**License:** MIT (see [LICENSE](LICENSE)). The EXE and installer bundle third-party
software, including Qt/PySide6 under LGPL-3.0. Their license texts are included in the
packages; see [Distribution](#distribution-exe--installer).

## Installation

The Windows installer and portable ZIP are available on the
[latest release](https://github.com/Sir2B/SyslogMonitor/releases/latest).

To run from source, Python 3.11 or later with SQLite FTS5 is required (included with the
python.org Windows builds).

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

By default, the application listens on the standard syslog port `0.0.0.0:514/udp`;
TCP and TLS are disabled until enabled in Settings. Administrator rights are not required to
listen on this port on Windows. If another syslog service already uses a configured
port for the same protocol, change the port in Settings. The firewall must
allow traffic from the intended senders. For example, this rule restricts access to one
sender (run in an elevated PowerShell):

```powershell
$sender = "192.0.2.50"  # Documentation-only address; replace with the actual sender IP.
New-NetFirewallRule -DisplayName "Syslog Monitor UDP 514" -Direction Inbound -Protocol UDP -LocalPort 514 -RemoteAddress $sender -Action Allow
# If TCP reception is enabled, create a separate rule for its configured port:
New-NetFirewallRule -DisplayName "Syslog Monitor TCP 514" -Direction Inbound -Protocol TCP -LocalPort 514 -RemoteAddress $sender -Action Allow
# TLS runs over TCP (default port 6514):
New-NetFirewallRule -DisplayName "Syslog Monitor TLS 6514" -Direction Inbound -Protocol TCP -LocalPort 6514 -RemoteAddress $sender -Action Allow
```

The installer offers separate optional UDP and TCP firewall rules (the TCP rule also
covers TLS). Each allows traffic
for the application without restricting sender addresses or ports. Create narrower
rules instead if needed.

**Firewall status:** The status bar reports whether the Windows Firewall allows inbound
traffic to this process on every enabled protocol and configured port. It reports the
worst result and is checked at startup, after changes to the ports or listeners, and
every five minutes in the background.

| Indicator | Meaning |
|---|---|
| `Firewall ✓` (green) | Allowed in every active network profile, for example by a port or application rule, or because inbound traffic is allowed by default. |
| `⚠ Firewall: port not allowed` (orange) | At least one active profile has no matching allow rule. Only messages from the local computer are certain to arrive. |
| `✖ Firewall blocked` (red) | A block rule applies. Block rules take precedence over allow rules. |
| `Firewall ?` (gray) | The firewall could not be checked. |

Click the indicator for per-protocol and per-profile details and suggested commands. A tray warning is
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

Requirements: Python 3.15 (`py -3.15`) and, for the installer, [Inno Setup 6](https://jrsoftware.org/isinfo.php)
(`winget install JRSoftware.InnoSetup --scope user`). Without Inno Setup, only the ZIP
is produced. Pass `-PythonVersion 3.11` to build with Python 3.11 instead. The build
checks that a reused build environment matches the requested Python version. The
virtual environment and PyInstaller intermediates are stored in
`%LOCALAPPDATA%\SyslogMonitor-build`. Output is written to `dist\`:

| File | Purpose |
|---|---|
| `SyslogMonitor-<version>-setup.exe` | Per-user installation **without administrator rights** to `%LOCALAPPDATA%\Programs\SyslogMonitor`, with Start menu entry and uninstall support in Windows Apps. Optional desktop shortcut, autostart, and UDP/TCP(+TLS) firewall rules (each rule requests elevation). |
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

### Releases and screenshot

Pushing a `v*` tag runs `.github/workflows/release.yml` on Windows. The workflow tests
and builds the tagged source with `packaging/build.ps1`, creates the GitHub release, and
attaches both the installer and the portable ZIP described above. It also renders the main
window with deterministic demo traffic (`packaging/make_screenshot.py`), uploads
`screenshot.png`, and embeds it in the release notes. The README image shows the latest
release's screenshot; none of these generated files need to be committed to Git.

Before creating a tag, set the same version in `pyproject.toml` and
`src/syslog_monitor/__init__.py` (for example, `1.2.3` for tag `v1.2.3`). The workflow
fails before building if they do not match. It can also be started manually for an
existing tag. On a rerun, an existing screenshot is replaced, but existing installer and
portable ZIP assets are kept; delete an asset from the release first if it should be
rebuilt and uploaded again. For older tags without the screenshot script, the current
workflow supplies it while rendering the tagged application.

To render a screenshot locally, run `python packaging\make_screenshot.py`
(output: `dist\screenshot.png`).

## Usage

| Control | Function |
|---|---|
| **Receive** | Toggle all enabled UDP, TCP, and TLS listeners. Previously stored data is retained. |
| **Live** | New messages appear at the top. Pausing freezes only the view; receiving and storage continue. Scrolling down automatically pauses live updates. |
| **Clear view** | Button beside the time range or **Ctrl+L**. Sets the custom range start to the current time and enables Live. The table, minimap, counters, and search then show only new messages, and the toolbar displays the start time. **No data is deleted.** Choose another range or uncheck “From” to show older messages again. |
| **Time range** | Above the minimap, beside “Reset zoom.” Choose 15 minutes through 30 days, “All,” or **“From / To…”**. Either date/time boundary is optional: From only shows messages from that time through now (including live updates); To only shows messages up to the selected time. To includes the displayed second. If From is later than To, the values are corrected automatically. Switching to a custom range uses the current range as its initial value. The range applies to the table, search, and minimap. The minimap fits the actual data range within the selected bounds. |
| **Search** | Field below the filters. **Enter/F3** or “▼ Older” moves to the next older match; **Shift+F3** or “▲ Newer” moves to the next newer match. **Ctrl+F** focuses the field. Search starts at the newest match, selects the matching row, and shows surrounding messages even if they do not match the query. It searches beyond the currently loaded table page. Active filters and time range still apply; search does not affect the minimap. Searching pauses the view, but receiving and storage continue. At the end, “No more matches” is shown; results do not wrap around. |
| **Severity** | Click a group in the colored legend to show only that group: Error, Warning, Info, Debug, or Unknown. Click the only selected group again or click “All” to reset the severity filter. Ctrl+click adds or removes groups. Info includes Notice and Info; Error includes Emergency through Error. Active groups are bold. Counts reflect the active filters. The severity menu also provides individual severities and presets. |
| **Facility** | Separate selector, in addition to severity and text rules. |
| **Filter rules** | Add rules for text, message, sender/IP, host, or application using contains, does not contain, equals, or does not equal. For “Text (all fields),” “contains all words” and its negative form are also available. Rules appear as compact summaries; click the pencil to edit a rule. Combine rules using AND or OR; non-matching messages are hidden. |
| **Select / copy** | Shift+click selects a range; Ctrl+click selects individual rows. Ctrl+A selects all currently loaded rows; Ctrl+C copies the selection. Right-click the table to see these shortcuts in the context menu. Selecting multiple rows automatically pauses Live. |
| **Table columns** | Right-click the table header to show or hide columns. At least one column stays visible, and your selection is saved. |
| **Zoom** | **Ctrl++** / **Ctrl+-** or **Ctrl+mouse wheel** zooms the interface from 75% to 200%; **Ctrl+0** resets to 100%. The zoom level is saved. |
| **Language** | On first launch, the application detects German from the system locale and otherwise defaults to English. Choose English or German in **Settings > Language** to override it; changes take effect after restarting. |
| **About** | Open **About…** from the toolbar for the app version, runtime details, license, and project links. |
| **Minimap** | Stacked bars per time bucket (red = errors, orange = warnings, etc.) with a red error strip above. The gray band marks the time span of the currently visible table rows and follows scrolling and resizing. With sparse data, the range is automatically narrowed and padded around existing messages. The displayed range appears in the header. **Click** to jump to a time. **Drag** to zoom to a selected range; “Reset zoom” restores automatic scaling. Tooltips show counts and milliseconds. |
| **Details** | Shows all fields of the selected row, including raw data and parser notes. |
| **F5** | Reload the current view and go to the latest messages matching the active filters and time range. |
| **Close button** | Minimizes the window to the tray; receiving continues. Quit using the “Quit” menu item or tray menu. |

### Syslog reception

In **Settings**, enable any combination of UDP, TCP, and TLS, and configure their ports
separately. UDP remains enabled on port 514 by default; TCP and TLS are disabled by
default and default to ports 514 and 6514 when enabled. UDP may share a port number
with TCP or TLS, but TCP and TLS need different ports and must not conflict with
another TCP service such as the MCP server. All listeners share the IPv4 listen address. Changes apply immediately while receiving. If one
listener cannot start, the error is displayed and any other working listener continues
to receive. All transports use the same parser and database; the transport is
not recorded separately for each stored message.

TCP accepts multiple persistent connections and RFC 6587 octet-counted frames, as well
as messages delimited by LF, CRLF, or NUL. Octet counts refer to bytes, so embedded
newlines and multibyte UTF-8 work correctly. An unterminated final line is accepted on
a clean connection close; an incomplete octet-counted frame is discarded. TCP messages
are limited to 1 MiB and 128 clients may be connected at once. Oversized or incomplete
frames are counted as dropped, and rejected connections are counted separately in the
status bar. Both are recorded in the application log.

TLS implements RFC 5425 (syslog over TLS) with TLS 1.2 or later and uses the same
framing and limits as TCP, so octet-counted frames (as required by RFC 5425) and
LF-delimited messages both work. Configure:

- **TLS certificate:** PEM file with the server certificate, optionally followed by
  intermediate certificates and the private key.
- **TLS private key:** PEM file with the unencrypted private key; leave empty if the key
  is in the certificate file. Password-protected keys are not supported.
- **Client CA (optional):** PEM file with one or more CA certificates. When set, every
  device must present a client certificate signed by one of these CAs (mutual TLS);
  otherwise, any client may connect.

The files are checked when the settings are saved and loaded again whenever the TLS
listener starts; after renewing a certificate, toggle **Receive** off and on. A TLS
handshake must complete within 10 seconds. Failed or timed-out handshakes, for example
plaintext senders or clients with untrusted certificates, are counted in the status bar
and logged. Devices must trust the server certificate (or its CA) and should verify that
its name matches the host name or IP address they connect to.

TLS connections use `close_notify` for an orderly shutdown. If a connection ends without
it, any unterminated message is discarded and counted as a framing drop; complete frames
received before the disconnect are processed normally.

For a quick test certificate (for example with OpenSSL):

```powershell
openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=syslog.example" `
  -addext "subjectAltName=DNS:syslog.example,IP:192.0.2.10" -keyout server.key -out server.crt
```

UDP and plain TCP syslog are **unencrypted and unauthenticated**. Only enable them on
trusted networks and restrict firewall access to known senders.

### Colors and highlights

**Settings > Appearance** offers **System** (default), **Light**, and **Dark**.
The selection is saved and applies immediately, without restarting reception.
Dark mode also adapts severity rows, table headers, scrollbars, filter panels,
dialogs, status text, and the minimap, including when switching an open window.
On Windows, the title bars follow the selected appearance as well (Qt/PySide6 6.8
or later). Custom highlight colors retain their contrast-aware text.

The gray background band spans the oldest through newest selected messages.
A translucent gray band independently marks the currently visible table time span.

Info/Notice rows are light blue; Debug rows are light gray. Their minimap bars are blue
and gray respectively. A scrollable **Highlight** panel appears to the right of the
filters. Rules appear as color-outlined text rows. Select a rule and use the pencil to
edit its text, color, enabled state, priority, or popup setting. The **×** on each
highlight or filter chip removes that rule. Use the panel's **▲ / ▼**
controls to step to newer or older messages matching the selected rule. Drag the divider
to adjust the width of the two panels. Highlights never hide messages. Text color is
chosen for contrast with the background.

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
enabled state are saved. Popup notifications can be enabled separately for each rule.
Existing highlight text is migrated as a purple rule when upgrading.

**New-highlight popups:** For each highlight rule, enable “Popup” in its editor to show
a Windows notification when a newly received message matches that rule, even if the
window is minimized to the tray and regardless of filters or Live pause. Existing
messages do not trigger a notification at startup. Notifications are grouped (at most
one every 10 seconds) and include up to the three newest messages and the total count.
Click a notification to open the window.

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

### Export

Use **Export...** in the toolbar to save **CSV** or **JSONL**. The period dropdown offers:

- **Since last reboot (per sender)** (default): from the newest stored boot-marker
  message for each source IP, including that message. Configure **Settings > Boot marker**
  (default `Initializing system`; multiple literal, ASCII-case-insensitive texts separated
  by `;`). This means the sending device's reboot, not a restart of the monitor or PC.
  Senders without a retained boot marker are excluded and their number is reported.
  If no boot marker is found at all, the export reports an error instead of silently
  choosing another period.
- **Last 24 hours**: a fixed window ending when the export starts.
- **From / To**: a custom local date/time range, including the displayed end second.

By default, all senders and severities are exported. Enable **Apply current severity,
facility and filter rules** to narrow the data; this does not apply the main window's
time range, minimap zoom, search navigation, highlights, or table selection.

Use **Columns to export** to select the fields for either format; at least one column
must remain selected. The default is a compact log export: **reception time,
facility, severity, hostname, application, and message**. Source IP, IDs, source port, syslog format,
parse issues, reported timestamps, process/message IDs, structured data, and raw packet
data are unchecked by default and can be enabled individually.
Enable **raw_base64 (original packet)** only when you need the original bytes.
Unchecked fields are omitted entirely from both the CSV header and JSONL objects.

Available fields include the ID, reception timestamp, source IP/port, facility and severity
names (for example `local0` and `Warning`), syslog format, parse issues, reported timestamps, hostname, application, process ID,
message ID, structured data, full message, and original packet bytes encoded as
`raw_base64`. Timestamps are ISO 8601 UTC; rows are ordered oldest first by reception
time and ID. CSV uses comma separators, standard quoting, and UTF-8 with a BOM for
spreadsheet compatibility. Formula-like text is prefixed with an apostrophe to prevent
spreadsheet execution. JSONL has one JSON object per line, preserves message text exactly,
and represents missing values as `null` (CSV uses empty cells).

Exports stream a consistent snapshot of committed database records in the background,
without the table's 5,000-row limit. Receiving continues; messages committed after the
snapshot starts are not included. Retention may already have removed older data. Long
exports may temporarily increase SQLite WAL disk usage while the snapshot is held.
Cancel or close the export dialog to stop. A destination file is replaced only after
successful completion; errors or cancellation leave an existing destination unchanged.

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
messages are truncated. The receiver status includes the active protocol/address
pairs; its existing `address` field remains the UDP address when UDP is active.

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

- Under network load or when the socket buffer is full, UDP can lose packets without the
  receiver detecting it.
- UDP and TCP syslog are neither encrypted nor authenticated; messages and sender
  addresses can be forged. Use only on trusted networks and restrict firewall access to the required
  senders.
- The application does not encrypt the local SQLite database. Protect operating-system
  access to the data and backups accordingly.
- Only IPv4 bind addresses are supported.
- The parser tolerates RFC 5424/3164. Non-conforming messages are still stored and
  marked with a parser note.
- Messages are sorted by reception time (newest first), not by the sender's timestamp.
- Substring search is case-insensitive only for ASCII characters (`café` and `cafe` differ).
  Word search does not have this limitation.
- If the receive queue fills (20,000 messages), UDP or TCP messages are dropped and
  counted in the status bar; TCP and TLS senders are not notified of these application-level drops.
- TLS without a client CA encrypts the connection but does not authenticate senders.

## Architecture

```text
src/syslog_monitor/
  events.py      Data model and severity classes
  parser.py      RFC 5424/3164 parser (pure, no I/O)
  receiver.py    UDP, TCP, and TLS receiver threads → queue
  writer.py      Batch writer thread, retention/budget, retries
  storage.py     SQLite schema, migrations, deletion logic
  query.py       Read queries, filters → SQL, histogram
  export.py      Snapshot-based, streaming CSV/JSONL export
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
pytest -q                          # unit, offscreen GUI, real UDP/TCP/TLS, and MCP-over-HTTP tests
$env:SYSLOG_MONITOR_SLOW_TESTS = 1  # enable load tests (~3.5 minutes)
pytest -q -m slow
```

GitHub Actions runs the non-slow tests on Windows with Python 3.11 and 3.15, and
builds and verifies the installer and portable ZIP with Python 3.15 for pushes to
`main` and pull requests targeting `main` ([workflow](.github/workflows/ci.yml)).
After the first successful run, a repository administrator can use **Settings >
Branches > Add branch protection rule** for `main`, enable **Require status checks
to pass before merging**, and select **Windows tests (Python 3.11)**. Slow tests
remain opt-in and are not run in CI. The Python 3.11 test remains the required check;
the Python 3.15 tests and packaging job provide additional compatibility coverage.

Load tests exercise 2.6 million messages, query performance, retention on a large data
set, and live UDP reception. A multi-day soak test is not automated. Before production
use, run the application with real sources for several days and monitor the status bar
and `logs\`.
