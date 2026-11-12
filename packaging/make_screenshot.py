"""Render demo screenshots of the main window, menus, and dialogs.

The release workflow attaches the images to the release; the README gallery
links to these assets. Use the native Qt platform plugin: on Windows
the ``offscreen`` plugin has no fonts and renders every glyph as a box.
"""

from __future__ import annotations

import argparse
import io
import random
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from PySide6.QtCore import QBuffer, QDeadlineTimer, QEvent, QIODevice, QLocale, QPoint, QPointF, QRectF, QSettings, Qt  # noqa: E402
from PySide6.QtGui import QColor, QFont, QImage, QPainter  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
from shiboken6 import delete  # noqa: E402

from syslog_monitor.config import Settings  # noqa: E402
from syslog_monitor.firewall import FirewallCheck, Level  # noqa: E402
from syslog_monitor.i18n import set_language  # noqa: E402
from syslog_monitor.parser import parse_datagram  # noqa: E402
from syslog_monitor.query import FilterRule, HighlightRule  # noqa: E402
from syslog_monitor.service import CaptureService  # noqa: E402
from syslog_monitor.storage import EventStore  # noqa: E402
from syslog_monitor.ui.main_window import MainWindow  # noqa: E402

HOUR_MS = 3_600_000
SPAN_MS = 20 * HOUR_MS  # inside the default "24 hours" range
HIGHLIGHT_TEXT = "link down"

# (ip, hostname, app, facility, rfc5424, [(weight, severity, message template)])
DEVICES = (
    ("192.168.10.1", "gw-router", "kernel", 0, False, [
        (6, 6, "eth1: rx {n} packets, tx {m} packets"),
        (3, 5, "DHCPACK(br0) 192.168.10.{h} 3c:52:82:{h:02x}:1f:0a sensor-{h}"),
        (1, 4, "nf_conntrack: table usage {p}%"),
    ]),
    ("192.168.10.2", "core-switch", "lldpd", 3, False, [
        (5, 6, "port Gi1/0/{port}: neighbor plc-{port} refreshed"),
        (2, 5, "STP: port Gi1/0/{port} transitioned to forwarding"),
    ]),
    ("192.168.10.20", "plc-line1", "control", 16, True, [
        (8, 6, "cycle time {ms} ms, jitter {j} us"),
        (3, 7, "io-scan slot {port}: inputs=0x{n:04x}"),
        (1, 4, "cycle time {ms2} ms exceeds budget"),
    ]),
    ("192.168.10.31", "cam-gate", "streamd", 17, True, [
        (4, 6, "stream main: {fps} fps, bitrate {kbps} kbit/s"),
        (1, 4, "rtsp client 192.168.10.{h} reconnected"),
    ]),
    ("192.168.10.45", "sensor-hub", "telemetry", 18, True, [
        (5, 6, "temperature={t:.1f}C humidity={rh}%"),
        (1, 7, "mqtt publish qos1 mid={n}"),
    ]),
)

# (offset from start in hours, duration in minutes, host index, severity, message)
INCIDENTS = (
    (4.5, 12, 2, 3, "fieldbus timeout on node 7, retry {n}"),
    (11.0, 6, 1, 3, "Gi1/0/12 link down, err-disable (bpduguard)"),
    (11.1, 6, 2, 2, "watchdog: control task missed deadline"),
    (17.25, 20, 3, 4, "frame drops detected: {fps} fps"),
    (18.0, 3, 0, 3, "WAN link down, failover to LTE"),
)


def _values(rng: random.Random) -> dict[str, object]:
    return {"n": rng.randrange(1, 60_000), "m": rng.randrange(1, 60_000), "h": rng.randrange(50, 200),
            "p": rng.randrange(20, 70), "port": rng.randrange(1, 24), "ms": rng.randrange(8, 11),
            "ms2": rng.randrange(14, 25), "j": rng.randrange(20, 400), "fps": rng.randrange(18, 31),
            "kbps": rng.randrange(3500, 6000), "t": rng.uniform(20.5, 27.5), "rh": rng.randrange(35, 55)}


def _datagram(device: tuple, severity: int, message: str, ts_ms: int, rng: random.Random) -> bytes:
    _ip, host, app, facility, rfc5424, _ = device
    pri = facility * 8 + severity
    stamp = datetime.fromtimestamp(ts_ms / 1000, timezone.utc)
    if rfc5424:
        iso = stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return f"<{pri}>1 {iso} {host} {app} {rng.randrange(100, 4000)} - - {message}".encode()
    local = datetime.fromtimestamp(ts_ms / 1000)  # RFC 3164 senders typically use local time
    return f"<{pri}>{local:%b} {local.day:2d} {local:%H:%M:%S} {host} {app}: {message}".encode()


def demo_datagrams(now_ms: int, seed: int = 1) -> list[tuple[str, int, bytes]]:
    """(source_ip, received_at, payload) tuples covering the last ``SPAN_MS``, oldest first."""
    rng = random.Random(seed)
    start = now_ms - SPAN_MS
    out: list[tuple[str, int, bytes]] = []
    ts = start
    while ts < now_ms - 60_000:  # the curated tail below forms the newest rows
        # busier during "working hours" of the demo span for a lively minimap
        ts += rng.randrange(8_000, 40_000 if (ts - start) % (8 * HOUR_MS) < 5 * HOUR_MS else 70_000)
        device = rng.choice(DEVICES)
        _w, severity, template = rng.choices(device[5], weights=[t[0] for t in device[5]])[0]
        out.append((device[0], ts, _datagram(device, severity, template.format(**_values(rng)), ts, rng)))
    for hours, minutes, index, severity, template in INCIDENTS:
        begin = start + int(hours * HOUR_MS)
        for _ in range(rng.randrange(25, 45)):
            ts = begin + rng.randrange(0, minutes * 60_000)
            device = DEVICES[index]
            out.append((device[0], ts, _datagram(device, severity, template.format(**_values(rng)), ts, rng)))
    # the newest messages (visible at the top of the live list) include a highlighted one
    tail = (
        (0, 4, "nf_conntrack: table usage 81%"),
        (1, 3, "Gi1/0/7 link down, cable diagnostics: open pair 2"),
        (2, 6, "cycle time 9 ms, jitter 112 us"),
        (4, 6, "temperature=24.3C humidity=41%"),
    )
    for step, (index, severity, message) in enumerate(tail, start=1):
        ts = now_ms - (len(tail) - step + 1) * 4_000
        out.append((DEVICES[index][0], ts, _datagram(DEVICES[index], severity, message, ts, rng)))
    out.sort(key=lambda item: item[1])
    return out


def fill_store(data_dir: Path, now_ms: int) -> int:
    store = EventStore(data_dir)
    try:
        events = [parse_datagram(payload, ip, 514, ts) for ip, ts, payload in demo_datagrams(now_ms)]
        store.insert(events)
        return len(events)
    finally:
        store.close()


def _wait(app: QApplication, condition, timeout_s: float = 30.0) -> None:
    deadline = QDeadlineTimer(int(timeout_s * 1000))
    while not condition():
        if deadline.hasExpired():
            raise TimeoutError("Window did not finish loading the demo data")
        app.processEvents()
        time.sleep(0.02)


VIEWS = ("main", "columns", "highlights", "settings", "export", "history", "analysis", "similar")
GALLERY = (
    ("light", "light", "main"), ("history", "dark", "history"),
    ("analysis", "light", "analysis"), ("similar", "dark", "similar"),
    ("highlights", "light", "highlights"), ("settings", "dark", "settings"),
)


def _send(port: int, payloads: list[bytes]) -> None:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for payload in payloads:
            sock.sendto(payload, ("127.0.0.1", port))


@contextmanager
def _demo_window(width: int, height: int, theme: str):
    """Main window on a temporary store filled with the demo data, ready for capturing."""
    if theme not in ("system", "light", "dark"):
        raise ValueError(f"Unknown theme: {theme}")
    app = QApplication.instance() or QApplication(sys.argv[:1])
    set_language("en")
    QLocale.setDefault(QLocale(QLocale.Language.English, QLocale.Country.UnitedStates))
    with tempfile.TemporaryDirectory(prefix="syslog-monitor-screenshot-") as tmp:
        tmp_dir = Path(tmp)
        now_ms = time.time_ns() // 1_000_000
        total = fill_store(tmp_dir / "data", now_ms)
        service = CaptureService(tmp_dir / "data", Settings(bind_host="127.0.0.1", port=0, theme=theme))
        service.start_listener()
        window = MainWindow(
            service, settings_path=tmp_dir / "settings.json",
            ui_state=QSettings(str(tmp_dir / "ui.ini"), QSettings.IniFormat), tray_enabled=False,
            firewall_checker=lambda *_args: FirewallCheck(Level.OK, "Firewall allows syslog"))
        try:
            for row in list(window.highlights.rule_rows):
                window.highlights.remove_rule(row)
            window.highlights.add_rule(HighlightRule(HIGHLIGHT_TEXT))
            window.resize(width, height)
            window.show()
            window.refresh_all()
            _wait(app, lambda: window.model.rowCount() > 0 and window.minimap.histogram is not None
                  and window.minimap.histogram.total >= total)
            window.table.selectRow(3)  # the warning below the highlighted message fills the detail pane
            _wait(app, lambda: bool(window.details.toPlainText()))
            _wait(app, lambda: bool(window.inspector.graph.series))
            yield app, window, service
        finally:
            window.close()
            window.shutdown()
            service.shutdown()
            delete(window)


def _settle(app: QApplication, ms: int = 400) -> None:
    deadline = time.monotonic() + ms / 1000
    while time.monotonic() < deadline:
        app.processEvents()
        app.sendPostedEvents(None, QEvent.DeferredDelete)  # removed filter chips must not linger
        time.sleep(0.02)


def render(output: Path, width: int = 1400, height: int = 860, *,
           theme: str = "system", view: str = "main") -> Path:
    if view not in VIEWS:
        raise ValueError(f"Unknown view: {view}")
    with _demo_window(width, height, theme) as (app, window, service):
        overlay = None
        try:
            if view == "highlights":
                window.highlights.edit_rule(window.highlights.rule_rows[0])
            elif view == "columns":
                overlay = window.column_menu
                header = window.table.horizontalHeader()
                overlay.popup(header.mapToGlobal(QPoint(220, header.height())))
            elif view in ("settings", "export"):
                window.sidebar.set_expanded(True)
                window.show_page(view)
            elif view == "history":
                # Scrolled into history: the banner row reports messages above and new arrivals.
                bar = window.table.verticalScrollBar()
                app.processEvents()
                bar.setValue(bar.maximum() // 3)
                scrolled = bar.value() > 0
                rng = random.Random(7)
                late = [(DEVICES[i], sev, msg) for i, sev, msg in (
                    (2, 6, "cycle time 9 ms, jitter 87 us"), (4, 6, "temperature=24.4C humidity=41%"),
                    (0, 6, "eth1: rx 5120 packets, tx 4980 packets"))]
                now = time.time_ns() // 1_000_000
                _send(service.bound_port, [_datagram(device, sev, msg, now, rng) for device, sev, msg in late])
                if scrolled:
                    _wait(app, lambda: (window.newer_banner.new or 0) >= len(late))
                window.table.selectRow(window.table.rowAt(window.table.viewport().height() // 2))
            elif view == "analysis":
                from syslog_monitor.analysis import MODE_SIMILAR

                window.show_page("analysis")
                page = window._analysis_page
                page.similarity.setValue(60)
                page.mode.setCurrentIndex(page.mode.findData(MODE_SIMILAR))
                page.analyze()
                _wait(app, lambda: page.report is not None and page.report.mode == MODE_SIMILAR
                      and page.report.similarity == 0.6 and not page.busy)
            elif view == "similar":
                from syslog_monitor.ui.message_inspector import MODE_SIMILAR

                window.table.selectRow(1)
                window.inspector.set_mode(MODE_SIMILAR)
                window.inspector.set_similarity(0.75)
                _wait(app, lambda: window.inspector._stats is not None
                      and window.inspector._stats.similarity == 0.75 and window.inspector.common.text())
            _settle(app, 400)
            output.parent.mkdir(parents=True, exist_ok=True)
            image = window.grab()
            if overlay is not None:
                painter = QPainter(image)
                try:
                    position = window.mapFromGlobal(overlay.mapToGlobal(QPoint(0, 0)))
                    painter.drawPixmap(position, overlay.grab())
                finally:
                    painter.end()
            if not image.save(str(output), "PNG"):
                raise OSError(f"Could not write {output}")
        finally:
            if overlay is not None:
                overlay.close()
    return output


def _caption(image: QImage, text: str) -> QImage:
    """Draws a centered caption near the bottom so viewers know what the scene shows."""
    painter = QPainter(image)
    try:
        painter.setRenderHint(QPainter.Antialiasing)
        font = QFont(painter.font())
        font.setPixelSize(max(18, image.height() // 34))
        font.setBold(True)
        painter.setFont(font)
        metrics = painter.fontMetrics()
        box = QRectF(0, 0, metrics.horizontalAdvance(text) + 2 * metrics.height(), metrics.height() * 1.9)
        box.moveCenter(QPointF(image.width() / 2, image.height() * 0.62))  # over the table, not the details
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(20, 24, 32, 215))
        painter.drawRoundedRect(box, box.height() / 2, box.height() / 2)
        painter.setPen(QColor("white"))
        painter.drawText(box, Qt.AlignCenter, text)
    finally:
        painter.end()
    return image


def _to_pil(image: QImage):
    from PIL import Image

    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    return Image.open(io.BytesIO(bytes(buffer.data()))).convert("RGB")


def render_demo(output: Path, width: int = 1400, height: int = 860, *, theme: str = "light") -> Path:
    """Animated tour through live view, filter, search, similar messages and analysis as a GIF."""
    from PIL import Image

    frames: list[tuple[QImage, int]] = []
    with _demo_window(width, height, theme) as (app, window, service):
        def snap(duration_ms: int, caption: str) -> None:
            _settle(app, 250)
            frames.append((_caption(window.grab().toImage(), caption), duration_ms))

        live = "Live view: messages arrive over UDP, TCP or TLS"
        snap(1600, live)
        rng = random.Random(11)
        for batch in range(4):
            rows = window.model.rowCount()
            now = time.time_ns() // 1_000_000
            payloads = [_datagram(DEVICES[(batch + i) % len(DEVICES)], sev, msg, now, rng) for i, (sev, msg) in
                        enumerate(((6, f"cycle time {8 + batch} ms, jitter {70 + 9 * batch} us"),
                                   (4, f"rtsp client 192.168.10.{60 + batch} reconnected"),
                                   (6, f"temperature={23.5 + batch / 3:.1f}C humidity={40 + batch}%")))]
            _send(service.bound_port, payloads)
            _wait(app, lambda: window.model.rowCount() >= rows + len(payloads))
            snap(650, live)

        window.filter_bar.set_severities({0, 1, 2, 3, 4})
        _settle(app, 700)
        snap(1300, "Filter: show only warnings and errors")
        row = window.filter_bar.add_rule(FilterRule("message", "contains", "link"))
        _settle(app, 700)
        window.filter_bar.edit_rule(row)
        snap(1900, "Combine filter rules – the minimap follows the filter")
        window.filter_bar.reset()
        _settle(app, 700)

        for count in range(1, len("watchdog") + 1):
            window.search_text.setText("watchdog"[:count])
            _settle(app, 30)
            frames.append((_caption(window.grab().toImage(), "Search jumps to matches and keeps the context"),
                           120))
        window.find_text()
        snap(2000, "Search jumps to matches and keeps the context")

        from syslog_monitor.ui.message_inspector import MODE_SIMILAR as INSPECT_SIMILAR

        window.table.selectRow(1)
        _wait(app, lambda: bool(window.details.toPlainText()))
        window.inspector.set_mode(INSPECT_SIMILAR)
        window.inspector.set_similarity(0.75)
        _wait(app, lambda: window.inspector._stats is not None
              and window.inspector._stats.similarity == 0.75 and window.inspector.common.text())
        snap(2600, "Details: how often similar messages occurred")

        from syslog_monitor.analysis import MODE_SIMILAR

        window.show_page("analysis")
        page = window._analysis_page
        page.similarity.setValue(60)
        page.mode.setCurrentIndex(page.mode.findData(MODE_SIMILAR))
        page.analyze()
        _wait(app, lambda: page.report is not None and page.report.mode == MODE_SIMILAR
              and page.report.similarity == 0.6 and not page.busy)
        snap(2800, "Analysis: the most frequent messages at a glance")

    images = [_to_pil(image).quantize(colors=256, dither=Image.Dither.NONE) for image, _ in frames]
    output.parent.mkdir(parents=True, exist_ok=True)
    images[0].save(output, save_all=True, append_images=images[1:], loop=0,
                   duration=[duration for _, duration in frames], disposal=1)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "screenshot.png")
    parser.add_argument("--width", type=int, default=1400)
    parser.add_argument("--height", type=int, default=860)
    parser.add_argument("--theme", choices=("system", "light", "dark"), default="system")
    parser.add_argument("--view", choices=VIEWS, default="main")
    parser.add_argument("--gallery-dir", type=Path,
                        help="Also render the README gallery views and the animated demo into this directory")
    parser.add_argument("--demo", type=Path, help="Only render the animated demo GIF to this path")
    args = parser.parse_args(argv)
    if args.demo is not None:
        print(render_demo(args.demo, args.width, args.height,
                          theme="light" if args.theme == "system" else args.theme))
        return 0
    print(render(args.output, args.width, args.height, theme=args.theme, view=args.view))
    if args.gallery_dir is not None:
        for name, theme, view in GALLERY:
            print(render(args.gallery_dir / f"screenshot-{name}.png", args.width, args.height,
                         theme=theme, view=view))
        print(render_demo(args.gallery_dir / "screenshot-demo.gif", args.width, args.height))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
