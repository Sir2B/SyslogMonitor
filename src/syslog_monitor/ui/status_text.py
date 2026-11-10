"""Rich-text snippets for the main window status bar (pure functions, no widgets)."""

from __future__ import annotations

from syslog_monitor.firewall import FirewallCheck, Level
from syslog_monitor.i18n import tr
from syslog_monitor.stats import StatsSnapshot
from syslog_monitor.ui.formatting import format_bytes, format_count
from syslog_monitor.ui.palette import status_color

GREEN, AMBER, RED, GREY = "#1a7f37", "#9a6700", "#b00020", "#666"


def _bold(text: str, color: str) -> str:
    return f"<b style='color:{status_color(color)}'>{text}</b>"


def _span(text: str, color: str) -> str:
    return f"<span style='color:{status_color(color)}'>{text}</span>"


def counters(snap: StatsSnapshot, rates, *, compact: bool) -> tuple[str, str]:
    """(label HTML, plain tooltip) for received/stored/queued counts, rates and losses."""
    counts = tr("Received {received} · stored {stored} · queued {queued}",
                received=format_count(snap.received), stored=format_count(snap.persisted),
                queued=format_count(snap.queued))
    live_rates = tr("Live: {received:.1f}/s received · {stored:.1f}/s stored · {dropped:.1f}/s dropped",
                    received=rates.received, stored=rates.persisted, dropped=rates.dropped)
    text = counts if compact else f"{counts}<br>{_span(live_rates, '#555')}"
    losses = snap.dropped_queue_full + snap.dropped_write_error + snap.dropped_tcp_framing
    if losses:
        text += " · " + _bold(f"{tr('dropped')} {format_count(losses)}", RED)
    if snap.tcp_connections_rejected:
        text += " · " + _bold(f"{tr('TCP connections rejected')} {format_count(snap.tcp_connections_rejected)}", RED)
    if snap.tls_handshake_failures:
        text += " · " + _bold(f"{tr('TLS handshakes failed')} {format_count(snap.tls_handshake_failures)}", AMBER)
    return text, f"{counts}\n{live_rates}"


def storage(snap: StatsSnapshot, max_bytes: int) -> str:
    text = f"DB {format_bytes(snap.storage_bytes)} / {format_bytes(max_bytes)}"
    if snap.writer_error:
        return f"{_bold(snap.writer_error, RED)} · {text}"
    if snap.storage_budget_exceeded:
        return f"{_bold(tr('Budget exceeded'), AMBER)} · {text}"
    return text


def listener(snap: StatsSnapshot, listening: bool) -> str:
    if snap.listener_state == "error":
        text = _bold(snap.listener_error, RED)
        if listening:
            text += f" · {tr('Still receiving on')} {snap.listener_display_address}"
        return text
    if listening:
        return _span(f"{snap.listener_display_address} {tr('active')}", GREEN)
    return _span(tr("Receiving stopped"), GREY)


def firewall(check: FirewallCheck) -> tuple[str, str]:
    """(link HTML, tooltip) for the firewall indicator."""
    text, color = {
        Level.OK: (tr("Firewall ✓"), GREEN),
        Level.WARNING: (tr("⚠ Firewall: port not allowed"), AMBER),
        Level.ERROR: (tr("✖ Firewall blocked"), RED),
        Level.UNKNOWN: (tr("Firewall ?"), GREY),
    }[check.level]
    weight = "bold" if check.level >= Level.WARNING else "normal"
    html = (f"<a href='firewall' style='color:{status_color(color)};font-weight:{weight};"
            f"text-decoration:none'>{text}</a>")
    return html, "\n".join((check.summary, *check.details, tr("Click for details")))


def mcp(service) -> tuple[str, str]:
    """(link HTML, tooltip) for the MCP indicator; ``service`` may be disabled."""
    if service is None or not service.enabled:
        text, color, tip = tr("MCP off"), GREY, tr("MCP server for AI assistants is disabled.")
    elif service.running:
        host = getattr(service, "host", "127.0.0.1")
        local = host.startswith("127.")
        text, color = f"MCP ✓ {'' if local else host}:{service.port}", GREEN
        tip = tr("MCP server (read-only, no authentication): {url}", url=service.url)
        if not local:
            tip += "\n" + tr("Listening on {address} – reachable from the network.",
                              address=f"{host}:{service.port}")
    elif service.starting:
        text, color, tip = "MCP …", GREY, tr("MCP server is starting")
    else:
        text, color, tip = "✖ MCP", RED, service.error
    html = f"<a href='mcp' style='color:{status_color(color)};text-decoration:none'>{text}</a>"
    return html, f"{tip}\n{tr('Click for details')}"


def mode(live: bool) -> tuple[str, str]:
    """(label HTML, tooltip) for the autoscroll state."""
    if live:
        return (f"&nbsp;{_bold('● ' + tr('Autoscroll on'), GREEN)}",
                tr("The newest messages appear at the top."))
    return (f"&nbsp;{_bold('⏸ ' + tr('Autoscroll off'), AMBER)}",
            tr("Autoscroll is off; receiving and storage continue.\n"
               "Use the bar above the table to show the newest messages or enable autoscroll."))
