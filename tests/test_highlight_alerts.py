from syslog_monitor.query import EventRow, HighlightBatch
from syslog_monitor.ui.highlight_alerts import HighlightAlerter


def row(i, message="Initializing system"):
    return EventRow(i, 1_700_000_000_000 + i, "192.0.2.1", 1, 7, f"plc-{i}", "app", None, message, "")


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def test_alerts_are_aggregated_and_rate_limited():
    shown, clock = [], Clock()
    alerts = HighlightAlerter(lambda t, b: shown.append((t, b)), min_interval_s=10, clock=clock)
    assert not alerts.flush()
    alerts.add(HighlightBatch(1, 1, [row(1)]))
    assert alerts.flush()
    assert shown[0][0] == "Highlight: 1 new message"
    assert "plc-1: Initializing system" in shown[0][1]

    clock.now += 2
    alerts.add(HighlightBatch(5, 4, [row(5), row(4), row(3)]))
    alerts.add(HighlightBatch(7, 2, [row(7, "x " * 200), row(6)]))
    assert not alerts.flush() and alerts.pending == 6
    clock.now += 10
    assert alerts.flush()
    title, body = shown[1]
    assert title == "Highlight: 6 new messages"
    lines = body.splitlines()
    assert [line.split()[1] for line in lines[:3]] == ["plc-7:", "plc-6:", "plc-5:"]
    assert lines[0].endswith("…") and len(lines[0]) < 150
    assert lines[-1] == "… and 3 more"
    assert alerts.pending == 0 and not alerts.flush()


def test_disabled_or_cleared_alerts_show_nothing():
    shown = []
    alerts = HighlightAlerter(lambda t, b: shown.append(t))
    alerts.enabled = False
    alerts.add(HighlightBatch(1, 1, [row(1)]))
    alerts.enabled = True
    alerts.add(HighlightBatch(2, 0, []))
    assert not alerts.flush()
    alerts.add(HighlightBatch(3, 1, [row(3)]))
    alerts.clear()
    assert not alerts.flush() and shown == []
