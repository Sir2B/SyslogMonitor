"""Tests for packaging/make_screenshot.py (used by the release workflow)."""

import importlib.util
from pathlib import Path

import pytest
from PySide6.QtGui import QImage

from syslog_monitor.parser import parse_datagram

ROOT = Path(__file__).resolve().parents[1]
NOW_MS = 1_760_000_000_000


@pytest.fixture(scope="module")
def screenshot():
    spec = importlib.util.spec_from_file_location("make_screenshot", ROOT / "packaging" / "make_screenshot.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_data_is_deterministic_and_realistic(screenshot):
    datagrams = screenshot.demo_datagrams(NOW_MS)
    assert datagrams == screenshot.demo_datagrams(NOW_MS)
    times = [ts for _ip, ts, _payload in datagrams]
    assert times == sorted(times)
    assert NOW_MS - screenshot.SPAN_MS <= times[0] and times[-1] < NOW_MS
    events = [parse_datagram(payload, ip, 514, ts) for ip, ts, payload in datagrams]
    assert not any(event.issues for event in events)
    assert len({event.hostname for event in events}) == len(screenshot.DEVICES)
    severities = {event.severity for event in events}
    assert {2, 3, 4, 5, 6, 7} <= severities
    assert any(screenshot.HIGHLIGHT_TEXT in event.message for event in events[-4:])


def test_render_writes_png_of_requested_size(qapp, screenshot, tmp_path):
    output = screenshot.render(tmp_path / "shot.png", 1200, 760)
    image = QImage(str(output))
    assert not image.isNull()
    ratio = image.devicePixelRatio()
    # Qt's font-less offscreen plugin may force a larger minimum width.
    assert image.width() / ratio >= 1200 and image.height() / ratio == 760
