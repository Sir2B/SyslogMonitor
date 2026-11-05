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


@pytest.mark.parametrize(("theme", "view"), [
    ("system", "main"), ("light", "main"), ("dark", "main"),
    ("dark", "columns"), ("light", "highlights"), ("light", "settings"), ("dark", "export"),
])
def test_render_writes_png_of_requested_size(qapp, screenshot, tmp_path, theme, view):
    height = 860 if view == "settings" else 760
    output = (screenshot.render(tmp_path / "shot.png", 1200, height) if theme == "system"
              else screenshot.render(tmp_path / "shot.png", 1200, height, theme=theme, view=view))
    image = QImage(str(output))
    assert not image.isNull()
    ratio = image.devicePixelRatio()
    # Qt's font-less offscreen plugin may force a larger minimum width.
    assert image.width() / ratio >= 1200 and image.height() / ratio == height


def test_gallery_cli_renders_all_expected_release_assets(screenshot, tmp_path, monkeypatch):
    calls = []

    def render(output, width, height, *, theme, view):
        calls.append((output, theme, view))
        return output

    monkeypatch.setattr(screenshot, "render", render)
    gallery = tmp_path / "screenshots"
    output = tmp_path / "screenshot.png"
    assert screenshot.main(["--output", str(output), "--gallery-dir", str(gallery)]) == 0
    assert calls == [
        (output, "system", "main"),
        (gallery / "screenshot-light.png", "light", "main"),
        (gallery / "screenshot-dark.png", "dark", "main"),
        (gallery / "screenshot-columns.png", "dark", "columns"),
        (gallery / "screenshot-highlights.png", "light", "highlights"),
        (gallery / "screenshot-settings.png", "light", "settings"),
        (gallery / "screenshot-export.png", "dark", "export"),
    ]
