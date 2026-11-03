"""Tests for packaging/collect_licenses.py (the PyInstaller-specific part is exercised by build.ps1)."""

import importlib.util
from importlib import metadata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def collector():
    spec = importlib.util.spec_from_file_location("collect_licenses", ROOT / "packaging" / "collect_licenses.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_top_level_names(collector):
    assert collector.top_level_names(["uvicorn.protocols.http", "uvicorn", "json", ""]) == {"uvicorn", "json"}


def test_distributions_for_maps_imports_and_skips_own_package(collector):
    mapping = {"PySide6": ["PySide6", "PySide6_Essentials"], "syslog_monitor": ["syslog-monitor"],
               "yaml": ["PyYAML"]}
    result = collector.distributions_for({"PySide6", "syslog_monitor", "json"}, mapping)
    assert result == {"pyside6", "pyside6-essentials"}


def test_qt_distributions_are_recognised(collector):
    for name in ("pyside6", "pyside6-essentials", "pyside6-addons", "shiboken6"):
        assert collector.QT_DISTRIBUTION.match(name)
    assert not collector.QT_DISTRIBUTION.match("pyside6x")


def test_bundled_license_texts_exist(collector):
    for name in collector.QT_LICENSE_FILES:
        text = (collector.EXTRA_TEXTS / name).read_text(encoding="utf-8")
        assert "GENERAL PUBLIC LICENSE" in text
    assert "MIT License" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_copy_distribution_adds_lgpl_texts_for_pyside(collector, tmp_path):
    notice = collector.copy_distribution(metadata.distribution("PySide6"), tmp_path / "licenses")
    names = {Path(f).name for f in notice.files}
    assert {"LGPL-3.0.txt", "GPL-3.0.txt"} <= names
    assert notice.license.startswith("LGPL-3.0-only")
    assert all((tmp_path / f).is_file() for f in notice.files)


def test_copy_distribution_finds_declared_license_file(collector, tmp_path):
    notice = collector.copy_distribution(metadata.distribution("mcp"), tmp_path / "licenses")
    assert notice.files and "MIT" in notice.license


def test_render_notices_lists_every_package(collector):
    notices = [collector.Notice("zeta", "1.0", "MIT", "https://z", ["licenses/zeta/LICENSE"]),
               collector.Notice("Alpha", "2.0", "BSD-3-Clause", "", ["licenses/alpha/COPYING"])]
    text = collector.render_notices("Syslog Monitor", notices)
    assert text.index("Alpha 2.0") < text.index("zeta 1.0")
    assert "licenses/zeta/LICENSE" in text and "LICENSE.txt" in text and "Lesser General Public License" in text
