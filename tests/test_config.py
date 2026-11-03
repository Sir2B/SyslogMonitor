import json
from pathlib import Path

from syslog_monitor.config import Settings, default_config_dir, load_settings, save_settings


def test_defaults_are_valid():
    assert Settings().validate() == []
    assert Settings().port == 514


def test_validation_errors():
    bad = Settings(bind_host="::1", port=0, retention_days=0, max_storage_mb=1)
    assert len(bad.validate()) == 4
    assert Settings(bind_host="nonsense").validate()


def test_roundtrip_and_unknown_keys(tmp_path):
    path = tmp_path / "settings.json"
    save_settings(path, Settings(port=5514, retention_days=7))
    data = json.loads(path.read_text())
    data["future_option"] = 1
    path.write_text(json.dumps(data))
    loaded = load_settings(path)
    assert (loaded.port, loaded.retention_days) == (5514, 7)


def test_corrupt_or_invalid_file_falls_back(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{not json")
    assert load_settings(path) == Settings()
    path.write_text(json.dumps({"port": 70000}))
    assert load_settings(path) == Settings()


def test_data_dir_resolution(tmp_path):
    assert Settings().resolved_data_dir(tmp_path) == tmp_path / "data"
    assert Settings(data_dir=str(tmp_path / "x")).resolved_data_dir(tmp_path) == tmp_path / "x"


def test_mcp_defaults_and_validation(tmp_path):
    settings = Settings()
    assert (settings.mcp_enabled, settings.mcp_port, settings.boot_marker) == (True, 8514, "Initializing system")
    assert Settings(mcp_port=0).validate() == ["MCP port must be between 1 and 65535."]
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"port": 5514}))  # file from a version without MCP
    assert load_settings(path).mcp_enabled
    path.write_text(json.dumps({"mcp_port": "x"}))
    assert load_settings(path) == Settings()
    save_settings(path, Settings(mcp_enabled=False, mcp_port=9000, boot_marker="a; b"))
    assert load_settings(path) == Settings(mcp_enabled=False, mcp_port=9000, boot_marker="a; b")


def test_default_config_dir_uses_local_appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    path = default_config_dir()
    assert path == tmp_path / "SyslogMonitor"
    assert not path.exists()


def test_default_config_dir_uses_home_without_local_appdata(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_config_dir() == tmp_path / ".local" / "share" / "SyslogMonitor"
