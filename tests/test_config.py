import json
from dataclasses import replace
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


def test_listener_defaults_migration_validation_and_roundtrip(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"bind_host": "127.0.0.1", "port": 5514}))
    old = load_settings(path)
    assert (old.udp_enabled, old.tcp_enabled, old.tcp_port) == (True, False, 514)
    assert old.listener_endpoints == (("UDP", 5514),)

    both = Settings(port=5514, tcp_enabled=True, tcp_port=6514)
    assert both.validate() == []
    assert both.listener_endpoints == (("UDP", 5514), ("TCP", 6514))
    save_settings(path, both)
    assert load_settings(path) == both
    assert Settings(udp_enabled=False, tcp_enabled=True).listener_endpoints == (("TCP", 514),)
    assert "Enable at least one UDP, TCP or TLS listener." in Settings(udp_enabled=False).validate()
    assert Settings(tcp_port=0).validate() == ["TCP port must be between 1 and 65535."]
    assert Settings(tcp_port="514").validate() == ["TCP port must be between 1 and 65535."]
    assert Settings(tcp_enabled="false").validate() == ["UDP, TCP and TLS enabled settings must be true or false."]

    path.write_text(json.dumps({"tcp_enabled": "false"}))
    assert load_settings(path) == Settings()


def test_default_config_dir_uses_local_appdata(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    path = default_config_dir()
    assert path == tmp_path / "SyslogMonitor"
    assert not path.exists()


def test_default_config_dir_uses_home_without_local_appdata(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert default_config_dir() == tmp_path / ".local" / "share" / "SyslogMonitor"


def test_tls_settings_defaults_validation_and_roundtrip(tmp_path):
    defaults = Settings()
    assert (defaults.tls_enabled, defaults.tls_port, defaults.tls_files) == (False, 6514, ("", "", ""))
    assert Settings(tls_port=0).validate() == ["TLS port must be between 1 and 65535."]
    assert Settings(tls_enabled=True).validate() == ["TLS needs a certificate file."]
    assert Settings(tls_enabled=True, tls_cert_file="  ").validate() == ["TLS needs a certificate file."]
    assert Settings(tls_cert_file=None).validate() == ["TLS file settings must be text."]
    assert Settings(tls_enabled="yes").validate() == ["UDP, TCP and TLS enabled settings must be true or false."]

    tls_only = Settings(udp_enabled=False, tls_enabled=True, tls_cert_file="server.crt")
    assert tls_only.validate() == []
    assert tls_only.listener_endpoints == (("TLS", 6514),)
    clash = Settings(tcp_enabled=True, tcp_port=6514, tls_enabled=True, tls_cert_file="server.crt")
    assert clash.validate() == ["TCP and TLS listeners need different ports."]
    assert replace(clash, tcp_enabled=False).validate() == []
    all_three = replace(clash, tcp_port=1514, tls_key_file="server.key", tls_ca_file="ca.pem")
    assert all_three.listener_endpoints == (("UDP", 514), ("TCP", 1514), ("TLS", 6514))
    assert all_three.tls_files == ("server.crt", "server.key", "ca.pem")

    path = tmp_path / "settings.json"
    save_settings(path, all_three)
    assert load_settings(path) == all_three
