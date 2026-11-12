import json
import socket

import pytest

from syslog_monitor import tls_test
from syslog_monitor.config import load_settings
from syslog_monitor.service import CaptureService
from syslog_monitor.writer import WriterTuning


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("mtls", [False, True])
def test_setup_then_check_receives_a_message_over_tls(tmp_path, capsys, mtls):
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    (config_dir / "settings.json").write_text(json.dumps({"bind_host": "127.0.0.1", "port": free_port()}))
    port = free_port()
    args = ["--config-dir", str(config_dir), "setup", "--name", "127.0.0.1", "--port", str(port)]
    assert tls_test.main(args + (["--mtls"] if mtls else [])) == 0
    settings = load_settings(config_dir / "settings.json")
    assert settings.tls_enabled and settings.tls_port == port and settings.port != 514
    assert bool(settings.tls_ca_file) == mtls
    assert (config_dir / "settings.json.bak").exists()
    snippet = (config_dir / "tls-test" / "rsyslog-tls.conf").read_text()
    assert 'target="127.0.0.1"' in snippet and ("client.key" in snippet) == mtls
    names = {path.name for path in (config_dir / "tls-test").iterdir()}
    assert {"ca.crt", "ca.der", "ca.cer", "server.crt", "server.key", "server-chain.crt"} <= names
    assert ({"client.crt", "client.key", "client.p12"} <= names) == mtls
    from cryptography import x509
    assert x509.load_der_x509_certificate((config_dir / "tls-test" / "ca.der").read_bytes())
    if mtls:
        from cryptography.hazmat.primitives.serialization import pkcs12
        bundle = pkcs12.load_pkcs12((config_dir / "tls-test" / "client.p12").read_bytes(), None)
        assert bundle.key is not None and len(bundle.additional_certs) == 1

    service = CaptureService(settings.resolved_data_dir(config_dir), settings,
                             tuning=WriterTuning(flush_interval_s=0.05))
    try:
        assert service.start_listener()
        assert tls_test.main(["--config-dir", str(config_dir), "check", "--timeout", "10"]) == 0
    finally:
        service.shutdown()
    assert "TLS syslog works" in capsys.readouterr().out


def test_check_rejects_a_server_with_an_unknown_certificate(tmp_path, capsys):
    config_dir = tmp_path / "cfg"
    other = tmp_path / "other"
    port = free_port()
    for directory in (config_dir, other):
        directory.mkdir()
        (directory / "settings.json").write_text(json.dumps({"bind_host": "127.0.0.1", "port": free_port()}))
        tls_test.main(["--config-dir", str(directory), "setup", "--name", "127.0.0.1", "--port", str(port)])
    settings = load_settings(other / "settings.json")
    service = CaptureService(settings.resolved_data_dir(other), settings)
    try:
        assert service.start_listener()
        assert tls_test.main(["--config-dir", str(config_dir), "check", "--timeout", "1"]) == 1
    finally:
        service.shutdown()
    assert "server certificate rejected" in capsys.readouterr().out


def test_create_certificates_supports_key_types(tmp_path):
    import ssl
    from syslog_monitor.tls_test import KEY_TYPES, create_certificates

    for key_type in KEY_TYPES:
        if key_type == "rsa-4096":
            continue
        paths = create_certificates(tmp_path / key_type, ["127.0.0.1"], mtls=True, days=5, key_type=key_type)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(paths["server_chain"], paths["server_key"])
        context.load_verify_locations(paths["ca_crt"])
