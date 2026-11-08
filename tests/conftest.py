import datetime
import ipaddress
import os
import socket
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from syslog_monitor.events import SyslogEvent  # noqa: E402
from syslog_monitor.storage import EventStore  # noqa: E402

BASE_MS = 1_760_000_000_000  # fixed reference time for deterministic tests


def make_event(offset_ms: int = 0, *, severity: int | None = 6, message: str = "hello world",
               source_ip: str = "192.0.2.1", hostname: str | None = "host1",
               app_name: str | None = "app", facility: int | None = 1) -> SyslogEvent:
    return SyslogEvent(
        received_at=BASE_MS + offset_ms,
        source_ip=source_ip,
        source_port=514,
        raw=message.encode(),
        message=message,
        format="rfc5424",
        severity=severity,
        facility=facility,
        hostname=hostname,
        app_name=app_name,
    )


@pytest.fixture
def store(tmp_path: Path):
    s = EventStore(tmp_path)
    yield s
    s.close()


@pytest.fixture
def window(qtbot, tmp_path):
    from PySide6.QtCore import QSettings

    from syslog_monitor.config import Settings
    from syslog_monitor.service import CaptureService
    from syslog_monitor.ui.main_window import MainWindow
    from syslog_monitor.writer import WriterTuning
    from ui_test_helpers import FAST, isolated_firewall_checker

    service = CaptureService(tmp_path / "data", Settings(bind_host="127.0.0.1", port=0),
                             tuning=WriterTuning(flush_interval_s=0.05))
    assert service.start_listener()
    win = MainWindow(service, settings_path=tmp_path / "settings.json",
                     ui_state=QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat),
                     tray_enabled=False, timings=FAST, firewall_checker=isolated_firewall_checker)
    qtbot.addWidget(win)
    win.show()
    yield win
    win.shutdown()
    service.shutdown()


def send_udp(port: int, *payloads: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for payload in payloads:
            sock.sendto(payload, ("127.0.0.1", port))


def _write_cert(directory: Path, name: str, common_name: str, *, issuer=None, ca: bool = False,
                password: bytes | None = None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer_cert, issuer_key = issuer if issuer else (None, key)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(issuer_cert.subject if issuer_cert else subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                              critical=False))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    cert = builder.sign(issuer_key, hashes.SHA256())
    encryption = (serialization.BestAvailableEncryption(password) if password
                  else serialization.NoEncryption())
    cert_path, key_path = directory / f"{name}.crt", directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8, encryption))
    return cert, key, cert_path, key_path


@pytest.fixture(scope="session")
def tls_certs(tmp_path_factory):
    """CA-signed server and client certificates plus an untrusted client certificate."""
    pytest.importorskip("cryptography")
    directory = tmp_path_factory.mktemp("tls")
    ca_cert, ca_key, ca_path, _ = _write_cert(directory, "ca", "Test CA", ca=True)
    _, _, server_cert, server_key = _write_cert(directory, "server", "localhost", issuer=(ca_cert, ca_key))
    _, _, client_cert, client_key = _write_cert(directory, "client", "device", issuer=(ca_cert, ca_key))
    _, _, rogue_cert, rogue_key = _write_cert(directory, "rogue", "rogue")
    _, _, locked_cert, locked_key = _write_cert(directory, "locked", "localhost", issuer=(ca_cert, ca_key),
                                                password=b"secret")
    combined = directory / "combined.pem"
    combined.write_bytes(server_cert.read_bytes() + server_key.read_bytes())
    return SimpleNamespace(ca=str(ca_path), server_cert=str(server_cert), server_key=str(server_key),
                           combined=str(combined), client_cert=str(client_cert), client_key=str(client_key),
                           rogue_cert=str(rogue_cert), rogue_key=str(rogue_key),
                           locked_cert=str(locked_cert), locked_key=str(locked_key))


def tls_client_context(certs, client: str | None = None):
    import ssl
    context = ssl.create_default_context(cafile=certs.ca)
    if client:
        context.load_cert_chain(getattr(certs, f"{client}_cert"), getattr(certs, f"{client}_key"))
    return context
