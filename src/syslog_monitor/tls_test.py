"""Set up and verify syslog over TLS end to end (command line).

    python -m syslog_monitor.tls_test setup [--name HOST ...] [--port 6514] [--mtls]
    python -m syslog_monitor.tls_test check [--host 127.0.0.1] [--timeout 15]
    python -m syslog_monitor.tls_test wait  [--token TEXT] [--timeout 120]

``setup`` creates a CA, a server certificate (and with ``--mtls`` a client certificate),
enables the TLS listener in the settings (backup: settings.json.bak) and writes ready-to-use
rsyslog/syslog-ng snippets for the sending device. ``check`` acts as the sending device:
it connects with full certificate and hostname validation, sends one RFC 5425 message
and confirms that Syslog Monitor stored it. ``wait`` waits for a message sent by a real
device (e.g. ``logger <token>``).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import socket
import ssl
import sys
import time
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from syslog_monitor.config import DEFAULT_TLS_PORT, Settings, default_config_dir, load_settings, save_settings
from syslog_monitor.storage import connect, db_path

TLS_DIR_NAME = "tls-test"
DEVICE_DIR = "/etc/syslog-tls"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _san(names: list[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = []
    for name in dict.fromkeys(names):
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name.encode("idna").decode("ascii")))
    return x509.SubjectAlternativeName(entries)


def _issue(subject: str, key, issuer, issuer_key, days: int, *, ca: bool = False,
           usage=None, names: list[str] | None = None):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (x509.CertificateBuilder().subject_name(name)
               .issuer_name(issuer.subject if issuer else name).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                              critical=False))
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        builder = (builder
                   .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False),
                                  critical=True)
                   .add_extension(x509.ExtendedKeyUsage([usage]), critical=False))
        if names:
            builder = builder.add_extension(_san(names), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def local_names() -> list[str]:
    """Names and IPv4 addresses a device may use to reach this computer."""
    names = [socket.gethostname(), socket.getfqdn(), "localhost", "127.0.0.1"]
    try:
        names += [info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
    except OSError:
        pass
    return [name for name in dict.fromkeys(names) if name]


def create_certificates(directory: Path, names: list[str], *, mtls: bool, days: int = 365) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    ca_key = _key()
    ca = _issue("Syslog Monitor test CA", ca_key, None, ca_key, days, ca=True)
    server_key = _key()
    server = _issue(names[0], server_key, ca, ca_key, days, usage=ExtendedKeyUsageOID.SERVER_AUTH, names=names)
    paths = {"ca": directory / "ca.pem", "server": directory / "server.pem"}
    paths["ca"].write_bytes(_pem(ca))
    paths["server"].write_bytes(_pem(server) + _pem(ca) + _pem_key(server_key))
    if mtls:
        client_key = _key()
        client = _issue("syslog-test-client", client_key, ca, ca_key, days,
                        usage=ExtendedKeyUsageOID.CLIENT_AUTH)
        paths["client_cert"] = directory / "client.pem"
        paths["client_key"] = directory / "client.key"
        paths["client_cert"].write_bytes(_pem(client))
        paths["client_key"].write_bytes(_pem_key(client_key))
    return paths


def device_snippets(server: str, port: int, mtls: bool) -> dict[str, str]:
    """rsyslog and syslog-ng forwarding configuration for the files copied to DEVICE_DIR."""
    client = (f'    StreamDriver.CertFile="{DEVICE_DIR}/client.pem"\n'
              f'    StreamDriver.KeyFile="{DEVICE_DIR}/client.key"\n') if mtls else ""
    rsyslog = (
        "# /etc/rsyslog.d/90-syslog-monitor-tls.conf  (needs package rsyslog-gnutls or rsyslog-openssl)\n"
        f'global(DefaultNetstreamDriverCAFile="{DEVICE_DIR}/ca.pem")\n'
        '*.* action(type="omfwd" protocol="tcp" TCP_Framing="octet-counted"\n'
        f'    target="{server}" port="{port}"\n'
        '    StreamDriver="gtls" StreamDriverMode="1"\n'
        f'    StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="{server}"\n'
        f"{client}"
        '    action.resumeRetryCount="-1" queue.type="LinkedList")\n')
    key_options = (f'            cert-file("{DEVICE_DIR}/client.pem")\n'
                   f'            key-file("{DEVICE_DIR}/client.key")\n') if mtls else ""
    syslog_ng = (
        "# /etc/syslog-ng/conf.d/syslog-monitor-tls.conf\n"
        "destination d_syslog_monitor {\n"
        f'    syslog("{server}" transport("tls") port({port})\n'
        "        tls(\n"
        f'            ca-file("{DEVICE_DIR}/ca.pem")\n'
        f"{key_options}"
        "            peer-verify(required-trusted)\n"
        "        )\n"
        "    );\n"
        "};\n"
        "log { source(s_src); destination(d_syslog_monitor); };\n")
    return {"rsyslog-tls.conf": rsyslog, "syslog-ng-tls.conf": syslog_ng}


def setup(config_dir: Path, names: list[str], port: int, mtls: bool, days: int) -> int:
    settings_path = config_dir / "settings.json"
    settings = load_settings(settings_path)
    directory = config_dir / TLS_DIR_NAME
    paths = create_certificates(directory, names, mtls=mtls, days=days)
    new = replace(settings, tls_enabled=True, tls_port=port, tls_cert_file=str(paths["server"]),
                  tls_key_file="", tls_ca_file=str(paths["ca"]) if mtls else "")
    if problems := new.validate():
        print("Cannot apply settings: " + "; ".join(problems), file=sys.stderr)
        return 2
    if settings_path.exists():
        shutil.copyfile(settings_path, settings_path.with_name("settings.json.bak"))
    save_settings(settings_path, new)
    server = names[0]
    for name, text in device_snippets(server, port, mtls).items():
        (directory / name).write_text(text, encoding="utf-8", newline="\n")
    device_files = ["ca.pem"] + (["client.pem", "client.key"] if mtls else [])
    print(f"Certificates and device configuration: {directory}")
    print(f"Server certificate names: {', '.join(names)}")
    print(f"Syslog Monitor: TLS on port {port}" + (", client certificates required" if mtls else ""))
    print("Restart Syslog Monitor so the TLS listener uses the new files (close it before 'setup' "
          "if possible: saving the Settings dialog of a running instance would restore its old values).")
    print("Allow the port in the firewall (elevated PowerShell):")
    print(f"  New-NetFirewallRule -DisplayName 'Syslog Monitor TLS' -Direction Inbound "
          f"-Protocol TCP -LocalPort {port} -Action Allow")
    print(f"Device: copy {', '.join(device_files)} to {DEVICE_DIR}/ and use rsyslog-tls.conf "
          f"or syslog-ng-tls.conf (target {server}; change it if the device uses another of the names).")
    print("Then: python -m syslog_monitor.tls_test check   (built-in client)")
    print("  or: python -m syslog_monitor.tls_test wait    (message from the device)")
    return 0


def _wait_for(settings: Settings, config_dir: Path, token: str, timeout: float):
    path = db_path(settings.resolved_data_dir(config_dir))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            conn = connect(path, readonly=True)
            try:
                row = conn.execute("SELECT source_ip, hostname, message FROM events WHERE message LIKE ? "
                                   "ORDER BY id DESC LIMIT 1", (f"%{token}%",)).fetchone()
            finally:
                conn.close()
            if row:
                return row
        time.sleep(0.25)
    return None


def check(config_dir: Path, host: str, timeout: float) -> int:
    settings = load_settings(config_dir / "settings.json")
    if not settings.tls_enabled:
        print("FAIL: TLS is not enabled in the settings; run 'setup' first.")
        return 1
    directory = config_dir / TLS_DIR_NAME
    context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if settings.tls_ca_file:
        context.load_cert_chain(str(directory / "client.pem"), str(directory / "client.key"))
    token = f"tls-test-{uuid.uuid4().hex[:12]}"
    message = f"<134>1 {datetime.now(timezone.utc).isoformat()} tls-test syslog-monitor - - - {token}"
    frame = f"{len(message.encode())} {message}".encode()
    try:
        with socket.create_connection((host, settings.tls_port), timeout=10) as raw:
            print(f"OK   TCP connection to {host}:{settings.tls_port}")
            with context.wrap_socket(raw, server_hostname=host) as tls:
                print(f"OK   TLS handshake ({tls.version()}, {tls.cipher()[0]}), server certificate trusted"
                      + (", client certificate accepted" if settings.tls_ca_file else ""))
                tls.sendall(frame)
                tls.unwrap()
    except ssl.SSLCertVerificationError as exc:
        print(f"FAIL server certificate rejected: {exc.verify_message}. "
              "Restart Syslog Monitor after 'setup' or use one of the certificate names as --host.")
        return 1
    except (ssl.SSLError, OSError) as exc:
        print(f"FAIL {exc}. Is Syslog Monitor running with the TLS listener enabled?")
        return 1
    print(f"OK   sent test message {token}")
    row = _wait_for(settings, config_dir, token, timeout)
    if row is None:
        print(f"FAIL message was not stored within {timeout:g} s")
        return 1
    print(f"OK   stored by Syslog Monitor (from {row[0]}) – TLS syslog works")
    return 0


def wait(config_dir: Path, token: str, timeout: float) -> int:
    settings = load_settings(config_dir / "settings.json")
    print(f"Send a message containing {token!r} from the device, e.g.:  logger {token}")
    print(f"Waiting up to {timeout:g} s ...")
    row = _wait_for(settings, config_dir, token, timeout)
    if row is None:
        print("FAIL no matching message received")
        return 1
    print(f"OK   received from {row[0]} ({row[1] or 'no hostname'}): {row[2]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m syslog_monitor.tls_test", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config-dir", type=Path, default=default_config_dir())
    commands = parser.add_subparsers(dest="command", required=True)
    s = commands.add_parser("setup", help="create certificates, enable TLS, write device configuration")
    s.add_argument("--name", action="append", default=[],
                   help="DNS name/IP the device connects to (repeatable; first one is used in snippets)")
    s.add_argument("--port", type=int, default=DEFAULT_TLS_PORT)
    s.add_argument("--mtls", action="store_true", help="require client certificates")
    s.add_argument("--days", type=int, default=365)
    c = commands.add_parser("check", help="send a TLS test message and confirm it was stored")
    c.add_argument("--host", default="127.0.0.1")
    c.add_argument("--timeout", type=float, default=15)
    w = commands.add_parser("wait", help="wait for a test message from a real device")
    w.add_argument("--token", default=f"tls-test-{uuid.uuid4().hex[:8]}")
    w.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args(argv)
    if args.command == "setup":
        names = args.name + [name for name in local_names() if name not in args.name]
        return setup(args.config_dir, names, args.port, args.mtls, args.days)
    if args.command == "check":
        return check(args.config_dir, args.host, args.timeout)
    return wait(args.config_dir, args.token, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
