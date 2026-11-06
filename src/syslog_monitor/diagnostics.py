"""Isolated, bounded, evidence-based syslog client checks; never touches capture storage."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from syslog_monitor.parser import parse_datagram
from syslog_monitor.receiver import TcpFramer, TcpFramingError, create_tls_context

CASES = ("udp", "tcp", "tcp_reconnect", "tls_valid", "tls_untrusted", "tls_hostname",
         "tls_expired", "tls_usage")
NEGATIVE_CASES = frozenset(CASES[4:])
CERTIFICATE_ALERTS = frozenset((
    "TLSV1_ALERT_UNKNOWN_CA", "SSLV3_ALERT_BAD_CERTIFICATE", "SSLV3_ALERT_CERTIFICATE_UNKNOWN",
    "SSLV3_ALERT_CERTIFICATE_EXPIRED", "SSLV3_ALERT_UNSUPPORTED_CERTIFICATE",
))


def generate_certificates(directory: Path, hostname: str) -> dict[str, Path]:
    """Generate an ephemeral test CA and one server certificate for each TLS scenario."""
    if not hostname or len(hostname) > 253:
        raise ValueError("Enter a valid DNS hostname or IPv4 address.")
    try:
        name = x509.IPAddress(ipaddress.IPv4Address(hostname))
    except ipaddress.AddressValueError:
        hostname = hostname.encode("idna").decode("ascii")
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                   for label in hostname.split(".")):
            raise ValueError("Enter a valid DNS hostname or IPv4 address.")
        name = x509.DNSName(hostname)
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    def authority(common_name: str):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                               critical=False)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                               critical=True)
                .sign(key, hashes.SHA256()))
        return key, cert

    ca_key, ca = authority("Syslog Monitor temporary diagnostic CA")
    other_key, other_ca = authority("Syslog Monitor untrusted diagnostic CA")
    paths = {"ca": directory / "test-ca.pem"}
    paths["ca"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for case in CASES[3:]:
        issuer_key, issuer = (other_key, other_ca) if case == "tls_untrusted" else (ca_key, ca)
        san = x509.DNSName("wrong-name.syslog-test.invalid") if case == "tls_hostname" else name
        # Ensure even a test against this particular name receives a different SAN.
        if case == "tls_hostname" and hostname == "wrong-name.syslog-test.invalid":
            san = x509.DNSName("other-name.syslog-test.invalid")
        expired = case == "tls_expired"
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
                .issuer_name(issuer.subject).public_key(server_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=2))
                .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
                               critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                               critical=False)
                .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False),
                               critical=True)
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH if case == "tls_usage"
                    else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(issuer_key, hashes.SHA256()))
        paths[case] = directory / f"{case}.pem"
        paths[case].write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
            + server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return paths


@dataclass(frozen=True)
class CheckOptions:
    case: str
    bind_host: str
    port: int
    client_ip: str
    token: str
    expected_format: str = "rfc5424"
    facility: int = 16
    severity: int = 6
    timeout: float = 60

    def validate(self) -> None:
        if self.case not in CASES:
            raise ValueError("Unknown diagnostic case.")
        ipaddress.IPv4Address(self.bind_host)
        ipaddress.IPv4Address(self.client_ip)
        if not 0 <= self.port <= 65535 or not 1 <= self.timeout <= 300:
            raise ValueError("Invalid diagnostic port or timeout.")
        if not self.token or self.expected_format not in ("rfc5424", "rfc3164"):
            raise ValueError("A test token and supported message format are required.")
        if not 0 <= self.facility <= 23 or not 0 <= self.severity <= 7:
            raise ValueError("Invalid expected facility or severity.")


@dataclass(frozen=True)
class CheckResult:
    case: str
    status: str
    reason: str
    messages: int = 0
    connections: int = 0
    connection_attempts: int = 0
    datagrams: int = 0
    ignored_sources: int = 0
    evidence: tuple[str, ...] = ()


def run_check(options: CheckOptions, cancel: threading.Event, *,
              certificate: Path | None = None, baseline_ok: bool = False,
              ready: Callable[[int], None] | None = None) -> CheckResult:
    options.validate()
    if options.case in NEGATIVE_CASES and not baseline_ok:
        raise ValueError("Complete the TLS positive control first.")
    tls = options.case.startswith("tls_")
    context = create_tls_context(str(certificate)) if tls and certificate is not None else None
    if tls and context is None:
        raise ValueError("A TLS test certificate is required.")
    udp = options.case == "udp"
    deadline = time.monotonic() + options.timeout
    evidence: list[str] = []
    messages = connections = 0
    connection_attempts = datagrams = ignored_sources = 0
    mismatch = False
    certificate_rejected = False
    accepted_bad_certificate = False

    def record(text: str) -> None:
        if len(evidence) < 50:
            evidence.append(text)
        elif len(evidence) == 50:
            evidence.append("Further evidence omitted (50-entry limit).")

    def inspect(payload: bytes, framing: str = "datagram") -> bool:
        nonlocal messages, mismatch
        event = parse_datagram(payload, options.client_ip, 0, time.time_ns() // 1_000_000)
        if options.token not in event.message:
            return False
        messages += 1
        valid = (event.format == options.expected_format and event.facility == options.facility
                 and event.severity == options.severity
                 and not event.issues and framing != "eof"
                 and (options.case != "tls_valid" or framing == "octets"))
        mismatch |= not valid
        record(f"format={event.format}; facility={event.facility}; severity={event.severity}; "
               f"parser_notes={','.join(event.issues) or '-'}; framing={framing}")
        return True

    if certificate is not None and tls:
        cert = x509.load_pem_x509_certificate(certificate.read_bytes())
        record(f"Certificate SHA256: {cert.fingerprint(hashes.SHA256()).hex()}")
        record(f"Certificate subject: {cert.subject.rfc4514_string()}")
        record(f"Certificate SAN: {cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as listener:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind((options.bind_host, options.port))
        record(f"Listener: {options.bind_host}:{listener.getsockname()[1]}; client={options.client_ip}")
        listener.settimeout(0.25)
        if not udp:
            listener.listen(4)
        if ready is not None:
            ready(listener.getsockname()[1])
        while not cancel.is_set() and time.monotonic() < deadline:
            try:
                if udp:
                    data, address = listener.recvfrom(65535)
                    if address[0] != options.client_ip:
                        ignored_sources += 1
                        continue
                    datagrams += 1
                    if inspect(data):
                        break
                    continue
                connection, address = listener.accept()
            except socket.timeout:
                continue
            with connection:
                if address[0] != options.client_ip:
                    ignored_sources += 1
                    continue
                connection_attempts += 1
                connection.settimeout(0.25)
                stream = connection
                matched = False
                try:
                    if context is not None:
                        stream = context.wrap_socket(connection, server_side=True,
                                                     do_handshake_on_connect=False)
                        while not cancel.is_set() and time.monotonic() < deadline:
                            try:
                                stream.do_handshake()
                                record(f"TLS: {stream.version()}; {stream.cipher()[0]}")
                                break
                            except (ssl.SSLWantReadError, ssl.SSLWantWriteError, socket.timeout):
                                continue
                        else:
                            continue
                    framer = TcpFramer()
                    while not cancel.is_set() and time.monotonic() < deadline:
                        try:
                            data = stream.recv(65536)
                        except socket.timeout:
                            continue
                        if not data:
                            tail = framer.finish()
                            if tail is not None:
                                matched |= inspect(tail, "eof")
                            break
                        for payload in framer.feed(data):
                            matched |= inspect(payload, framer.last_framing or "unknown")
                            if matched:
                                break
                        if matched:
                            break
                except ssl.SSLError as exc:
                    record(f"TLS alert: {exc.reason}")
                    certificate_rejected |= exc.reason in CERTIFICATE_ALERTS
                except (OSError, TcpFramingError) as exc:
                    record(f"{type(exc).__name__}: {exc}")
                finally:
                    if stream is not connection:
                        stream.close()
                if matched:
                    connections += 1
                    accepted_bad_certificate |= options.case in NEGATIVE_CASES
                if accepted_bad_certificate or certificate_rejected:
                    break
                if matched and (options.case != "tcp_reconnect" or connections >= 2):
                    break
    if cancel.is_set():
        status, reason = "inconclusive", "Test cancelled."
    elif accepted_bad_certificate:
        status, reason = "failed", "Client sent the test message despite an invalid certificate."
    elif options.case in NEGATIVE_CASES and certificate_rejected:
        status, reason = "passed", "Client returned a certificate-related TLS rejection alert."
    elif mismatch:
        status, reason = "failed", "Test message failed the selected format, PRI, parser, or framing checks."
    elif messages and (options.case != "tcp_reconnect" or connections >= 2):
        status, reason = "passed", "Expected test message received."
    else:
        status, reason = "inconclusive", "Required evidence was not observed before timeout."
    return CheckResult(options.case, status, reason, messages, connections,
                       connection_attempts, datagrams, ignored_sources, tuple(evidence))
