"""Trigger the device's existing syslog pipeline, not a substitute network sender."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import shlex
import threading
import time
from dataclasses import dataclass, field
from collections.abc import Callable
from pathlib import Path

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from syslog_monitor.config import default_config_dir

log = logging.getLogger(__name__)

LOGGER_FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    **{16 + index: f"local{index}" for index in range(8)},
}
LOGGER_SEVERITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


def _load_legacy_sec1(data: bytes) -> ec.EllipticCurvePrivateKey:
    """Load a legacy SEC1 scalar and verify it against the encoded public key."""
    def field(buffer: bytes, offset: int) -> tuple[int, bytes, int]:
        if offset + 2 > len(buffer):
            raise ValueError("Truncated EC key encoding")
        tag, length = buffer[offset:offset + 2]
        offset += 2
        if length & 0x80:
            count = length & 0x7f
            if not 1 <= count <= 4 or offset + count > len(buffer):
                raise ValueError("Invalid EC key length")
            length = int.from_bytes(buffer[offset:offset + count], "big")
            offset += count
        end = offset + length
        if end > len(buffer):
            raise ValueError("Truncated EC key encoding")
        return tag, buffer[offset:end], end

    def encode(tag: int, value: bytes) -> bytes:
        size = len(value)
        length = bytes([size]) if size < 128 else (
            bytes([0x80 | ((size.bit_length() + 7) // 8)])
            + size.to_bytes((size.bit_length() + 7) // 8, "big"))
        return bytes([tag]) + length + value

    tag, body, end = field(data, 0)
    if tag != 0x30 or end != len(data):
        raise ValueError("Invalid SEC1 EC key")
    tag, version, offset = field(body, 0)
    if tag != 2 or version != b"\x01":
        raise ValueError("Invalid SEC1 EC key version")
    tag, scalar, tail_start = field(body, offset)
    if tag != 4:
        raise ValueError("Invalid SEC1 EC private value")
    tag, parameters, offset = field(body, tail_start)
    if tag != 0xa0:
        raise ValueError("Missing SEC1 EC curve parameters")
    tag, public_bits, end = field(body, offset)
    if tag != 0xa1 or end != len(body):
        raise ValueError("Missing SEC1 EC public key")
    algorithm = encode(0x30, b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" + parameters)
    public = serialization.load_der_public_key(encode(0x30, algorithm + public_bits))
    if not isinstance(public, ec.EllipticCurvePublicKey):
        raise ValueError("Invalid SEC1 EC public key")
    private_value = int.from_bytes(scalar, "big")
    if not scalar or not 0 < private_value.bit_length() <= public.curve.key_size:
        raise ValueError(
            f"Invalid SEC1 EC private value length (curve={public.curve.name}, "
            f"encoded_bytes={len(scalar)}, significant_bits={private_value.bit_length()}, "
            f"maximum_bits={public.curve.key_size})")
    private = ec.derive_private_key(private_value, public.curve)
    if private.public_key().public_numbers() != public.public_numbers():
        raise ValueError("SEC1 EC private value does not match the public key")
    return private


class CompatibleECDSAKey(paramiko.ECDSAKey):
    def _decode_key(self, data):
        try:
            super()._decode_key(data)
        except paramiko.SSHException as exc:
            pkformat, der = data
            if pkformat != self._PRIVATE_KEY_FORMAT_ORIGINAL or "private key value is too short" not in str(exc):
                raise
            private = _load_legacy_sec1(der)
            self.signing_key = private
            self.verifying_key = private.public_key()
            self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(type(private.curve))
            if self.ecdsa_curve is None:
                raise paramiko.SSHException("EC curve is not supported by SSH")
            log.info("Loaded legacy SEC1 EC key in memory and verified its public key")


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class SshOptions:
    host: str
    port: int
    username: str
    host_fingerprint: str = ""
    password: str = field(default="", repr=False)
    key_file: str = ""

    def validate(self) -> None:
        if not self.host or not self.username or not 1 <= self.port <= 65535:
            raise ValueError("SSH host, port and username are required.")
        if self.host_fingerprint and not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", self.host_fingerprint):
            raise ValueError("Enter the verified SSH SHA256 host-key fingerprint.")


class PinnedHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str):
        self.expected = expected

    def missing_host_key(self, client, hostname, key):
        actual = fingerprint(key)
        if actual != self.expected:
            raise paramiko.SSHException(
                f"SSH host key mismatch: received {actual}. Verify it independently on the device.")


class ConfirmHostKey(paramiko.MissingHostKeyPolicy):
    def __init__(self, confirm: Callable[[str, str, str], bool] | None, store: Path):
        self.confirm = confirm
        self.store = store

    def missing_host_key(self, client, hostname, key):
        if self.confirm is None or not self.confirm(hostname, key.get_name(), fingerprint(key)):
            raise paramiko.SSHException("SSH host key was not accepted.")
        self.store.parent.mkdir(parents=True, exist_ok=True)
        # Keep OpenSSH's file read-only; accepted hosts are stored separately for this app.
        keys = paramiko.HostKeys()
        if self.store.exists():
            keys.load(str(self.store))
        existing = keys.lookup(hostname)
        if existing is not None and key.get_name() in existing and existing[key.get_name()] != key:
            raise paramiko.BadHostKeyException(hostname, key, existing[key.get_name()])
        keys.add(hostname, key.get_name(), key)
        keys.save(str(self.store))
        client.get_host_keys().add(hostname, key.get_name(), key)


class KeyLoadingClient(paramiko.SSHClient):
    def __init__(self):
        super().__init__()
        self.key_load_warnings: list[str] = []

    def _key_from_filepath(self, filename, klass, password):
        try:
            return self._load_key_file(filename, password)
        except (ValueError, TypeError, paramiko.SSHException) as exc:
            warning = f"Cannot load SSH private key {Path(filename).name}: {exc}"
            if warning not in self.key_load_warnings:
                self.key_load_warnings.append(warning)
                log.warning("%s", warning)
            # Paramiko continues with the next discovered identity or password only
            # for SSHException; backend ValueError must not abort that search.
            raise paramiko.SSHException(warning) from exc

    def _load_key_file(self, filename, password):
        path = Path(filename.removesuffix("-cert.pub"))
        data = path.read_bytes()
        secret = password.encode("utf-8") if isinstance(password, str) else password
        loader = (serialization.load_ssh_private_key if b"BEGIN OPENSSH PRIVATE KEY" in data
                  else serialization.load_pem_private_key)
        try:
            try:
                decoded = loader(data, password=secret)
            except TypeError:
                if secret is None:
                    raise paramiko.PasswordRequiredException("Private key file is encrypted") from None
                # An optional login password need not imply an encrypted private key.
                decoded = loader(data, password=None)
        except ValueError as exc:
            if b"BEGIN EC PRIVATE KEY" in data and "private key value is too short" in str(exc):
                key = CompatibleECDSAKey.from_private_key_file(str(path), password=password)
                certificate = Path(str(path) + "-cert.pub")
                if certificate.exists():
                    key.load_certificate(str(certificate))
                return key
            raise
        if isinstance(decoded, ec.EllipticCurvePrivateKey):
            key = paramiko.ECDSAKey(vals=(decoded, decoded.public_key()))
        elif isinstance(decoded, rsa.RSAPrivateKey):
            key = paramiko.RSAKey(key=decoded)
        else:
            key = paramiko.Ed25519Key.from_private_key_file(str(path), password=password)
        certificate = Path(str(path) + "-cert.pub")
        if certificate.exists():
            key.load_certificate(str(certificate))
        return key


class SshTrigger:
    def __init__(self, options: SshOptions, confirm: Callable[[str, str, str], bool] | None = None):
        self.options = options
        self.client = KeyLoadingClient()
        self.verified_fingerprint = ""
        if options.host_fingerprint:
            self.client.set_missing_host_key_policy(PinnedHostKey(options.host_fingerprint))
        else:
            known_hosts = Path.home() / ".ssh" / "known_hosts"
            if known_hosts.exists():
                self.client.load_system_host_keys(str(known_hosts))
            store = default_config_dir() / "ssh_known_hosts"
            if store.exists():
                self.client.load_host_keys(str(store))
            self.client.set_missing_host_key_policy(ConfirmHostKey(confirm, store))

    def close(self) -> None:
        self.client.close()

    def send(self, token: str, facility: int, severity: int, cancel: threading.Event) -> None:
        self.options.validate()
        if not token or not 0 <= facility <= 23 or not 0 <= severity <= 7:
            raise ValueError("Invalid SSH test message or priority.")
        if facility not in LOGGER_FACILITIES:
            raise ValueError("This facility is not supported by the Linux logger trigger; send the message manually.")
        if cancel.is_set():
            raise ValueError("SSH trigger cancelled.")
        try:
            automatic_keys = not self.options.key_file
            key_file = os.path.expanduser(os.path.expandvars(self.options.key_file)) if self.options.key_file else None
            self.client.connect(
                hostname=self.options.host, port=self.options.port, username=self.options.username,
                password=self.options.password or None, key_filename=key_file,
                passphrase=self.options.password or None,
                allow_agent=automatic_keys, look_for_keys=automatic_keys,
                timeout=5, banner_timeout=5, auth_timeout=5, channel_timeout=5,
            )
            transport = self.client.get_transport()
            if transport is None:
                raise paramiko.SSHException("SSH connection is not active.")
            self.verified_fingerprint = fingerprint(transport.get_remote_server_key())
            if cancel.is_set():
                raise ValueError("SSH trigger cancelled.")
            # logger writes locally; no destination/protocol flags bypass the real syslog daemon.
            priority = f"{LOGGER_FACILITIES[facility]}.{LOGGER_SEVERITIES[severity]}"
            command = f"logger -p {priority} -t syslog-monitor-check -- {shlex.quote(token)}"
            stdin, stdout, stderr = self.client.exec_command(command, timeout=5)
            stdin.close()
            channel = stdout.channel
            deadline = time.monotonic() + 5
            while not channel.exit_status_ready():
                if cancel.is_set():
                    raise ValueError("SSH trigger cancelled.")
                if time.monotonic() >= deadline:
                    raise TimeoutError("SSH logger command timed out.")
                # Drain both streams to avoid a full channel window; output is never needed.
                if channel.recv_ready():
                    channel.recv(4096)
                if channel.recv_stderr_ready():
                    channel.recv_stderr(4096)
                cancel.wait(0.05)
            if cancel.is_set():
                raise ValueError("SSH trigger cancelled.")
            code = channel.recv_exit_status()
            if code != 0:
                raise ValueError(f"Remote logger command failed (exit {code}). Check logger availability and permissions.")
        finally:
            self.close()
