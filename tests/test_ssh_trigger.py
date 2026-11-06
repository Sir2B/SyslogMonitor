import shlex
import base64
import hashlib
import socket
import threading
from unittest.mock import Mock
from contextlib import contextmanager
from dataclasses import replace

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from syslog_monitor.ssh_trigger import KeyLoadingClient, SshOptions, SshTrigger, fingerprint, _load_legacy_sec1


@pytest.fixture(autouse=True)
def isolate_ssh_identity_files(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("syslog_monitor.ssh_trigger.Path.home", lambda: tmp_path)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(paramiko, "Agent", lambda: Mock(get_keys=lambda: ()))


@contextmanager
def ssh_server(exit_code=0, public_key=None, host_key=None):
    host_key = host_key or paramiko.RSAKey.generate(2048)
    commands = []
    finished = threading.Event()
    stop = threading.Event()
    errors = []

    class Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL if (username, password) == ("tester", "secret") else paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            return paramiko.AUTH_SUCCESSFUL if username == "tester" and key == public_key else paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command):
            commands.append(command.decode())
            finished.set()
            return True

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)

        def serve():
            transport = None
            try:
                while not stop.is_set():
                    try:
                        conn, _ = listener.accept()
                        break
                    except socket.timeout:
                        continue
                else:
                    return
                with conn:
                    transport = paramiko.Transport(conn)
                    transport.add_server_key(host_key)
                    transport.start_server(server=Server())
                    channel = transport.accept(5)
                    if channel is not None and finished.wait(5):
                        if exit_code is not None:
                            channel.send_exit_status(exit_code)
                        stop.wait(5)
            except (EOFError, OSError, paramiko.SSHException) as exc:
                errors.append(exc)
            finally:
                if transport:
                    transport.close()

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield SshOptions("127.0.0.1", listener.getsockname()[1], "tester",
                             fingerprint(host_key), "secret"), commands
        finally:
            stop.set()
            thread.join(6)
            assert not thread.is_alive()


def test_password_ssh_executes_only_local_logger_and_quotes_token():
    token = "CHECK ' $(touch should-not-run); end"
    with ssh_server() as (options, commands):
        SshTrigger(options).send(token, 16, 6, threading.Event())
        assert shlex.split(commands[0]) == ["logger", "-p", "local0.info", "-t", "syslog-monitor-check", "--", token]
        assert options.password not in repr(options)


@pytest.mark.parametrize(("facility", "severity", "priority"), [
    (1, 2, "user.crit"), (16, 6, "local0.info"), (23, 7, "local7.debug"),
])
def test_logger_priority_uses_explicit_facility_and_severity(facility, severity, priority):
    with ssh_server() as (options, commands):
        SshTrigger(options).send("CHECK", facility, severity, threading.Event())
        assert shlex.split(commands[0])[2] == priority


def test_nonportable_logger_facility_is_rejected_before_connection():
    trigger = SshTrigger(SshOptions("localhost", 22, "tester", "SHA256:" + "A" * 43))
    try:
        with pytest.raises(ValueError, match="send the message manually"):
            trigger.send("CHECK", 12, 6, threading.Event())
    finally:
        trigger.close()


def test_private_key_authentication(tmp_path):
    key = paramiko.RSAKey.generate(2048)
    path = tmp_path / "client.key"
    key.write_private_key_file(str(path), password="key-passphrase")
    with ssh_server(public_key=key) as (options, commands):
        options = replace(options, password="key-passphrase", key_file=str(path))
        SshTrigger(options).send("CHECK", 0, 0, threading.Event())
        assert "-p kern.emerg" in commands[0]


@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("format", [serialization.PrivateFormat.OpenSSH,
                                  serialization.PrivateFormat.TraditionalOpenSSL])
def test_ec_key_uses_complete_encoded_key(tmp_path, monkeypatch, encrypted, format):
    private = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "ec-key"
    password = "key-passphrase" if encrypted else ""
    encryption = (serialization.BestAvailableEncryption(password.encode()) if encrypted
                  else serialization.NoEncryption())
    path.write_bytes(private.private_bytes(serialization.Encoding.PEM, format, encryption))
    expected = paramiko.ECDSAKey(vals=(private, private.public_key()))
    def broken_legacy_decoder(*args, **kwargs):
        raise ValueError("private key value is too short")
    monkeypatch.setattr(paramiko.ECDSAKey, "_decode_key", broken_legacy_decoder)
    with ssh_server(public_key=expected) as (options, commands):
        SshTrigger(replace(options, password=password, key_file=str(path))).send(
            "CHECK", 16, 6, threading.Event())
        assert commands


def short_scalar_pem(curve, scalar=b"\x01"):
    private = ec.derive_private_key(1, curve)
    der = private.private_bytes(serialization.Encoding.DER,
                               serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption())
    width = (curve.key_size + 7) // 8
    marker = bytes([4, width])
    start = der.index(marker)
    body_start = 2 if der[1] < 128 else 3
    body = der[body_start:start] + bytes([4, len(scalar)]) + scalar + der[start + 2 + width:]
    encoded = b"\x30" + bytes([len(body)]) + body if len(body) < 128 else (
        b"\x30\x81" + bytes([len(body)]) + body)
    pem = b"-----BEGIN EC PRIVATE KEY-----\n" + base64.encodebytes(encoded) + b"-----END EC PRIVATE KEY-----\n"
    return private, pem, encoded


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_real_short_sec1_scalar_error_and_in_memory_compatibility(tmp_path, curve):
    private, pem, der = short_scalar_pem(curve)
    with pytest.raises(ValueError, match="private key value is too short"):
        serialization.load_pem_private_key(pem, password=None)
    path = tmp_path / "id_ecdsa"
    path.write_bytes(pem)
    key = KeyLoadingClient()._key_from_filepath(str(path), paramiko.ECDSAKey, None)
    assert key.signing_key.private_numbers() == private.private_numbers()
    assert path.read_bytes() == pem
    assert _load_legacy_sec1(der).private_numbers() == private.private_numbers()


def test_short_scalar_key_authenticates_without_changing_user_file(tmp_path):
    private, pem, _ = short_scalar_pem(ec.SECP521R1())
    path = tmp_path / "id_ecdsa"
    path.write_bytes(pem)
    expected = paramiko.ECDSAKey(vals=(private, private.public_key()))
    with ssh_server(public_key=expected) as (options, commands):
        SshTrigger(replace(options, password="", key_file=str(path))).send(
            "CHECK", 16, 6, threading.Event())
        assert commands
    assert path.read_bytes() == pem


@pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
def test_legacy_sec1_accepts_redundant_leading_zero_bytes(curve):
    width = (curve.key_size + 7) // 8
    private, _, der = short_scalar_pem(curve, b"\x00" * (width + 3) + b"\x01")
    assert _load_legacy_sec1(der).private_numbers() == private.private_numbers()


def test_zero_padded_legacy_key_authenticates(tmp_path, monkeypatch):
    private, pem, _ = short_scalar_pem(ec.SECP256R1(), b"\x00" * 35 + b"\x01")
    path = tmp_path / "id_ecdsa"
    path.write_bytes(pem)
    expected = paramiko.ECDSAKey(vals=(private, private.public_key()))
    original = serialization.load_pem_private_key
    def strict_loader(data, password):
        if data == pem:
            raise ValueError("EC private key value is too short")
        return original(data, password)
    monkeypatch.setattr(serialization, "load_pem_private_key", strict_loader)
    with ssh_server(public_key=expected) as (options, commands):
        SshTrigger(replace(options, password="", key_file=str(path))).send(
            "CHECK", 16, 6, threading.Event())
        assert commands
    assert path.read_bytes() == pem


def test_genuinely_oversized_scalar_is_rejected_with_nonsecret_diagnostics():
    _, _, der = short_scalar_pem(ec.SECP256R1(), b"\x01" + b"\x00" * 32)
    with pytest.raises(ValueError, match=r"curve=secp256r1.*maximum_bits=256"):
        _load_legacy_sec1(der)


def test_encrypted_legacy_short_scalar_key(tmp_path):
    private, _, der = short_scalar_pem(ec.SECP384R1())
    password = "test-passphrase"
    iv = bytes(range(16))
    aes_key = paramiko.util.generate_key_bytes(hashlib.md5, iv, password, 32)
    padder = padding.PKCS7(128).padder()
    plaintext = padder.update(der) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    pem = (b"-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"
           + iv.hex().upper().encode() + b"\n\n" + base64.encodebytes(ciphertext)
           + b"-----END EC PRIVATE KEY-----\n")
    path = tmp_path / "id_ecdsa"
    path.write_bytes(pem)
    loaded = KeyLoadingClient()._key_from_filepath(str(path), paramiko.ECDSAKey, password)
    assert loaded.signing_key.private_numbers() == private.private_numbers()
    assert path.read_bytes() == pem
    with pytest.raises(paramiko.SSHException):
        KeyLoadingClient()._key_from_filepath(str(path), paramiko.ECDSAKey, "wrong")


def test_legacy_loader_rejects_mismatching_public_point_and_zero_scalar():
    _, _, der = short_scalar_pem(ec.SECP256R1())
    offset = der.index(b"\x04\x01\x01")
    for scalar in (0, 2):
        corrupt = der[:offset + 2] + bytes([scalar]) + der[offset + 3:]
        with pytest.raises(ValueError):
            _load_legacy_sec1(corrupt)


def test_truncated_sec1_key_remains_rejected():
    _, _, der = short_scalar_pem(ec.SECP256R1())
    with pytest.raises(ValueError):
        _load_legacy_sec1(der[:-1])


def test_ed25519_key_is_not_tried_as_ec(tmp_path, monkeypatch):
    private = ed25519.Ed25519PrivateKey.generate()
    path = tmp_path / "device-key"
    path.write_bytes(private.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.OpenSSH,
                                           serialization.NoEncryption()))
    expected = paramiko.Ed25519Key.from_private_key_file(str(path))
    def broken_ec_decoder(*args, **kwargs):
        raise ValueError("EC private key is not encoded properly: private key value is too short")
    monkeypatch.setattr(paramiko.ECDSAKey, "_decode_key", broken_ec_decoder)
    with ssh_server(public_key=expected) as (options, commands):
        SshTrigger(replace(options, password="", key_file=str(path))).send(
            "CHECK", 16, 6, threading.Event())
        assert commands


def test_mismatch_never_authenticates_or_executes():
    with ssh_server() as (options, commands):
        bad = replace(options, host_fingerprint="SHA256:" + "A" * 43)
        with pytest.raises(paramiko.SSHException, match="host key mismatch"):
            SshTrigger(bad).send("CHECK", 16, 6, threading.Event())
        assert commands == []


def test_remote_logger_failure_is_explicit():
    with ssh_server(exit_code=127) as (options, commands):
        with pytest.raises(ValueError, match="exit 127"):
            SshTrigger(options).send("CHECK", 16, 6, threading.Event())


def test_authentication_failure_is_explicit():
    with ssh_server() as (options, commands):
        with pytest.raises(paramiko.AuthenticationException):
            SshTrigger(replace(options, password="wrong")).send("CHECK", 16, 6, threading.Event())
        assert commands == []


def test_cancellation_during_remote_command_closes_connection():
    with ssh_server(exit_code=None) as (options, commands):
        trigger = SshTrigger(options)
        cancel = threading.Event()
        errors = []
        def run():
            try:
                trigger.send("CHECK", 16, 6, cancel)
            except (ValueError, OSError, paramiko.SSHException) as exc:
                errors.append(exc)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            # Wait for the server's exec request rather than cancelling before connection.
            for _ in range(100):
                if commands:
                    break
                cancel.wait(0.05)
            assert commands
            cancel.set()
            trigger.close()
            thread.join(2)
            assert not thread.is_alive()
            assert errors
        finally:
            cancel.set()
            trigger.close()
            thread.join(5)


def test_validate_cancel_and_close():
    options = SshOptions("localhost", 22, "tester", "SHA256:" + "A" * 43, "secret")
    for invalid in (replace(options, host=""), replace(options, host_fingerprint="invalid"),
                    replace(options, port=0)):
        with pytest.raises(ValueError):
            invalid.validate()
    trigger = SshTrigger(options)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(ValueError, match="cancelled"):
        trigger.send("CHECK", 16, 6, cancel)
    trigger.close()


def test_automatic_user_directory_key_authentication(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    key_dir = tmp_path / ".ssh"
    key_dir.mkdir()
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_dir / "id_rsa"))
    monkeypatch.setattr(paramiko, "Agent", lambda: Mock(get_keys=lambda: ()))
    with ssh_server(public_key=key) as (options, commands):
        SshTrigger(replace(options, password="")).send("CHECK", 16, 6, threading.Event())
        assert commands


def test_unreadable_discovered_key_does_not_block_password(tmp_path):
    directory = tmp_path / ".ssh"
    directory.mkdir()
    (directory / "id_ecdsa").write_text("not a private key")
    with ssh_server() as (options, commands):
        trigger = SshTrigger(options)
        trigger.send("CHECK", 16, 6, threading.Event())
        assert commands
        assert trigger.client.key_load_warnings
        assert "id_ecdsa" in trigger.client.key_load_warnings[0]


def test_unreadable_ec_key_does_not_block_valid_ed25519_key(tmp_path):
    directory = tmp_path / ".ssh"
    directory.mkdir()
    (directory / "id_ecdsa").write_text("not a private key")
    private = ed25519.Ed25519PrivateKey.generate()
    path = directory / "id_ed25519"
    path.write_bytes(private.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.OpenSSH,
                                           serialization.NoEncryption()))
    expected = paramiko.Ed25519Key.from_private_key_file(str(path))
    with ssh_server(public_key=expected) as (options, commands):
        trigger = SshTrigger(replace(options, password=""))
        trigger.send("CHECK", 16, 6, threading.Event())
        assert commands
        assert trigger.client.key_load_warnings


def test_legacy_backend_value_error_is_a_skippable_key_error(tmp_path, monkeypatch):
    directory = tmp_path / ".ssh"
    directory.mkdir()
    _, pem, _ = short_scalar_pem(ec.SECP256R1())
    (directory / "id_ecdsa").write_bytes(pem)
    def invalid_encoding(*args):
        raise ValueError("Unsupported SEC1 parameters")
    monkeypatch.setattr("syslog_monitor.ssh_trigger._load_legacy_sec1", invalid_encoding)
    with ssh_server() as (options, commands):
        trigger = SshTrigger(options)
        trigger.send("CHECK", 16, 6, threading.Event())
        assert commands
        assert any("Unsupported SEC1" in warning for warning in trigger.client.key_load_warnings)


def test_explicit_key_expands_user_path_and_disables_discovery(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    trigger = SshTrigger(SshOptions("localhost", 22, "tester", "SHA256:" + "A" * 43,
                                  key_file=r"~\.ssh\custom"))
    trigger.client = Mock()
    trigger.client.get_transport.return_value.get_remote_server_key.return_value.asbytes.return_value = b"test-key"
    trigger.client.exec_command.side_effect = OSError("test stops before exec")
    with pytest.raises(OSError):
        trigger.send("CHECK", 16, 6, threading.Event())
    kwargs = trigger.client.connect.call_args.kwargs
    assert kwargs["key_filename"] == str(tmp_path / ".ssh" / "custom")
    assert kwargs["allow_agent"] is False
    assert kwargs["look_for_keys"] is False


def test_automatic_mode_enables_agent_and_key_discovery():
    trigger = SshTrigger(SshOptions("localhost", 22, "tester", "SHA256:" + "A" * 43))
    trigger.client = Mock()
    trigger.client.get_transport.return_value.get_remote_server_key.return_value.asbytes.return_value = b"test-key"
    trigger.client.exec_command.side_effect = OSError("test stops before exec")
    with pytest.raises(OSError):
        trigger.send("CHECK", 16, 6, threading.Event())
    kwargs = trigger.client.connect.call_args.kwargs
    assert kwargs["key_filename"] is None
    assert kwargs["allow_agent"] is True
    assert kwargs["look_for_keys"] is True


def test_unknown_host_confirmed_and_remembered(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr("syslog_monitor.ssh_trigger.Path.home", lambda: tmp_path)
    confirmations = []
    with ssh_server() as (options, commands):
        def confirm(host, algorithm, value):
            confirmations.append((host, algorithm, value))
            return True
        trigger = SshTrigger(replace(options, host_fingerprint=""), confirm)
        trigger.send("CHECK", 16, 6, threading.Event())
        assert confirmations[0][2] == options.host_fingerprint
        assert trigger.verified_fingerprint == options.host_fingerprint
        keys = paramiko.HostKeys(str(tmp_path / "SyslogMonitor" / "ssh_known_hosts"))
        assert keys.lookup(confirmations[0][0]) is not None
        assert commands


def test_unknown_host_rejected_runs_no_command(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr("syslog_monitor.ssh_trigger.Path.home", lambda: tmp_path)
    with ssh_server() as (options, commands):
        with pytest.raises(paramiko.SSHException, match="not accepted"):
            SshTrigger(replace(options, host_fingerprint=""), lambda *args: False).send(
                "CHECK", 16, 6, threading.Event())
        assert commands == []
        assert not (tmp_path / "SyslogMonitor" / "ssh_known_hosts").exists()


def test_changed_openssh_host_key_is_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr("syslog_monitor.ssh_trigger.Path.home", lambda: tmp_path)
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    with ssh_server() as (options, commands):
        keys = paramiko.HostKeys()
        host = f"[{options.host}]:{options.port}"
        key = paramiko.RSAKey.generate(2048)
        keys.add(paramiko.HostKeys.hash_host(host), key.get_name(), key)
        keys.save(str(ssh / "known_hosts"))
        with pytest.raises(paramiko.BadHostKeyException):
            SshTrigger(replace(options, host_fingerprint=""), lambda *args: pytest.fail(
                "Changed host must not prompt")).send("CHECK", 16, 6, threading.Event())
        assert commands == []


@pytest.mark.parametrize("source", ["openssh", "application"])
def test_known_hashed_host_connects_without_prompt(tmp_path, monkeypatch, source):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr("syslog_monitor.ssh_trigger.Path.home", lambda: tmp_path)
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    key = paramiko.RSAKey.generate(2048)
    with ssh_server(host_key=key) as (options, commands):
        keys = paramiko.HostKeys()
        keys.add(paramiko.HostKeys.hash_host(f"[{options.host}]:{options.port}"), key.get_name(), key)
        path = ssh / "known_hosts"
        if source == "application":
            path = tmp_path / "SyslogMonitor" / "ssh_known_hosts"
            path.parent.mkdir()
        keys.save(str(path))
        SshTrigger(replace(options, host_fingerprint=""), lambda *args: pytest.fail(
            "Known host must not prompt")).send("CHECK", 16, 6, threading.Event())
        assert commands
