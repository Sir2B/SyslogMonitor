"""Read-only check whether the Windows Firewall lets syslog UDP/TCP reach this process.

The *effective* policy (``-PolicyStore ActiveStore``: local rules merged with group policy)
is read with the NetSecurity cmdlets, which needs no admin rights. The COM object
``HNetCfg.FwPolicy2`` is only used for the active profiles, because it sees local rules
and defaults only. The evaluation is a pure function so it can be tested without Windows.
"""

from __future__ import annotations

import base64
import ctypes
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from enum import IntEnum

from syslog_monitor.config import ListenerEndpoint, Transport

log = logging.getLogger(__name__)

PROFILE_NAMES = {1: "Domain", 2: "Private", 4: "Public"}
PROFILE_BITS = {"domain": 1, "private": 2, "public": 4}
ALL_PROFILES = 0x7FFFFFFF
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17
PROTOCOL_ANY = 256
PROTOCOL_UNKNOWN = -1
PROTOCOL_NUMBERS = {"UDP": PROTOCOL_UDP, "TCP": PROTOCOL_TCP, "TLS": PROTOCOL_TCP}  # TLS runs over TCP
CHECK_TIMEOUT_S = 30


class Level(IntEnum):
    UNKNOWN = 0
    OK = 1
    WARNING = 2
    ERROR = 3


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    block: bool
    protocol: int = PROTOCOL_UDP
    local_ports: str = "*"
    profiles: int = ALL_PROFILES
    application: str = ""
    # bound to a Windows service or an app package/container – never applies to a desktop process
    restricted: bool = False
    group_policy: bool = False


@dataclass(frozen=True, slots=True)
class ProfileState:
    enabled: bool = True
    default_block: bool = True
    block_all_inbound: bool = False
    # Group policy can disable locally created rules ("Merge local firewall rules: No").
    allow_local_rules: bool = True


@dataclass(frozen=True, slots=True)
class FirewallState:
    """Effective inbound, enabled rules plus the per-profile switches of the active profiles."""
    active_profiles: int
    profiles: dict[int, ProfileState]
    rules: tuple[Rule, ...] = ()
    unreadable_rules: int = 0


@dataclass(frozen=True, slots=True)
class FirewallCheck:
    level: Level
    summary: str
    details: tuple[str, ...] = field(default_factory=tuple)
    endpoint_checks: tuple[tuple[Transport, int, FirewallCheck], ...] = field(default_factory=tuple)


def port_matches(spec: str | None, port: int) -> bool:
    if spec is None or spec.strip().lower() in ("", "*", "any"):
        return True
    for part in spec.split(","):
        part = part.strip()
        if part.lower() in ("*", "any"):
            return True
        low, sep, high = part.partition("-")
        if low.isdigit() and (not sep or high.isdigit()):
            if int(low) <= port <= int(high if sep else low):
                return True
        # Keywords such as "RPC" or "Teredo" never match a plain port.
    return False


def _norm_path(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expandvars(path.strip())))


def app_matches(rule_app: str | None, programs: tuple[str, ...]) -> bool:
    if not rule_app or rule_app.strip().lower() in ("", "*", "any"):
        return True
    wanted = _norm_path(rule_app)
    return any(_norm_path(p) == wanted for p in programs)


def _applies(rule: Rule, profile: int, ps: ProfileState, port: int, programs: tuple[str, ...],
             protocol: Transport) -> bool:
    return (not rule.restricted and rule.protocol in (PROTOCOL_NUMBERS[protocol], PROTOCOL_ANY)
            and bool(rule.profiles & profile) and (ps.allow_local_rules or rule.group_policy)
            and port_matches(rule.local_ports, port) and app_matches(rule.application, programs))


def assess(state: FirewallState, port: int, programs: tuple[str, ...],
           protocol: Transport = "UDP") -> FirewallCheck:
    """Mirror Windows semantics: block rules win over allow rules, otherwise the default applies."""
    active = [p for p in PROFILE_NAMES if state.active_profiles & p]
    if not active:
        return FirewallCheck(Level.UNKNOWN, "No active network profile detected")
    level, details = Level.OK, []
    for profile in active:
        name = PROFILE_NAMES[profile]
        ps = state.profiles.get(profile, ProfileState())
        matching = [r for r in state.rules if _applies(r, profile, ps, port, programs, protocol)]
        blocking = [r.name for r in matching if r.block]
        if not ps.enabled:
            details.append(f"{name}: Firewall is off; {protocol} port {port} is reachable.")
        elif ps.block_all_inbound:
            level = max(level, Level.ERROR)
            details.append(f"{name}: all inbound connections are blocked.")
        elif blocking:
            level = max(level, Level.ERROR)
            details.append(f"{name}: blocked by rule(s) “{'”, “'.join(sorted(set(blocking)))}”.")
        elif matching:
            details.append(f"{name}: allowed by “{matching[0].name}”.")
        elif ps.default_block:
            level = max(level, Level.WARNING)
            details.append(f"{name}: {protocol} {port} is not allowed; the default is to block inbound traffic.")
        else:
            details.append(f"{name}: inbound traffic is allowed by default.")
        if not ps.allow_local_rules:
            details.append(f"{name}: local rules are disabled by group policy; "
                           "only rules set by IT apply.")
    if state.unreadable_rules:
        details.append(f"Note: {state.unreadable_rules} rule(s) could not be evaluated due to read restrictions.")
    summary = {
        Level.OK: f"{protocol} {port} is allowed",
        Level.WARNING: f"{protocol} {port} is not allowed; only local messages can be received",
        Level.ERROR: f"{protocol} {port} is blocked",
    }[level]
    return FirewallCheck(level, summary, tuple(details))


def parse_protocol(value) -> int:
    text = str(value if value is not None else "any").strip().lower()
    if text in ("", "any", "*"):
        return PROTOCOL_ANY
    if text.isdigit():
        return int(text)
    return {"udp": PROTOCOL_UDP, "tcp": PROTOCOL_TCP}.get(text, PROTOCOL_UNKNOWN)


def parse_profiles(value) -> int:
    """``"Domain, Public"`` / ``"Any"`` (cmdlets) or a bit mask (COM) → bit mask."""
    if isinstance(value, int):
        return value or ALL_PROFILES
    text = str(value or "any").strip().lower()
    if text.isdigit():
        return int(text) or ALL_PROFILES
    bits = 0
    for part in text.replace(";", ",").split(","):
        part = part.strip()
        if part in ("any", "all", ""):
            return ALL_PROFILES
        bits |= PROFILE_BITS.get(part, 0)
    return bits


def parse_state(data: dict) -> FirewallState:
    rules = tuple(
        Rule(name=str(r.get("name") or "?"), block=bool(r.get("block")),
             protocol=parse_protocol(r.get("protocol")), local_ports=str(r.get("ports") or "*"),
             profiles=parse_profiles(r.get("profiles")), application=str(r.get("app") or ""),
             restricted=bool(r.get("restricted")), group_policy=bool(r.get("gpo")))
        for r in data.get("rules") or ())
    profiles = {int(k): ProfileState(bool(v["enabled"]), bool(v["default_block"]), bool(v["block_all"]),
                                     bool(v.get("allow_local", True)))
                for k, v in (data.get("profiles") or {}).items()}
    return FirewallState(int(data.get("active") or 0), profiles, rules, int(data.get("unreadable") or 0))


_PS_SCRIPT = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'
$store = 'ActiveStore'
$bits = @{ Domain = 1; Private = 2; Public = 4 }
$profiles = @{}
foreach ($p in Get-NetFirewallProfile -PolicyStore $store) {
  $profiles["$($bits["$($p.Name)"])"] = @{
    enabled = "$($p.Enabled)" -ne 'False'; default_block = "$($p.DefaultInboundAction)" -ne 'Allow';
    block_all = "$($p.AllowInboundRules)" -eq 'False'; allow_local = "$($p.AllowLocalFirewallRules)" -ne 'False' }
}
# bulk lookups are fast; some entries are access-denied in bulk and are fetched per rule below
$ports = @{}; foreach ($f in Get-NetFirewallPortFilter -PolicyStore $store -All) { $ports[$f.InstanceID] = $f }
$apps = @{}; foreach ($f in Get-NetFirewallApplicationFilter -PolicyStore $store -All) { $apps[$f.InstanceID] = $f }
$svcs = @{}; foreach ($f in Get-NetFirewallServiceFilter -PolicyStore $store -All) { $svcs[$f.InstanceID] = $f }
$unreadable = 0
$rules = foreach ($r in Get-NetFirewallRule -PolicyStore $store -Direction Inbound -Enabled True) {
  $id = $r.InstanceID
  $pf = $ports[$id]; if (-not $pf) { $pf = $r | Get-NetFirewallPortFilter }
  if (-not $pf) { $unreadable++; continue }
  if ("$($pf.Protocol)" -notin 'UDP', 'TCP', 'Any', '17', '6', '256') { continue }
  $af = $apps[$id]; if (-not $af) { $af = $r | Get-NetFirewallApplicationFilter }
  $sf = $svcs[$id]; if (-not $sf) { $sf = $r | Get-NetFirewallServiceFilter }
  @{ name = "$($r.DisplayName)"; block = "$($r.Action)" -eq 'Block'; protocol = "$($pf.Protocol)";
     ports = (@($pf.LocalPort) -join ','); profiles = "$($r.Profile)"; app = "$($af.Program)";
     gpo = "$($r.PolicyStoreSourceType)" -eq 'GroupPolicy';
     restricted = [bool](("$($sf.Service)" -notin '', 'Any', '*') -or ("$($af.Package)" -notin '', 'Any', '*') -or $r.Owner) }
}
$active = 0; try { $active = (New-Object -ComObject HNetCfg.FwPolicy2).CurrentProfileTypes } catch {}
@{ active = $active; unreadable = $unreadable; profiles = $profiles; rules = @($rules) } |
  ConvertTo-Json -Depth 4 -Compress
"""


def read_state() -> FirewallState:
    encoded = base64.b64encode(_PS_SCRIPT.encode("utf-16-le")).decode("ascii")
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, stdin=subprocess.DEVNULL, timeout=CHECK_TIMEOUT_S, check=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return parse_state(json.loads(completed.stdout.decode("utf-8-sig")))


def current_programs() -> tuple[str, ...]:
    """Path of the process that owns the socket (a venv launcher starts the base interpreter)."""
    if sys.platform == "win32":
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if kernel32.QueryFullProcessImageNameW(kernel32.GetCurrentProcess(), 0, buffer, ctypes.byref(size)):
            return (buffer.value,)
    return (getattr(sys, "_base_executable", "") or sys.executable,)


def firewall_rule_command(port: int, protocol: Transport = "UDP") -> str:
    return (f'New-NetFirewallRule -DisplayName "Syslog Monitor {protocol} {port}" -Direction Inbound '
            f"-Protocol {'TCP' if protocol == 'TLS' else protocol} -LocalPort {port} -Action Allow")


def firewall_unblock_command(port: int, program: str, protocol: Transport = "UDP") -> str:
    """Remove the block rules Windows creates for a new program (when nobody with admin
    rights allowed it on first use) and add the port rule."""
    quoted = program.replace("'", "''")
    return (f"Get-NetFirewallApplicationFilter -Program '{quoted}' | Get-NetFirewallRule | "
            "Where-Object Action -eq Block | Remove-NetFirewallRule; " + firewall_rule_command(port, protocol))


def remedy(check: FirewallCheck, port: int, program: str,
           protocol: Transport = "UDP") -> tuple[tuple[str, ...], str | None]:
    """Explanation lines and an optional admin PowerShell command for the details dialog."""
    if check.endpoint_checks:
        all_lines: list[str] = []
        commands: list[str] = []
        for endpoint_protocol, endpoint_port, endpoint_check in check.endpoint_checks:
            lines, command = remedy(endpoint_check, endpoint_port, program, endpoint_protocol)
            if lines:
                all_lines.extend((f"{endpoint_protocol} {endpoint_port}:", *lines))
            if command:
                commands.append(command)
        return tuple(all_lines), "; ".join(commands) if commands else None
    if check.level == Level.WARNING:
        command = firewall_rule_command(port, protocol)
        return ("Create allow rule (once, in an elevated PowerShell):", command), command
    if check.level == Level.ERROR:
        command = firewall_unblock_command(port, program, protocol)
        return (
            "Block rules take precedence over allow rules.",
            "When a new program is started without administrator rights, Windows often "
            "automatically creates block rules for its name. Remove them and replace them "
            "with an allow rule using this command in an elevated PowerShell:",
            command,
            "Rules set by IT (group policy) cannot be changed locally.",
        ), command
    return (), None


def check_firewalls(bind_host: str, endpoints: tuple[ListenerEndpoint, ...]) -> FirewallCheck:
    if not endpoints:
        return FirewallCheck(Level.UNKNOWN, "No syslog listener is enabled")
    if bind_host.startswith("127.") or bind_host == "localhost":
        return FirewallCheck(Level.OK, "Local-only listener; firewall is not relevant")
    if sys.platform != "win32":
        return FirewallCheck(Level.UNKNOWN, "Firewall checks are only available on Windows")
    try:
        state, programs = read_state(), current_programs()
        checks = tuple((protocol, port, assess(state, port, programs, protocol))
                       for protocol, port in endpoints)
        level = max(check.level for _, _, check in checks)
        summary = "; ".join(check.summary for _, _, check in checks)
        details = tuple(
            detail if len(checks) == 1 else f"{protocol} {port}: {detail}"
            for protocol, port, check in checks for detail in check.details)
        return FirewallCheck(level, summary, details, checks)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        log.warning("Firewall check failed: %s", exc)
        return FirewallCheck(Level.UNKNOWN, "Could not check the firewall", (str(exc)[:300],))


def check_firewall(bind_host: str, port: int, protocol: Transport = "UDP") -> FirewallCheck:
    return check_firewalls(bind_host, ((protocol, port),))
