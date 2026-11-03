import sys

import pytest

from syslog_monitor import firewall
from syslog_monitor.firewall import (
    ALL_PROFILES, FirewallCheck, FirewallState, Level, ProfileState, Rule, app_matches, assess, check_firewall,
    parse_profiles, parse_protocol, parse_state, port_matches,
)

PY = r"C:\Python311\python.exe"
DOMAIN, PRIVATE, PUBLIC = 1, 2, 4


def state(*rules: Rule, active=PRIVATE, **profile) -> FirewallState:
    return FirewallState(active, {p: ProfileState(**profile) for p in (1, 2, 4)}, rules)


@pytest.mark.parametrize("spec,expected", [
    ("*", True), ("", True), (None, True), ("Any", True), ("514", True), ("5514", False), ("100-600", True),
    ("80,443,514", True), ("80, 500-520", True), ("RPC", False), ("RPC,514", True), ("515-600", False),
])
def test_port_matches(spec, expected):
    assert port_matches(spec, 514) is expected


def test_app_matches_normalizes_paths(monkeypatch):
    monkeypatch.setenv("PYHOME", r"C:\Python311")
    assert app_matches("", (PY,))
    assert app_matches("*", (PY,))
    assert app_matches("Any", (PY,))
    assert app_matches(r"c:\python311\PYTHON.EXE", (PY,))
    assert app_matches(r"%PYHOME%\python.exe", (PY,))
    assert not app_matches(r"C:\Other\python.exe", (PY,))


def test_allow_rule_for_program_is_ok():
    check = assess(state(Rule("python.exe", block=False, application=PY)), 514, (PY,))
    assert check.level == Level.OK
    assert "python.exe" in check.details[0]


def test_block_rule_wins_over_allow_rule():
    check = assess(state(Rule("Syslog", block=False, local_ports="514"),
                         Rule("python.exe", block=True, application=PY)), 514, (PY,))
    assert check.level == Level.ERROR
    assert "python.exe" in check.details[0]


def test_missing_rule_with_default_block_warns():
    check = assess(state(Rule("other port", block=False, local_ports="5514"),
                         Rule("tcp only", block=False, protocol=6),
                         Rule("other app", block=False, application=r"C:\x.exe")), 514, (PY,))
    assert check.level == Level.WARNING
    assert "not allowed" in check.summary


def test_rule_for_other_profile_does_not_apply():
    rule = Rule("python.exe", block=False, application=PY, profiles=DOMAIN | PUBLIC)
    assert assess(state(rule, active=PRIVATE), 514, (PY,)).level == Level.WARNING
    assert assess(state(rule, active=DOMAIN), 514, (PY,)).level == Level.OK


def test_worst_active_profile_wins():
    rule = Rule("python.exe", block=False, application=PY, profiles=DOMAIN)
    check = assess(state(rule, active=DOMAIN | PUBLIC), 514, (PY,))
    assert check.level == Level.WARNING
    assert len(check.details) == 2


def test_service_and_app_package_rules_are_ignored():
    rules = (Rule("Microsoft Store", block=False, restricted=True),
             Rule("svc block", block=True, restricted=True))
    assert assess(state(*rules), 514, (PY,)).level == Level.WARNING


def test_profile_switches():
    assert assess(state(enabled=False), 514, (PY,)).level == Level.OK
    assert assess(state(default_block=False), 514, (PY,)).level == Level.OK
    assert assess(state(Rule("all", block=False), block_all_inbound=True), 514, (PY,)).level == Level.ERROR


def test_group_policy_can_disable_local_rules():
    local = Rule("python.exe", block=False, application=PY)
    gpo = Rule("IT syslog", block=False, local_ports="514", group_policy=True)
    no_local = {"allow_local_rules": False}
    check = assess(state(local, **no_local), 514, (PY,))
    assert check.level == Level.WARNING
    assert any("group policy" in d for d in check.details)
    assert assess(state(local, gpo, **no_local), 514, (PY,)).level == Level.OK
    local_block = Rule("old block", block=True, application=PY)
    assert assess(state(gpo, local_block, **no_local), 514, (PY,)).level == Level.OK
    assert assess(state(gpo, local_block), 514, (PY,)).level == Level.ERROR


def test_unreadable_rules_and_missing_profile_are_reported():
    check = assess(FirewallState(PRIVATE, {}, (Rule("all", block=False),), unreadable_rules=2), 514, (PY,))
    assert check.level == Level.OK and "2 rule(s)" in check.details[-1]
    assert assess(FirewallState(0, {}), 514, (PY,)).level == Level.UNKNOWN


@pytest.mark.parametrize("value,expected", [
    ("UDP", 17), ("Any", 256), ("", 256), (None, 256), ("17", 17), ("TCP", 6), ("ICMPv4", -1)])
def test_parse_protocol(value, expected):
    assert parse_protocol(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("Any", ALL_PROFILES), ("Domain, Public", 5), ("Private", 2), (None, ALL_PROFILES), (4, 4), (0, ALL_PROFILES)])
def test_parse_profiles(value, expected):
    assert parse_profiles(value) == expected


def test_parse_state_from_powershell_json():
    data = {"active": 5, "unreadable": 1,
            "profiles": {"1": {"enabled": True, "block_all": False, "default_block": False, "allow_local": True},
                         "2": {"enabled": False, "block_all": False, "default_block": True, "allow_local": True},
                         "4": {"enabled": True, "block_all": False, "default_block": True, "allow_local": False}},
            "rules": [{"name": "python.exe", "block": False, "protocol": "UDP", "ports": "Any",
                       "profiles": "Domain, Public", "app": PY, "gpo": False, "restricted": False},
                      {"name": "Store", "block": True, "protocol": "Any", "ports": "",
                       "profiles": "Any", "app": "Any", "gpo": True, "restricted": True}]}
    parsed = parse_state(data)
    assert parsed.active_profiles == 5 and parsed.unreadable_rules == 1
    assert not parsed.profiles[2].enabled and not parsed.profiles[1].default_block
    assert not parsed.profiles[4].allow_local_rules
    assert parsed.rules[0] == Rule("python.exe", block=False, protocol=17, local_ports="Any",
                                   profiles=5, application=PY)
    assert parsed.rules[1].restricted and parsed.rules[1].block and parsed.rules[1].group_policy
    assert parsed.rules[1].profiles == ALL_PROFILES


def test_loopback_needs_no_firewall(monkeypatch):
    monkeypatch.setattr(firewall, "read_state", lambda: pytest.fail("must not read"))
    assert check_firewall("127.0.0.1", 514).level == Level.OK


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_read_failure_is_reported_as_unknown(monkeypatch):
    def broken():
        raise OSError("powershell missing")
    monkeypatch.setattr(firewall, "read_state", broken)
    check = check_firewall("0.0.0.0", 514)
    assert check.level == Level.UNKNOWN and "powershell missing" in check.details[0]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_reads_real_firewall_without_admin():
    real = firewall.read_state()
    assert set(real.profiles) == {1, 2, 4}
    assert check_firewall("0.0.0.0", 514).level in (Level.OK, Level.WARNING, Level.ERROR)
    assert firewall.current_programs()[0].lower().endswith(".exe")


def test_remedy_offers_matching_admin_command():
    exe = r"C:\Apps\O'Brien\SyslogMonitor.exe"
    lines, command = firewall.remedy(FirewallCheck(Level.WARNING, "x"), 514, exe)
    assert command == firewall.firewall_rule_command(514) and command in lines
    assert "-LocalPort 514" in command and "Remove" not in command
    lines, command = firewall.remedy(FirewallCheck(Level.ERROR, "x"), 1514, exe)
    assert "-Program 'C:\\Apps\\O''Brien\\SyslogMonitor.exe'" in command
    assert "Where-Object Action -eq Block | Remove-NetFirewallRule" in command
    assert command.endswith(firewall.firewall_rule_command(1514)) and command in lines
    assert firewall.remedy(FirewallCheck(Level.OK, "x"), 514, exe) == ((), None)
    assert firewall.remedy(FirewallCheck(Level.UNKNOWN, "x"), 514, exe) == ((), None)
