from datetime import datetime, timezone

import pytest

from syslog_monitor.parser import parse_datagram, split_structured_data


def parse(data: bytes):
    return parse_datagram(data, "192.0.2.1", 40000, 1234)


def test_rfc5424_full():
    raw = (b'<165>1 2003-10-11T22:14:15.003Z device.example.com service 99 ID47 '
           b'[exampleSDID@32473 iut="3" eventSource="App\\"lic]ation"] \xef\xbb\xbfService started')
    ev = parse(raw)
    assert ev.format == "rfc5424"
    assert (ev.facility, ev.severity) == (20, 5)
    assert ev.hostname == "device.example.com"
    assert (ev.app_name, ev.procid, ev.msgid) == ("service", "99", "ID47")
    assert ev.structured_data == '[exampleSDID@32473 iut="3" eventSource="App\\"lic]ation"]'
    assert ev.message == "Service started"
    expected = datetime(2003, 10, 11, 22, 14, 15, 3000, tzinfo=timezone.utc)
    assert ev.reported_time_utc == int(expected.timestamp() * 1000)
    assert ev.issues == ()
    assert (ev.source_ip, ev.source_port, ev.received_at, ev.raw) == ("192.0.2.1", 40000, 1234, raw)


def test_rfc5424_nil_values_and_offset():
    ev = parse(b"<34>1 2003-08-24T05:14:15.000003-07:00 - - - - - msg")
    assert ev.hostname is None and ev.app_name is None and ev.structured_data is None
    assert ev.message == "msg"
    assert ev.reported_time_utc == int(datetime(2003, 8, 24, 12, 14, 15, tzinfo=timezone.utc).timestamp() * 1000)


def test_rfc5424_without_message_and_multiple_sd():
    ev = parse(b'<13>1 - h a - - [a@1 x="1"][b@2 y="]"]')
    assert ev.structured_data == '[a@1 x="1"][b@2 y="]"]'
    assert ev.message == ""
    assert ev.reported_time_text is None


def test_rfc5424_bad_timestamp_and_unterminated_sd():
    ev = parse(b'<13>1 yesterday h a - - [broken x="1" rest')
    assert "bad_timestamp" in ev.issues
    assert "bad_structured_data" in ev.issues
    assert ev.message == '[broken x="1" rest'


def test_rfc5424_timestamp_without_zone_is_not_utc():
    ev = parse(b"<13>1 2024-01-01T10:00:00 h a - - - x")
    assert ev.reported_time_text == "2024-01-01T10:00:00"
    assert ev.reported_time_utc is None
    assert "bad_timestamp" in ev.issues


@pytest.mark.parametrize("timestamp", [
    b"9999-12-31T23:59:59-23:59", b"0001-01-01T00:00:00+23:59",
])
def test_extreme_timestamp_is_recorded_as_invalid_instead_of_crashing(timestamp):
    ev = parse(b"<13>1 " + timestamp + b" host app - - - message")
    assert ev.reported_time_text == timestamp.decode()
    assert ev.reported_time_utc is None
    assert "bad_timestamp" in ev.issues
    assert ev.message == "message"


def test_rfc3164_with_host_and_tag():
    ev = parse(b"<34>Oct 11 22:14:15 testbox su[123]: login failed for user1 on /dev/pts/8\n")
    assert ev.format == "rfc3164"
    assert (ev.facility, ev.severity) == (4, 2)
    assert ev.reported_time_text == "Oct 11 22:14:15"
    assert ev.reported_time_utc is None  # no year / zone in BSD format
    assert (ev.hostname, ev.app_name, ev.procid) == ("testbox", "su", "123")
    assert ev.message == "login failed for user1 on /dev/pts/8"


def test_rfc3164_space_padded_day_without_host():
    ev = parse(b"<13>Feb  5 01:02:03 sshd: Accepted key")
    assert ev.reported_time_text == "Feb  5 01:02:03"
    assert ev.hostname is None
    assert ev.app_name == "sshd"
    assert ev.message == "Accepted key"


def test_rfc3164_iso_timestamp():
    ev = parse(b"<11>2024-05-01T12:00:00+02:00 router kernel: link down")
    assert ev.reported_time_utc == int(datetime(2024, 5, 1, 10, tzinfo=timezone.utc).timestamp() * 1000)
    assert (ev.hostname, ev.app_name, ev.message) == ("router", "kernel", "link down")


def test_pri_only_free_text():
    ev = parse(b"<14>just some text")
    assert ev.severity == 6
    assert ev.message == "just some text"
    assert "no_timestamp" in ev.issues


def test_missing_pri_keeps_message():
    ev = parse(b"plain message without header")
    assert ev.format == "unparsed"
    assert ev.severity is None and ev.facility is None
    assert ev.message == "plain message without header"
    assert ev.issues == ("no_pri",)


def test_invalid_pri():
    ev = parse(b"<999>x")
    assert ev.severity is None
    assert "invalid_pri" in ev.issues
    assert ev.message == "<999>x"


def test_invalid_utf8_is_readable():
    ev = parse(b"<14>bad \xff\xfe bytes")
    assert "invalid_utf8" in ev.issues
    assert "\\xff\\xfe" in ev.message
    assert ev.raw == b"<14>bad \xff\xfe bytes"


def test_large_datagram_not_truncated():
    body = b"x" * 60000
    ev = parse(b"<14>" + body)
    assert len(ev.message) == 60000


def test_empty_datagram():
    ev = parse(b"")
    assert ev.message == ""
    assert "no_pri" in ev.issues


def test_split_structured_data_nil():
    assert split_structured_data("- msg") == (None, " msg", True)
