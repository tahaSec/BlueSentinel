from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from backend.collectors import windows_collector as collector
from backend.collectors.windows_collector import CollectorError
from backend.models.security_event import SecurityEvent


class FakeEvent:
    EventID = 4625
    SourceName = "Microsoft-Windows-Security-Auditing"
    ComputerName = "TEST-PC"
    TimeGenerated = datetime(2025, 1, 1, 3, 0, tzinfo=timezone.utc)
    StringInserts = ["S-1", "svc", "DOMAIN", "0x0", "S-1", "alice"]


@pytest.fixture
def fake_windows_api(monkeypatch):
    batches = [[FakeEvent(), FakeEvent()], [FakeEvent()], []]
    calls = {"reads": 0, "closed": [], "token_closed": []}
    api = SimpleNamespace(
        GetCurrentProcess=lambda: "process",
        SetLastError=lambda value: None,
        GetLastError=lambda: 0,
        CloseHandle=lambda token: calls["token_closed"].append(token),
    )
    security = SimpleNamespace(
        OpenProcessToken=lambda process, access: "token",
        LookupPrivilegeValue=lambda system, name: "privilege",
        AdjustTokenPrivileges=lambda token, disable, privileges: None,
    )
    evtlog = SimpleNamespace(
        EVENTLOG_BACKWARDS_READ=1,
        EVENTLOG_SEQUENTIAL_READ=2,
        OpenEventLog=lambda server, log: "handle",
        ReadEventLog=lambda handle, flags, offset: (
            calls.__setitem__("reads", calls["reads"] + 1) or batches.pop(0)
        ),
        CloseEventLog=lambda handle: calls["closed"].append(handle),
    )
    con = SimpleNamespace(
        TOKEN_ADJUST_PRIVILEGES=1,
        TOKEN_QUERY=2,
        SE_PRIVILEGE_ENABLED=4,
        ERROR_NOT_ALL_ASSIGNED=1300,
    )
    for name, value in (("win32api", api), ("win32security", security),
                        ("win32evtlog", evtlog), ("win32con", con)):
        monkeypatch.setattr(collector, name, value)
    return calls, api, security


def test_collector_reads_multiple_batches_and_returns_model(fake_windows_api):
    calls, _, _ = fake_windows_api
    events = collector.collect_failed_logins(max_events=3)
    assert len(events) == 3
    assert all(isinstance(event, SecurityEvent) for event in events)
    assert events[0].username == "alice"
    assert events[0].computer == "TEST-PC"
    assert events[0].timestamp == datetime(2025, 1, 1, 3, 0, tzinfo=timezone.utc)
    assert calls["reads"] == 2
    assert calls["closed"] == ["handle"]
    assert calls["token_closed"] == ["token"]


def test_report_counts_scanned_and_matching_records(fake_windows_api):
    result = collector.collect_failed_logins_with_report(max_events=3)
    assert result.summary.records_scanned == 3
    assert result.summary.event_count == 3
    assert result.summary.max_records_reached is False
    assert result.summary.completed_normally is False


def test_report_marks_normal_end_of_log(fake_windows_api, monkeypatch):
    monkeypatch.setattr(collector.win32evtlog, "ReadEventLog", lambda *args: [])
    result = collector.collect_failed_logins_with_report()
    assert result.summary.records_scanned == 0
    assert result.summary.event_count == 0
    assert result.summary.max_records_reached is False
    assert result.summary.completed_normally is True


def test_report_marks_record_limit(fake_windows_api, monkeypatch):
    nonmatching_batch = [SimpleNamespace(EventID=1), SimpleNamespace(EventID=2)]
    monkeypatch.setattr(
        collector.win32evtlog, "ReadEventLog", lambda *args: nonmatching_batch
    )
    result = collector.collect_failed_logins_with_report(max_records=2)
    assert result.summary.records_scanned == 2
    assert result.summary.event_count == 0
    assert result.summary.max_records_reached is True
    assert result.summary.completed_normally is False


def test_report_for_zero_limits_does_not_call_windows(monkeypatch):
    monkeypatch.setattr(collector, "win32api", None)
    result = collector.collect_failed_logins_with_report(max_records=0)
    assert result.summary.records_scanned == 0
    assert result.summary.event_count == 0
    assert result.summary.max_records_reached is True
    assert result.summary.completed_normally is False


def test_collector_respects_zero_limit_without_windows_calls(monkeypatch):
    monkeypatch.setattr(collector, "win32api", None)
    assert collector.collect_failed_logins(0) == []


def test_collector_respects_zero_record_limit_without_windows_calls(monkeypatch):
    monkeypatch.setattr(collector, "win32api", None)
    assert collector.collect_failed_logins(max_records=0) == []


def test_collector_stops_at_max_records_even_with_unmatched_records(
    fake_windows_api, monkeypatch
):
    calls, _, _ = fake_windows_api

    class UnreadableEvent:
        @property
        def EventID(self):
            raise AssertionError("record beyond max_records was inspected")

    batch = [SimpleNamespace(EventID=1), SimpleNamespace(EventID=2), UnreadableEvent()]
    def read_batch(*args):
        calls["reads"] += 1
        return batch

    monkeypatch.setattr(collector.win32evtlog, "ReadEventLog", read_batch)
    assert collector.collect_failed_logins(max_records=2) == []
    assert calls["reads"] == 1
    assert calls["closed"] == ["handle"]


def test_collector_default_max_records_is_500(fake_windows_api, monkeypatch):
    calls, _, _ = fake_windows_api

    class UnreadableEvent:
        @property
        def EventID(self):
            raise AssertionError("collector read beyond its default record cap")

    batch = [SimpleNamespace(EventID=1) for _ in range(500)] + [UnreadableEvent()]
    monkeypatch.setattr(collector.win32evtlog, "ReadEventLog", lambda *args: batch)
    assert collector.collect_failed_logins() == []
    assert calls["closed"] == ["handle"]


@pytest.mark.parametrize("limit", [-1, 1.5, True])
def test_collector_rejects_invalid_limit(limit):
    with pytest.raises(ValueError):
        collector.collect_failed_logins(limit)


@pytest.mark.parametrize("limit", [-1, 1.5, True])
def test_collector_rejects_invalid_record_limit(limit):
    with pytest.raises(ValueError):
        collector.collect_failed_logins(max_records=limit)


def test_missing_privilege_is_reported(fake_windows_api):
    _, api, security = fake_windows_api
    api.GetLastError = lambda: 1300
    with pytest.raises(CollectorError, match="not assigned"):
        collector.enable_security_privilege()


def test_collector_failure_closes_event_log(fake_windows_api, monkeypatch):
    calls, _, _ = fake_windows_api
    monkeypatch.setattr(
        collector.win32evtlog, "ReadEventLog",
        lambda *args: (_ for _ in ()).throw(OSError("read failed")),
    )
    with pytest.raises(CollectorError, match="Failed to read"):
        collector.collect_failed_logins()
    assert calls["closed"] == ["handle"]


def test_privilege_enable_failure_is_not_silent(fake_windows_api, monkeypatch):
    _, _, security = fake_windows_api
    monkeypatch.setattr(
        security, "AdjustTokenPrivileges",
        lambda *args: (_ for _ in ()).throw(OSError("denied")),
    )
    with pytest.raises(CollectorError, match="Could not enable"):
        collector.enable_security_privilege()


def test_security_collector_supports_multiple_ids_and_since_filter(fake_windows_api, monkeypatch):
    older = SimpleNamespace(
        EventID=4625, SourceName="Security", ComputerName="LAB",
        TimeGenerated=datetime(2024, 12, 31, tzinfo=timezone.utc),
        StringInserts=["", "", "", "", "", "old-user"],
    )
    success = SimpleNamespace(
        EventID=4624, SourceName="Security", ComputerName="LAB",
        TimeGenerated=datetime(2025, 1, 1, tzinfo=timezone.utc),
        StringInserts=["", "", "", "", "", "alice", "DOMAIN", "", "3"],
    )
    privileged = SimpleNamespace(
        EventID=4672, SourceName="Security", ComputerName="LAB",
        TimeGenerated=datetime(2025, 1, 1, tzinfo=timezone.utc),
        StringInserts=["", "admin", "DOMAIN", "", "SeDebugPrivilege"],
    )
    monkeypatch.setattr(
        collector.win32evtlog, "ReadEventLog", lambda *args: [success, privileged, older]
    )

    result = collector.collect_security_events_with_report(
        {4624, 4625, 4672}, since=datetime(2025, 1, 1, tzinfo=timezone.utc)
    )
    assert [item.event_id for item in result.events] == [4624, 4672]
    assert result.events[0].username == "alice"
    assert result.events[0].logon_type == "3"
    assert result.events[1].username == "admin"
    assert result.summary.records_scanned == 3


def test_security_collector_skips_malformed_record_and_continues(
    fake_windows_api, monkeypatch, caplog
):
    class MalformedEvent:
        @property
        def EventID(self):
            raise ValueError("bad event")

    batches = [[MalformedEvent(), FakeEvent()], []]
    monkeypatch.setattr(collector.win32evtlog, "ReadEventLog", lambda *args: batches.pop(0))
    result = collector.collect_failed_logins_with_report(max_events=5)
    assert result.summary.records_scanned == 2
    assert result.summary.event_count == 1
    assert result.summary.completed_normally is True
    assert "Skipping malformed Security event" in caplog.text


def test_failed_logon_fields_use_target_account_and_correct_network_positions():
    inserts = ["-", "SYSTEM", "LOCAL", "0x3e7", "S-1-0-0", "alice", "LAB"]
    inserts.extend(["status", "reason", "substatus", "10", "User32", "Negotiate", "WORKSTATION"])
    inserts.extend(["-", "-", "0", "0x123", r"C:\Windows\System32\winlogon.exe", "203.0.113.7", "51422"])
    mapped = collector._event_fields(4625, inserts)
    assert mapped["username"] == "alice"
    assert mapped["domain"] == "LAB"
    assert mapped["logon_type"] == "10"
    assert mapped["source_ip"] == "203.0.113.7"


def test_successful_logon_fields_use_documented_network_and_logon_positions():
    inserts = ["subject-sid", "service", "LAB", "0x3e7", "target-sid", "alice", "LAB"]
    inserts.extend(["0x44", "3", "User32", "Negotiate", "WORKSTATION"])
    inserts.extend(["guid", "-", "-", "0", "0x200", "process.exe", "192.0.2.45", "443"])
    mapped = collector._event_fields(4624, inserts)
    assert mapped["username"] == "alice"
    assert mapped["account_sid"] == "target-sid"
    assert mapped["logon_type"] == "3"
    assert mapped["source_ip"] == "192.0.2.45"


def test_account_and_group_change_fields_use_the_target_member():
    created = collector._event_fields(4720, ["new-user", "LAB", "sid", "subject-sid", "admin"])
    assert created["username"] == "new-user"
    assert created["domain"] == "LAB"
    assert created["account_sid"] == "sid"

    # 4732 starts with MemberName and MemberSid, then group and subject fields.
    added = collector._event_fields(4732, [
        "CN=new-user,CN=Users,DC=lab,DC=example", "member-sid", "Administrators",
        "LAB", "group-sid", "subject-sid", "admin", "LAB", "0x44", "-",
    ])
    assert added["username"] == "new-user"
    assert added["account_sid"] == "member-sid"
    assert added["domain"] is None

    locked = collector._event_fields(4740, ["new-user", "LAB", "sid", "SYSTEM"])
    assert locked["username"] == "new-user"
    assert locked["domain"] == "LAB"
    assert locked["account_sid"] == "sid"


def test_process_and_explicit_credentials_fields_use_documented_positions():
    process_inserts = [
        "sid", "creator", "LAB", "0x44", "0x200", r"C:\\Tools\\demo.exe",
        "%%1938", "0xe74", "demo.exe -arg", "target-sid", "target", "LAB",
        "0x99", r"C:\\Windows\\explorer.exe",
    ]
    process = collector._event_fields(4688, process_inserts)
    assert process["process_name"] == "demo.exe"
    assert process["command_line"] == "demo.exe -arg"
    assert process["parent_process"] == r"C:\\Windows\\explorer.exe"

    explicit = collector._event_fields(4648, [
        "subject-sid", "caller", "LAB", "0x1", "guid", "credential-user",
        "DOMAIN", "target-guid", "server", "info", "0x44", "proc.exe", "::1", "445",
    ])
    assert explicit["username"] == "credential-user"
    assert explicit["domain"] == "DOMAIN"
    assert explicit["source_ip"] == "::1"
