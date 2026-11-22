from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from backend.collectors import windows_collector, sysmon_collector
from backend.collectors.windows_collector import CollectorError


def test_sysmon_collection_maps_supported_events_and_closes_handle(monkeypatch):
    calls = {"closed": []}
    values = [
        SimpleNamespace(
            EventID=1, ComputerName="LAB", TimeGenerated=datetime(2025, 1, 1, tzinfo=timezone.utc),
            StringInserts=["", "", "guid", "10", r"C:\Windows\powershell.exe", "LAB\\user",
                           "", "", "", "", "powershell.exe -enc Zg==", "", "LAB\\user",
                           "", "", "", "", "", "", "", "", r"C:\Windows\explorer.exe"],
        ),
        SimpleNamespace(
            EventID=3, ComputerName="LAB", TimeGenerated=datetime(2025, 1, 1, tzinfo=timezone.utc),
            StringInserts=["", "", "guid", "10", r"C:\app.exe", "LAB\\user", "tcp", "true",
                           "false", "10.0.0.2", "host", "50000", "", "false", "8.8.8.8"],
        ),
        SimpleNamespace(
            EventID=999, ComputerName="LAB", TimeGenerated=datetime(2025, 1, 1, tzinfo=timezone.utc),
            StringInserts=[],
        ),
    ]
    api = SimpleNamespace(
        EVENTLOG_BACKWARDS_READ=1, EVENTLOG_SEQUENTIAL_READ=2,
        OpenEventLog=lambda server, channel: "sysmon-handle",
        ReadEventLog=lambda *args: values,
        CloseEventLog=lambda handle: calls["closed"].append(handle),
    )
    monkeypatch.setattr(windows_collector, "win32evtlog", api)

    result = sysmon_collector.collect_sysmon_events_with_report(max_records=3)

    assert [item.event_id for item in result.events] == [1, 3]
    assert result.events[0].command_line == "powershell.exe -enc Zg=="
    assert result.events[1].destination_ip == "8.8.8.8"
    assert result.summary.records_scanned == 3
    assert result.summary.event_count == 2
    assert result.summary.max_records_reached is True
    assert calls["closed"] == ["sysmon-handle"]


def test_missing_sysmon_api_is_reported(monkeypatch):
    monkeypatch.setattr(windows_collector, "win32evtlog", None)
    with pytest.raises(CollectorError, match="requires pywin32"):
        sysmon_collector.collect_sysmon_events_with_report()


def test_sysmon_zero_limit_skips_windows_api(monkeypatch):
    monkeypatch.setattr(windows_collector, "win32evtlog", None)
    result = sysmon_collector.collect_sysmon_events_with_report(max_records=0)
    assert result.events == []
    assert result.summary.max_records_reached is True
