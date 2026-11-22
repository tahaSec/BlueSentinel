from datetime import datetime, timedelta, timezone
import json

import pytest

from backend.detection.engine import DetectionEngine
from backend.detection.rule_loader import RuleValidationError, load_rules, validate_rule
from backend.models.security_event import SecurityEvent


BASE = datetime(2025, 1, 1, tzinfo=timezone.utc)


def event(event_id, seconds=0, username="alice", source="Windows Security", **fields):
    return SecurityEvent(
        event_id=event_id, source=source, computer="LAB", timestamp=BASE + timedelta(seconds=seconds),
        username=username, description=fields.pop("description", None), **fields
    )


def test_rule_directory_loads_ten_validated_rules():
    rules = load_rules("rules")
    assert len(rules) == 10
    assert {rule["detector"] for rule in rules} == {
        "brute_force", "suspicious_successful_login", "privileged_logon",
        "suspicious_process", "account_change", "network_burst", "event_correlation",
    }


def test_rule_loader_rejects_invalid_threshold():
    rule = {
        "id": "X", "name": "Bad", "description": "Bad", "detector": "brute_force",
        "sources": ["Windows Security"], "conditions": {"event_ids": [4625]},
        "enabled": True, "severity": "HIGH", "mitre": [], "mitre_tactics": [],
        "options": {"threshold": 0}, "recommended_actions": [],
    }
    with pytest.raises(RuleValidationError):
        validate_rule(rule)


def test_rule_loader_rejects_invalid_brute_force_group_by():
    rule = next(rule for rule in load_rules("rules") if rule["detector"] == "brute_force")
    rule["options"]["group_by"] = ["computer"]
    with pytest.raises(RuleValidationError, match="group_by"):
        validate_rule(rule)


def test_rule_loader_rejects_duplicate_ids(tmp_path):
    rule = {
        "id": "DUP", "name": "Rule", "description": "Description",
        "detector": "privileged_logon", "sources": ["Windows Security"],
        "conditions": {"event_ids": [4672]}, "enabled": True,
        "severity": "MEDIUM", "mitre": [], "mitre_tactics": [],
        "options": {}, "recommended_actions": [],
    }
    (tmp_path / "one.json").write_text(json.dumps(rule), encoding="utf-8")
    (tmp_path / "two.json").write_text(json.dumps(rule), encoding="utf-8")
    with pytest.raises(RuleValidationError, match="duplicate rule id"):
        load_rules(str(tmp_path))


def test_success_after_repeated_failures_creates_explainable_signal():
    engine = DetectionEngine(load_rules("rules"))
    events = [event(4625, seconds=value) for value in (0, 20, 40)] + [event(4624, seconds=50)]
    alerts = engine.detect(events)
    alert = next(item for item in alerts if item.rule_id == "BS-002")
    assert alert.event_count == 4
    assert alert.attack_techniques == ["T1078"]
    assert len(alert.evidence) == 4


def test_success_after_failures_groups_username_case_variants():
    engine = DetectionEngine(load_rules("rules"))
    events = [event(4625, seconds=value, username="Alice") for value in (0, 20, 40)]
    events.append(event(4624, seconds=50, username="alice"))
    alerts = engine.detect(events)
    assert any(alert.rule_id == "BS-002" for alert in alerts)


def test_success_after_failures_does_not_mix_same_name_across_domains():
    engine = DetectionEngine(load_rules("rules"))
    events = [event(4625, seconds=value, username="alice", domain="DOMAIN-A")
              for value in (0, 20, 40)]
    events.append(event(4624, seconds=50, username="alice", domain="DOMAIN-B"))
    assert not any(alert.rule_id == "BS-002" for alert in engine.detect(events))


def test_privileged_logon_and_account_changes_have_event_specific_mapping():
    engine = DetectionEngine(load_rules("rules"))
    alerts = engine.detect([event(4672), event(4720, seconds=1), event(4732, seconds=2)])
    by_event_rule = {alert.rule_id: alert for alert in alerts}
    account_alerts = [alert for alert in alerts if alert.rule_id == "BS-005"]
    assert by_event_rule["BS-003"].attack_techniques == []
    assert [item.attack_techniques for item in account_alerts] == [["T1136"], ["T1098.007"]]


def test_process_indicator_and_network_burst_are_detected():
    engine = DetectionEngine(load_rules("rules"))
    events = [event(1, description="powershell.exe -enc Zg==", source="Sysmon")]
    events.extend(
        event(3, seconds=index, source_ip="10.0.0.1", source="Sysmon")
        for index in range(50)
    )
    alerts = engine.detect(events)
    assert any(alert.rule_id == "BS-004" and alert.attack_techniques == ["T1059.001"] for alert in alerts)
    assert any(alert.rule_id == "BS-006" and alert.event_count == 50 for alert in alerts)


def test_network_burst_groups_by_source_ip_across_multiple_usernames():
    engine = DetectionEngine(load_rules("rules"))
    events = [
        event(3, seconds=index, source="Sysmon", source_ip="192.0.2.55",
              username="user-{}".format(index % 7))
        for index in range(50)
    ]
    alerts = [item for item in engine.detect(events) if item.rule_id == "BS-006"]
    ip_alert = next(item for item in alerts if "source_ip:192.0.2.55" in item.correlation_keys)
    assert ip_alert.event_count == 50
    assert ip_alert.username is None


def test_disabled_rule_does_not_execute():
    rule = {
        "id": "OFF", "name": "Disabled", "description": "No run", "detector": "privileged_logon",
        "sources": ["Windows Security"], "conditions": {"event_ids": [4672]},
        "enabled": False, "severity": "MEDIUM", "mitre": [], "mitre_tactics": [], "options": {},
        "recommended_actions": [],
    }
    assert DetectionEngine([rule]).detect([event(4672)]) == []


def test_rule_source_scope_is_enforced():
    engine = DetectionEngine(load_rules("rules"))
    events = [event(4625, seconds=seconds, source="Sysmon") for seconds in range(5)]
    assert not any(alert.rule_id == "BS-001" for alert in engine.detect(events))


@pytest.mark.parametrize("case", ["privileged", "process_network", "account_group", "lockout"])
def test_ordered_event_correlations(case):
    engine = DetectionEngine(load_rules("rules"))
    if case == "privileged":
        events = [event(4624, account_sid="S-1-5-21-123"),
                  event(4672, seconds=30, account_sid="S-1-5-21-123")]
        expected_rule = "BS-007"
    elif case == "process_network":
        events = [
            event(1, source="Sysmon", process_name="powershell.exe"),
            event(3, seconds=30, source="Sysmon", process_name="powershell.exe"),
        ]
        expected_rule = "BS-008"
    elif case == "account_group":
        events = [event(4720, account_sid="S-1-5-21-456"),
                  event(4732, seconds=30, account_sid="S-1-5-21-456")]
        expected_rule = "BS-009"
    else:
        events = [event(4625, account_sid="S-1-5-21-789"),
                  event(4740, seconds=30, account_sid="S-1-5-21-789")]
        expected_rule = "BS-010"

    alerts = engine.detect(list(reversed(events)))
    alert = next(item for item in alerts if item.rule_id == expected_rule)
    assert alert.event_count == 2
    assert [item["event_id"] for item in alert.evidence] == [events[0].event_id, events[1].event_id]
    assert alert.correlation_keys


def test_event_correlation_rejects_different_identities_and_out_of_window():
    engine = DetectionEngine(load_rules("rules"))
    different_accounts = [
        event(4624, username="alice", account_sid="S-1-1"),
        event(4672, 30, username="alice", account_sid="S-1-2"),
    ]
    too_late = [event(4624, account_sid="S-1-1"), event(4672, 301, account_sid="S-1-1")]
    no_identity = [event(4624, username=None), event(4672, 30, username=None)]
    for events in (different_accounts, too_late, no_identity):
        assert not any(alert.rule_id == "BS-007" for alert in engine.detect(events))


def test_rule_loader_rejects_malformed_event_correlation_stages():
    rule = {
        "id": "CHAIN", "name": "Bad chain", "description": "Bad stages",
        "detector": "event_correlation", "sources": ["Windows Security"],
        "conditions": {"event_ids": [4624, 4672], "stages": [[4624], []]},
        "enabled": True, "severity": "MEDIUM", "mitre": [], "mitre_tactics": [],
        "options": {"window_seconds": 60, "correlation_fields": ["username"]},
        "recommended_actions": [],
    }
    with pytest.raises(RuleValidationError, match="conditions.stages"):
        validate_rule(rule)
