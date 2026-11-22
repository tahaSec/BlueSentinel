from datetime import datetime, timedelta, timezone

from backend.correlation.alert_correlator import correlate_alerts
from backend.models.detection_alert import DetectionAlert


BASE = datetime(2025, 1, 1, tzinfo=timezone.utc)


def alert(username, seconds, rule_id="R1", correlation_keys=None):
    stamp = BASE + timedelta(seconds=seconds)
    return DetectionAlert(
        rule_name=rule_id, username=username, event_count=5,
        first_seen=stamp, last_seen=stamp, threshold=5,
        window_seconds=60, attack_techniques=["T1110"], rule_id=rule_id,
        correlation_keys=correlation_keys or [],
    )


def test_correlates_same_user_alerts_within_window_and_sorts():
    groups = correlate_alerts([alert("alice", 100, "R2"), alert("alice", 0), alert("bob", 10)])
    assert len(groups) == 1
    assert groups[0].username == "alice"
    assert [item.rule_id for item in groups[0].alerts] == ["R1", "R2"]
    assert groups[0].attack_techniques == ["T1110"]


def test_does_not_group_missing_users_or_distant_alerts():
    groups = correlate_alerts([alert(None, 0), alert("alice", 0), alert("alice", 901)])
    assert groups == []


def test_correlates_distinct_accounts_by_shared_source_ip():
    groups = correlate_alerts([
        alert("alice", 0, correlation_keys=["source_ip:192.0.2.10"]),
        alert("bob", 30, "R2", ["source_ip:192.0.2.10"]),
    ])
    assert len(groups) == 1
    assert groups[0].username is None
    assert groups[0].correlation_keys == ["source_ip:192.0.2.10"]
    assert "source_ip:192.0.2.10" in groups[0].explanation


def test_correlates_username_case_variants_as_one_account():
    groups = correlate_alerts([alert("Alice", 0), alert("alice", 20, "R2")])
    assert len(groups) == 1
    assert groups[0].username == "Alice"


def test_domain_qualified_user_keys_do_not_merge_different_accounts():
    groups = correlate_alerts([
        alert("alice", 0, correlation_keys=["username:domain-a\\alice"]),
        alert("alice", 10, "R2", ["username:domain-b\\alice"]),
    ])
    assert groups == []
