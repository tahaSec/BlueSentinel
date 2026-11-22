from datetime import datetime, timedelta, timezone

import pytest

from backend.detection.brute_force import detect_brute_force
from backend.models.security_event import SecurityEvent


START = datetime(2025, 1, 1, tzinfo=timezone.utc)


def make_event(event_id=4625, username="alice", seconds=0, domain=None):
    return SecurityEvent(
        event_id=event_id,
        source="Windows Security",
        computer="TEST-PC",
        timestamp=START + timedelta(seconds=seconds),
        username=username,
        description=None,
        domain=domain,
    )


def test_five_failed_logons_within_window_raise_alert():
    events = [make_event(seconds=seconds) for seconds in (0, 10, 20, 30, 60)]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].username == "alice"
    assert alerts[0].event_count == 5
    assert alerts[0].first_seen == START
    assert alerts[0].last_seen == START + timedelta(seconds=60)
    assert alerts[0].first_seen.tzinfo == timezone.utc


def test_four_failed_logons_do_not_raise_alert():
    events = [make_event(seconds=seconds) for seconds in (0, 10, 20, 30)]

    assert detect_brute_force(events) == []


def test_five_failed_logons_spanning_more_than_window_do_not_raise_alert():
    events = [make_event(seconds=seconds) for seconds in (0, 15, 30, 45, 61)]

    assert detect_brute_force(events) == []


def test_different_users_are_counted_separately():
    events = [
        make_event(username="alice", seconds=seconds)
        for seconds in (0, 10, 20)
    ] + [
        make_event(username="bob", seconds=seconds)
        for seconds in (30, 40, 50)
    ]

    assert detect_brute_force(events) == []


def test_username_case_variants_are_grouped_as_the_same_account():
    events = [
        make_event(username=name, seconds=index * 10)
        for index, name in enumerate(("Alice", "alice", "ALICE", "Alice", "alice"))
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0].username == "Alice"


def test_identical_usernames_in_different_domains_are_separate_accounts():
    events = [
        make_event(4625, seconds=offset, username="alice", domain="DOMAIN-A")
        for offset in (0, 10, 20)
    ] + [
        make_event(4625, seconds=offset, username="alice", domain="DOMAIN-B")
        for offset in (30, 40)
    ]
    assert detect_brute_force(events) == []


def test_brute_force_can_group_by_source_ip_when_accounts_differ():
    events = [
        SecurityEvent(
            event_id=4625, source="Windows Security", computer="LAB",
            timestamp=START + timedelta(seconds=index * 5), username="user-{}".format(index),
            description=None, source_ip="192.0.2.77",
        )
        for index in range(5)
    ]
    alerts = detect_brute_force(events, group_by=("username", "source_ip"))
    assert len(alerts) == 1
    assert alerts[0].username is None
    assert alerts[0].correlation_keys == ["source_ip:192.0.2.77"]


def test_username_alert_suppresses_duplicate_ip_alert_for_identical_evidence():
    events = [
        SecurityEvent(
            event_id=4625, source="Windows Security", computer="LAB",
            timestamp=START + timedelta(seconds=index * 5), username="alice",
            description=None, source_ip="192.0.2.77",
        )
        for index in range(5)
    ]
    alerts = detect_brute_force(events, group_by=("username", "source_ip"))
    assert len(alerts) == 1
    assert alerts[0].username == "alice"


@pytest.mark.parametrize("group_by", [(), ("host",), "username", ([],)])
def test_invalid_brute_force_grouping_is_rejected(group_by):
    with pytest.raises(ValueError, match="group_by"):
        detect_brute_force([], group_by=group_by)


def test_successful_logons_are_not_counted():
    events = [make_event(event_id=4624, seconds=seconds) for seconds in range(5)]

    assert detect_brute_force(events) == []


@pytest.mark.parametrize("username", [None, "", "   "])
def test_missing_or_blank_usernames_are_not_counted(username):
    events = [make_event(username=username, seconds=seconds) for seconds in range(5)]

    assert detect_brute_force(events) == []


def test_mixed_input_order_is_sorted_before_analysis():
    events = [
        make_event(seconds=40),
        make_event(seconds=0),
        make_event(seconds=60),
        make_event(seconds=20),
        make_event(seconds=10),
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].first_seen == START
    assert alerts[0].last_seen == START + timedelta(seconds=60)


@pytest.mark.parametrize("threshold", [0, -1, 1.5, True])
def test_invalid_threshold_is_rejected(threshold):
    with pytest.raises(ValueError):
        detect_brute_force([], threshold=threshold)


@pytest.mark.parametrize("window", [0, -1, float("inf"), float("nan"), True])
def test_invalid_time_window_is_rejected(window):
    with pytest.raises(ValueError):
        detect_brute_force([], time_window_seconds=window)
