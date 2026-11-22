from datetime import datetime, timezone

import pytest

from backend.normalization.event_normalizer import normalize_windows_event


def test_normalize_windows_event():
    raw_event = {
        "event_id": 4625,
        "source": "Windows Security",
        "timestamp": "2025-01-01T00:00:00Z",
        "computer": "TEST-PC",
        "username": "admin",
        "description": "Failed login attempt"
    }

    event = normalize_windows_event(raw_event)

    assert event.event_id == 4625
    assert event.computer == "TEST-PC"
    assert event.username == "admin"
    assert event.source == "Windows Security"


def test_normalizer_default_values():
    event = normalize_windows_event({
        "event_id": 4625,
        "timestamp": datetime(2025, 1, 1, tzinfo=timezone.utc),
    })

    assert event.event_id == 4625
    assert event.username is None
    assert event.computer is None
    assert event.source is None
    assert event.timestamp.tzinfo == timezone.utc


def test_normalizer_normalizes_timestamp_to_utc():
    event = normalize_windows_event({
        "event_id": "4625",
        "timestamp": "2025-01-01T03:00:00+03:00",
    })
    assert event.timestamp == datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc)


def test_normalizer_rejects_missing_required_fields():
    with pytest.raises(ValueError, match="event_id"):
        normalize_windows_event({"timestamp": "2025-01-01T00:00:00Z"})
    with pytest.raises(ValueError, match="timestamp"):
        normalize_windows_event({"event_id": 4625})


@pytest.mark.parametrize("timestamp", ["not-a-date", 123, ""])
def test_normalizer_rejects_invalid_timestamp(timestamp):
    with pytest.raises((TypeError, ValueError)):
        normalize_windows_event({"event_id": 4625, "timestamp": timestamp})


@pytest.mark.parametrize("event_id", [None, "invalid", 1.2])
def test_normalizer_rejects_invalid_event_id(event_id):
    with pytest.raises(ValueError):
        normalize_windows_event({"event_id": event_id})


def test_normalizer_preserves_unknown_optional_fields_as_none():
    event = normalize_windows_event({
        "event_id": 4625,
        "timestamp": "2025-01-01T00:00:00Z",
    })
    assert event.username is None
    assert event.description is None
