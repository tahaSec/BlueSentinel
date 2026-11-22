from datetime import datetime

import pytest

from backend.models.security_event import SecurityEvent


def test_security_event_creation():
    event = SecurityEvent(
        event_id=4625,
        source="Windows Security",
        computer="TEST-PC",
        timestamp=datetime.now(),
        username="test_user",
        description="Failed login attempt",
        severity="MEDIUM"
    )

    assert event.event_id == 4625
    assert event.username == "test_user"
    assert event.severity == "MEDIUM"


def test_default_severity():
    event = SecurityEvent(
        event_id=4624,
        source="Windows Security",
        computer="TEST-PC",
        timestamp=datetime.now(),
        username="test_user",
        description="Successful login"
    )

    assert event.severity == "INFO"


@pytest.mark.parametrize("event_id", [0, -1])
def test_event_id_must_be_positive(event_id):
    with pytest.raises(ValueError, match="positive integer"):
        SecurityEvent(
            event_id=event_id, source=None, computer=None,
            timestamp=datetime.now(), username=None, description=None,
        )
