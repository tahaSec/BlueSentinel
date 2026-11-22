"""Convert Windows event dictionaries to the shared SecurityEvent model."""

from datetime import datetime, timezone
from typing import Any, Mapping

from backend.models.security_event import SecurityEvent
from backend.normalization.redaction import redact_sensitive


def _normalize_timestamp(value: Any) -> datetime:
    if value is None:
        raise ValueError("timestamp is required")
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("timestamp must be a valid ISO 8601 datetime") from error
    else:
        raise TypeError("timestamp must be a datetime or ISO 8601 string")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        # Naive input timestamps are defined as UTC at this API boundary.
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def normalize_windows_event(raw_event: Mapping[str, Any]) -> SecurityEvent:
    if isinstance(raw_event, SecurityEvent):
        return raw_event
    if not hasattr(raw_event, "get"):
        raise TypeError("raw_event must be a mapping")
    raw_event = redact_sensitive(dict(raw_event))
    raw_event_id = raw_event.get("event_id")
    if raw_event_id is None:
        raise ValueError("event_id must be an integer")
    if isinstance(raw_event_id, bool) or not isinstance(raw_event_id, (int, str)):
        raise ValueError("event_id must be an integer")
    if isinstance(raw_event_id, str) and not raw_event_id.strip().lstrip("+").isdigit():
        raise ValueError("event_id must be an integer")
    try:
        event_id = int(raw_event_id)
    except (TypeError, ValueError) as error:
        raise ValueError("event_id must be an integer") from error
    return SecurityEvent(
        event_id=event_id,
        source=raw_event.get("source"),
        computer=raw_event.get("computer"),
        timestamp=_normalize_timestamp(raw_event.get("timestamp")),
        username=raw_event.get("username"),
        description=raw_event.get("description"),
        severity=raw_event.get("severity") or "INFO",
        domain=raw_event.get("domain"),
        source_ip=raw_event.get("source_ip"),
        destination_ip=raw_event.get("destination_ip"),
        process_name=raw_event.get("process_name"),
        process_path=raw_event.get("process_path"),
        parent_process=raw_event.get("parent_process"),
        command_line=raw_event.get("command_line"),
        logon_type=raw_event.get("logon_type"),
        raw_data=raw_event.get("raw_data", dict(raw_event)),
        account_sid=raw_event.get("account_sid"),
    )
