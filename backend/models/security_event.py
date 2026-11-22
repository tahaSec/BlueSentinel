from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class SecurityEvent:
    event_id: int
    source: Optional[str]
    computer: Optional[str]
    timestamp: datetime
    username: Optional[str]
    description: Optional[str]
    severity: str = "INFO"
    domain: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    logon_type: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    account_sid: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.event_id, int) or isinstance(self.event_id, bool):
            raise TypeError("event_id must be an integer")
        if self.event_id < 1:
            raise ValueError("event_id must be a positive integer")
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime")
        # All model timestamps are timezone-aware UTC. Naive values are treated
        # as UTC for backwards compatibility with callers that already supply UTC.
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        else:
            self.timestamp = self.timestamp.astimezone(timezone.utc)
        for field_name in (
            "source", "computer", "username", "description", "severity", "domain",
            "source_ip", "destination_ip", "process_name", "process_path",
            "parent_process", "command_line", "logon_type",
            "account_sid",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise TypeError("{} must be a string or None".format(field_name))
        if not isinstance(self.raw_data, dict):
            raise TypeError("raw_data must be a dictionary")
