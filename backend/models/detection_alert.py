"""Data model for a security detection alert."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class DetectionAlert:
    """Describe a detected pattern without changing the source event model."""

    rule_name: str
    username: Optional[str]
    event_count: int
    first_seen: datetime
    last_seen: datetime
    threshold: int
    window_seconds: float
    severity: str = "HIGH"
    attack_techniques: List[str] = field(default_factory=list)
    rule_id: str = ""
    description: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    correlation_keys: List[str] = field(default_factory=list)

    def __post_init__(self):
        for field_name in ("first_seen", "last_seen"):
            value = getattr(self, field_name)
            if not isinstance(value, datetime):
                raise TypeError("{} must be a datetime".format(field_name))
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("{} must be timezone-aware".format(field_name))
            setattr(self, field_name, value.astimezone(timezone.utc))
