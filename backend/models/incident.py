"""Security incident model and workflow states."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


INCIDENT_STATUSES = ("NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")


@dataclass
class Incident:
    incident_id: int
    title: str
    description: str
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime
    related_event_ids: List[int] = field(default_factory=list)
    detection_ids: List[int] = field(default_factory=list)
    detection_rule: Optional[str] = None
    mitre_mapping: List[str] = field(default_factory=list)
    analyst_notes: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.status not in INCIDENT_STATUSES:
            raise ValueError("unsupported incident status")
        for field_name in ("created_at", "updated_at"):
            value = getattr(self, field_name)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("incident timestamps must be timezone-aware")
            setattr(self, field_name, value.astimezone(timezone.utc))
