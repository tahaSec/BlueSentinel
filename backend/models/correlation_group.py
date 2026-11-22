"""A group of related detection alerts."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from backend.models.detection_alert import DetectionAlert


@dataclass
class CorrelationGroup:
    username: Optional[str]
    alerts: List[DetectionAlert]
    first_seen: datetime
    last_seen: datetime
    attack_techniques: List[str] = field(default_factory=list)
    correlation_keys: List[str] = field(default_factory=list)
    explanation: str = ""
