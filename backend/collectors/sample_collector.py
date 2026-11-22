"""Import normalized synthetic or previously exported event records."""

import json
from pathlib import Path
from typing import List

from backend.models.security_event import SecurityEvent
from backend.normalization.event_normalizer import normalize_windows_event


def load_sample_events(path: str) -> List[SecurityEvent]:
    """Read an event object, list, or {'events': [...]} JSON document."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = payload.get("events", [payload])
    if not isinstance(payload, list):
        raise ValueError("input must be an event object, event list, or events object")
    return [normalize_windows_event(item) for item in payload]
