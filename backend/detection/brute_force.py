"""Rule-based detection for repeated failed Windows logons."""

from datetime import datetime, timedelta, timezone
import math
from typing import Dict, List, Optional, Tuple

from backend.models.detection_alert import DetectionAlert
from backend.models.security_event import SecurityEvent


def _validate_options(threshold: int, time_window_seconds: float) -> None:
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    if (
        isinstance(time_window_seconds, bool)
        or not isinstance(time_window_seconds, (int, float))
        or not math.isfinite(time_window_seconds)
        or time_window_seconds <= 0
    ):
        raise ValueError("time_window_seconds must be a positive finite number")


def detect_brute_force(
    events: List[SecurityEvent],
    threshold: int = 5,
    time_window_seconds: float = 60,
    group_by=("username",),
) -> List[DetectionAlert]:
    """Detect per-user bursts of failed logons in a sliding time window.

    Only event ID 4625 is counted. Rules may group by non-empty username and/or
    source IP. Timestamps must be timezone-aware and are compared in UTC. One
    alert is returned when an identity's rolling count first reaches threshold.
    """
    _validate_options(threshold, time_window_seconds)
    allowed_groups = {"username", "source_ip"}
    if (
        not isinstance(group_by, (list, tuple, set))
        or not group_by
        or any(
            not isinstance(value, str) or value not in allowed_groups
            for value in group_by
        )
    ):
        raise ValueError("group_by must contain username and/or source_ip")
    group_by = set(group_by)
    events_by_identity: Dict[Tuple[str, str], List[datetime]] = {}
    display_names: Dict[Tuple[str, str], Optional[str]] = {}

    for event in events:
        if not isinstance(event, SecurityEvent):
            raise TypeError("events must contain SecurityEvent objects")
        if event.event_id != 4625:
            continue
        username = event.username if event.username and event.username.strip() else None
        source_ip = event.source_ip if event.source_ip and event.source_ip.strip() else None
        identities = []
        if "username" in group_by and username:
            domain = event.domain.strip().casefold() if event.domain and event.domain.strip() else ""
            identity = domain + "\\" + username.casefold() if domain else username.casefold()
            identities.append(("username", identity, username))
        if "source_ip" in group_by and source_ip:
            identities.append(("source_ip", source_ip.casefold(), None))
        if not identities:
            continue
        timestamp = event.timestamp
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("event timestamps must be timezone-aware")
        timestamp = timestamp.astimezone(timezone.utc)
        for kind, identity, display_name in identities:
            key = (kind, identity)
            display_names.setdefault(key, display_name)
            events_by_identity.setdefault(key, []).append(timestamp)

    alerts: List[DetectionAlert] = []
    window = timedelta(seconds=time_window_seconds)
    for identity_key, timestamps in events_by_identity.items():
        identity_type, identity = identity_key
        username = display_names[identity_key]
        timestamps.sort()
        start = 0
        alert_active = False

        for end, current_time in enumerate(timestamps):
            while current_time - timestamps[start] > window:
                start += 1

            count_in_window = end - start + 1
            if count_in_window >= threshold and not alert_active:
                alerts.append(
                    DetectionAlert(
                        rule_name="Brute Force Detection",
                        username=username,
                        event_count=count_in_window,
                        first_seen=timestamps[start],
                        last_seen=current_time,
                        threshold=threshold,
                        window_seconds=float(time_window_seconds),
                        attack_techniques=["T1110"],
                        rule_id="BS-001",
                        description="Repeated failed logons for one account in a short period.",
                        evidence=[
                            {"event_id": 4625, "timestamp": timestamp.isoformat()}
                            for timestamp in timestamps[start:end + 1]
                        ],
                        recommended_actions=[
                            "Review the related authentication events and source context.",
                            "Confirm whether the activity matches expected user behavior.",
                        ],
                        correlation_keys=[identity_type + ":" + identity],
                    )
                )
                alert_active = True
            elif count_in_window < threshold:
                alert_active = False

    username_evidence = {
        tuple((item["event_id"], item["timestamp"]) for item in alert.evidence)
        for alert in alerts if alert.username is not None
    }
    alerts = [
        alert for alert in alerts
        if alert.username is not None
        or tuple((item["event_id"], item["timestamp"]) for item in alert.evidence)
        not in username_evidence
    ]
    alerts.sort(key=lambda alert: (alert.first_seen, alert.username or "", alert.correlation_keys))
    return alerts
