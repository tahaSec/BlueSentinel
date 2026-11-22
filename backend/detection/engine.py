"""Run validated JSON-backed detection rules against normalized events."""

from collections import defaultdict
from datetime import timedelta
from typing import Dict, List

from backend.detection.brute_force import detect_brute_force
from backend.detection.rule_loader import load_rules, validate_rule
from backend.models.detection_alert import DetectionAlert
from backend.models.security_event import SecurityEvent


class DetectionEngine:
    """Dispatch events to the enabled detectors defined in JSON rule files."""

    def __init__(self, rules: List[dict]):
        self.rules = [validate_rule(rule) for rule in rules]

    @classmethod
    def from_directory(cls, directory: str = "rules"):
        return cls(load_rules(directory))

    def detect(self, events: List[SecurityEvent]) -> List[DetectionAlert]:
        """Return alerts from every enabled rule in time order."""
        ordered = sorted(events, key=lambda event: event.timestamp)
        alerts = []
        for rule in self.rules:
            if not rule["enabled"]:
                continue
            scoped_events = [
                event for event in ordered if self._source_matches(event, rule["sources"])
            ]
            detector = rule["detector"]
            options = rule.get("options", {})
            if detector == "brute_force":
                matches = detect_brute_force(
                    [event for event in scoped_events
                     if event.event_id in rule["conditions"]["event_ids"]],
                    options.get("threshold", 5),
                    options.get("window_seconds", 60),
                    options.get("group_by", ["username"]),
                )
            elif detector == "suspicious_successful_login":
                matches = self._successful_after_failures(scoped_events, rule, options)
            elif detector == "privileged_logon":
                matches = self._single_event(
                    scoped_events, rule, set(rule["conditions"]["event_ids"])
                )
            elif detector == "suspicious_process":
                matches = self._suspicious_processes(scoped_events, rule, options)
            elif detector == "account_change":
                matches = self._single_event(
                    scoped_events, rule, set(rule["conditions"]["event_ids"])
                )
            elif detector == "event_correlation":
                matches = self._correlate_event_stages(scoped_events, rule, options)
            else:
                matches = self._network_bursts(scoped_events, rule, options)
            for alert in matches:
                alert.rule_id = rule["id"]
                alert.rule_name = rule["name"]
                alert.description = rule["description"]
                alert.severity = rule["severity"].upper()
                alert.recommended_actions = list(rule["recommended_actions"])
                if detector not in {"account_change", "suspicious_process"}:
                    alert.attack_techniques = list(rule["mitre"])
                if detector == "brute_force":
                    username_key = next(
                        (key.split(":", 1)[1] for key in alert.correlation_keys
                         if key.startswith("username:")),
                        (alert.username or "").casefold(),
                    )
                    if "\\" in username_key:
                        expected_domain, expected_username = username_key.rsplit("\\", 1)
                    else:
                        expected_domain, expected_username = "", username_key
                    related = [
                        event for event in scoped_events
                        if event.event_id == 4625
                        and event.username and event.username.casefold() == expected_username
                        and (event.domain.strip().casefold() if event.domain and event.domain.strip() else "") == expected_domain
                        and alert.first_seen <= event.timestamp <= alert.last_seen
                    ]
                    extra_keys = []
                    for event in related:
                        if event.account_sid:
                            extra_keys.append("account_sid:" + event.account_sid.casefold())
                        if event.source_ip:
                            extra_keys.append("source_ip:" + event.source_ip.casefold())
                        if event.computer:
                            extra_keys.append("computer:" + event.computer.casefold())
                    alert.correlation_keys = sorted(set(alert.correlation_keys + extra_keys))
            alerts.extend(matches)
        alerts.sort(key=lambda alert: (alert.first_seen, alert.rule_id, alert.username or ""))
        return alerts

    @staticmethod
    def _source_matches(event, sources):
        actual = (event.source or "").casefold()
        for expected in sources:
            expected = expected.casefold()
            if expected == "windows security" and "security" in actual:
                return True
            if expected == "sysmon" and "sysmon" in actual:
                return True
            if actual == expected:
                return True
        return False

    @staticmethod
    def _alert(rule, event, count=1, first_seen=None, evidence=None, techniques=None):
        username = event.username if event.username and event.username.strip() else None
        correlation_keys = []
        if username:
            domain = event.domain.strip().casefold() if event.domain and event.domain.strip() else None
            identity = domain + "\\" + username.casefold() if domain else username.casefold()
            correlation_keys.append("username:" + identity)
        if event.account_sid:
            correlation_keys.append("account_sid:" + event.account_sid.casefold())
        if event.source_ip:
            correlation_keys.append("source_ip:" + event.source_ip.casefold())
        if event.computer:
            correlation_keys.append("computer:" + event.computer.casefold())
        if event.process_name:
            correlation_keys.append("process:" + event.process_name.casefold())
        return DetectionAlert(
            rule_name=rule["name"], username=username,
            event_count=count, first_seen=first_seen or event.timestamp,
            last_seen=event.timestamp, threshold=rule.get("options", {}).get("threshold", 1),
            window_seconds=float(rule.get("options", {}).get("window_seconds", 0)),
            severity=rule["severity"].upper(), attack_techniques=list(techniques or rule["mitre"]),
            rule_id=rule["id"], description=rule["description"],
            evidence=evidence or [{"event_id": event.event_id, "timestamp": event.timestamp.isoformat()}],
            recommended_actions=list(rule["recommended_actions"]),
            correlation_keys=correlation_keys,
        )

    def _successful_after_failures(self, events, rule, options):
        threshold = options.get("threshold", 3)
        window = timedelta(seconds=options.get("window_seconds", 300))
        event_ids = set(rule["conditions"]["event_ids"])
        failed_ids = event_ids.intersection({4625})
        successful_ids = event_ids.intersection({4624})
        failures = defaultdict(list)
        alerts = []
        for event in events:
            username = event.username
            if not username or not username.strip():
                continue
            domain = event.domain.strip().casefold() if event.domain and event.domain.strip() else ""
            user_key = domain + "\\" + username.casefold() if domain else username.casefold()
            if event.event_id in failed_ids:
                failures[user_key].append(event)
            elif event.event_id in successful_ids:
                recent = [
                    failed for failed in failures[user_key]
                    if timedelta(0) <= event.timestamp - failed.timestamp <= window
                ]
                failures[user_key] = recent
                if len(recent) >= threshold:
                    alerts.append(self._alert(
                        rule, event, len(recent) + 1, recent[0].timestamp,
                        [{"event_id": failed.event_id, "timestamp": failed.timestamp.isoformat()} for failed in recent]
                        + [{"event_id": event.event_id, "timestamp": event.timestamp.isoformat()}],
                    ))
                    failures[user_key] = []
        return alerts

    def _single_event(self, events, rule, event_ids):
        alerts = []
        for event in events:
            if event.event_id not in event_ids:
                continue
            techniques = list(rule["mitre"])
            if rule["detector"] == "account_change":
                if event.event_id == 4720:
                    techniques = ["T1136"]
                elif event.event_id in (4728, 4732):
                    techniques = ["T1098.007"]
                else:
                    techniques = []
            alert = self._alert(rule, event, techniques=techniques)
            alerts.append(alert)
        return alerts

    def _suspicious_processes(self, events, rule, options):
        event_ids = set(rule["conditions"]["event_ids"])
        indicators = [item.casefold() for item in options.get("indicators", [])]
        alerts = []
        for event in events:
            if event.event_id not in event_ids:
                continue
            command = " ".join(filter(None, (event.command_line, event.description))).casefold()
            matched = [indicator for indicator in indicators if indicator in command]
            if matched:
                alert = self._alert(rule, event, evidence=[
                    {"event_id": event.event_id, "timestamp": event.timestamp.isoformat(),
                     "matched_indicators": matched}
                ])
                alert.attack_techniques = ["T1059.001"] if "powershell" in command else ["T1059"]
                alerts.append(alert)
        return alerts

    def _network_bursts(self, events, rule, options):
        threshold = options.get("threshold", 50)
        window = timedelta(seconds=options.get("window_seconds", 60))
        event_ids = set(rule["conditions"]["event_ids"])
        by_identity = defaultdict(list)
        for event in events:
            username = event.username if event.username and event.username.strip() else None
            if event.event_id in event_ids:
                if username:
                    domain = event.domain.strip().casefold() if event.domain and event.domain.strip() else ""
                    user_identity = domain + "\\" + username.casefold() if domain else username.casefold()
                    by_identity["username:" + user_identity].append(event)
                if event.source_ip and event.source_ip.strip():
                    by_identity["source_ip:" + event.source_ip.casefold()].append(event)
        alerts = []
        for identity, events_for_identity in by_identity.items():
            start = 0
            active = False
            for end, event in enumerate(events_for_identity):
                while event.timestamp - events_for_identity[start].timestamp > window:
                    start += 1
                count = end - start + 1
                if count >= threshold and not active:
                    alert = self._alert(
                        rule, event, count, events_for_identity[start].timestamp,
                        [{"event_id": item.event_id, "timestamp": item.timestamp.isoformat()}
                         for item in events_for_identity[start:end + 1]],
                    )
                    if identity.startswith("source_ip:"):
                        alert.username = None
                        alert.correlation_keys = [identity]
                    alerts.append(alert)
                    active = True
                elif count < threshold:
                    active = False
        return alerts

    def _correlate_event_stages(self, events, rule, options):
        """Find ordered event stages sharing an explicit entity key.

        Each sequence must complete inside the configured window. Missing
        identity values never become a shared key, so unrelated events cannot
        correlate merely because both lack a username or process name.
        """
        stages = [set(stage) for stage in rule["conditions"]["stages"]]
        fields = options["correlation_fields"]
        window = timedelta(seconds=options.get("window_seconds", 900))
        alerts = []

        def keys_for(event):
            keys = set()
            for field in fields:
                value = getattr(event, field)
                if isinstance(value, str) and value.strip():
                    normalized = value.casefold()
                    if field == "username" and event.domain and event.domain.strip():
                        normalized = event.domain.casefold() + "\\" + normalized
                    keys.add(field + ":" + normalized)
            return keys

        for start_index, first in enumerate(events):
            if first.event_id not in stages[0]:
                continue
            shared_keys = keys_for(first)
            if not shared_keys:
                continue
            sequence = [first]
            cursor = start_index + 1
            for stage in stages[1:]:
                match = None
                while cursor < len(events):
                    candidate = events[cursor]
                    elapsed = candidate.timestamp - first.timestamp
                    if elapsed > window:
                        break
                    if (
                        candidate.event_id in stage
                        and elapsed >= timedelta(0)
                        and shared_keys.intersection(keys_for(candidate))
                    ):
                        match = candidate
                        break
                    cursor += 1
                if match is None:
                    sequence = []
                    break
                sequence.append(match)
                shared_keys.intersection_update(keys_for(match))
                cursor += 1
            if not sequence:
                continue

            final = sequence[-1]
            username = next((item.username for item in sequence if item.username and item.username.strip()), None)
            alert = self._alert(
                rule,
                final,
                count=len(sequence),
                first_seen=first.timestamp,
                evidence=[
                    {"event_id": item.event_id, "timestamp": item.timestamp.isoformat()}
                    for item in sequence
                ],
            )
            alert.username = username
            alert.correlation_keys = sorted(shared_keys)
            alerts.append(alert)
        return alerts
