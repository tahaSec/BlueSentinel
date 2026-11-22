"""Load and validate JSON detection rule definitions."""

import json
import math
from pathlib import Path
from typing import Any, Dict, List


SUPPORTED_DETECTORS = {
    "brute_force", "suspicious_successful_login", "privileged_logon",
    "suspicious_process", "account_change", "network_burst", "event_correlation",
}
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class RuleValidationError(ValueError):
    """Raised when a rule file is malformed or unsafe to execute."""


def validate_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the shared rule fields and detector-specific options."""
    if not isinstance(rule, dict):
        raise RuleValidationError("each rule must be a JSON object")
    for key in ("id", "name", "description", "detector", "severity"):
        if not isinstance(rule.get(key), str) or not rule[key].strip():
            raise RuleValidationError("rule requires a non-empty '{}'".format(key))
    if rule["detector"] not in SUPPORTED_DETECTORS:
        raise RuleValidationError("unsupported detector: {}".format(rule["detector"]))
    if rule["severity"].upper() not in SEVERITIES:
        raise RuleValidationError("severity must be LOW, MEDIUM, HIGH, or CRITICAL")
    if not isinstance(rule.get("enabled"), bool):
        raise RuleValidationError("rule 'enabled' must be a boolean")
    if not isinstance(rule.get("sources"), list) or not rule["sources"] or not all(
        isinstance(value, str) and value.strip() for value in rule["sources"]
    ):
        raise RuleValidationError("rule 'sources' must be a non-empty list of strings")
    conditions = rule.get("conditions")
    if not isinstance(conditions, dict):
        raise RuleValidationError("rule 'conditions' must be an object")
    if not isinstance(conditions.get("event_ids"), list) or not conditions["event_ids"] or not all(
        isinstance(value, int) and not isinstance(value, bool) and value > 0
        for value in conditions["event_ids"]
    ):
        raise RuleValidationError("conditions.event_ids must be a list of positive integers")
    required_event_ids = {
        "brute_force": {4625},
        "suspicious_successful_login": {4624, 4625},
        "privileged_logon": {4672},
        "network_burst": {3},
    }
    if not required_event_ids.get(rule["detector"], set()).issubset(
        set(conditions["event_ids"])
    ):
        raise RuleValidationError(
            "conditions.event_ids do not cover the selected detector's required event IDs"
        )
    if rule["detector"] == "suspicious_process" and not set(conditions["event_ids"]).intersection({1, 4688}):
        raise RuleValidationError("suspicious_process requires Sysmon 1 or Security 4688")
    if rule["detector"] == "account_change" and not set(conditions["event_ids"]).issubset(
        {4720, 4722, 4728, 4732}
    ):
        raise RuleValidationError("account_change supports event IDs 4720, 4722, 4728, and 4732")
    if rule["detector"] == "event_correlation":
        stages = conditions.get("stages")
        if not isinstance(stages, list) or len(stages) < 2 or any(
            not isinstance(stage, list) or not stage or any(
                not isinstance(event_id, int) or isinstance(event_id, bool) or event_id < 1
                for event_id in stage
            ) for stage in stages
        ):
            raise RuleValidationError(
                "event_correlation requires at least two non-empty conditions.stages lists"
            )
        stage_event_ids = {event_id for stage in stages for event_id in stage}
        if not stage_event_ids.issubset(set(conditions["event_ids"])):
            raise RuleValidationError("conditions.event_ids must include every staged event ID")
    if rule["detector"] == "suspicious_successful_login" and conditions.get("group_by", "username") != "username":
        raise RuleValidationError("suspicious_successful_login currently supports group_by=username")
    if rule["detector"] == "network_burst" and conditions.get(
        "group_by", "username_or_source_ip"
    ) != "username_or_source_ip":
        raise RuleValidationError("network_burst currently supports username_or_source_ip grouping")
    if not isinstance(rule.get("mitre"), list) or not all(
        isinstance(item, str) for item in rule["mitre"]
    ):
        raise RuleValidationError("rule 'mitre' must be a list of technique IDs")
    if not isinstance(rule.get("mitre_tactics"), list) or not all(
        isinstance(item, str) for item in rule["mitre_tactics"]
    ):
        raise RuleValidationError("rule 'mitre_tactics' must be a list of strings")
    if not isinstance(rule.get("recommended_actions"), list) or not all(
        isinstance(item, str) for item in rule["recommended_actions"]
    ):
        raise RuleValidationError("rule 'recommended_actions' must be a list of strings")

    options = rule.get("options", {})
    if not isinstance(options, dict):
        raise RuleValidationError("rule 'options' must be an object")
    if "threshold" in options:
        value = options["threshold"]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise RuleValidationError("threshold must be a positive integer")
    if "window_seconds" in options:
        value = options["window_seconds"]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RuleValidationError("window_seconds must be a positive number")
        if not math.isfinite(value) or value <= 0:
            raise RuleValidationError("window_seconds must be a positive finite number")
    if "event_ids" in options and (
        not isinstance(options["event_ids"], list)
        or not all(isinstance(value, int) and not isinstance(value, bool) and value > 0
                   for value in options["event_ids"])
    ):
        raise RuleValidationError("event_ids must be a list of positive integers")
    if "indicators" in options and (
        not isinstance(options["indicators"], list)
        or not all(isinstance(value, str) and value.strip() for value in options["indicators"])
    ):
        raise RuleValidationError("indicators must be a list of non-empty strings")
    if rule["detector"] == "brute_force" and "group_by" in options and (
        not isinstance(options["group_by"], list)
        or not options["group_by"]
        or any(
            not isinstance(value, str) or value not in {"username", "source_ip"}
            for value in options["group_by"]
        )
    ):
        raise RuleValidationError("brute_force group_by must contain username and/or source_ip")
    if rule["detector"] == "event_correlation":
        fields = options.get("correlation_fields")
        allowed_fields = {"username", "account_sid", "source_ip", "computer", "process_name"}
        if not isinstance(fields, list) or not fields or any(
            not isinstance(field, str) or field not in allowed_fields for field in fields
        ):
            raise RuleValidationError(
                "event_correlation requires correlation_fields from username, account_sid, source_ip, computer, process_name"
            )
    return rule


def load_rules(directory: str) -> List[Dict[str, Any]]:
    """Load all top-level JSON rules, sorted by filename."""
    rule_path = Path(directory)
    if not rule_path.exists():
        raise FileNotFoundError("rules directory does not exist: {}".format(rule_path))
    rules = []
    seen_ids = set()
    for path in sorted(rule_path.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuleValidationError("could not read rule file {}".format(path.name)) from error
        entries = value if isinstance(value, list) else [value]
        for entry in entries:
            rule = validate_rule(entry)
            if rule["id"] in seen_ids:
                raise RuleValidationError("duplicate rule id: {}".format(rule["id"]))
            seen_ids.add(rule["id"])
            rules.append(rule)
    return rules
