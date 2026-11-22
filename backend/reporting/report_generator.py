"""JSON, CSV, and Markdown exports for analyst review."""

from dataclasses import asdict
from datetime import datetime, timezone
import csv
import json
from pathlib import Path
from typing import Iterable, List

from backend.attack.mitre import techniques_for_alert
from backend.normalization.redaction import redact_sensitive


def _serializable(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def _payload(events, alerts, incidents):
    times = [event.timestamp for event in events]
    hosts = redact_sensitive(sorted({event.computer for event in events if event.computer}))
    severity_counts = {}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "collection_period": {
            "start": min(times).isoformat() if times else None,
            "end": max(times).isoformat() if times else None,
        },
        "hosts": hosts,
        "detection_summary": {"event_count": len(events), "alert_count": len(alerts),
                              "severity_distribution": severity_counts},
        "incident_summary": {"incident_count": len(incidents),
                             "status_distribution": _count_by(incidents, "status")},
        "events": [redact_sensitive(asdict(event)) for event in events],
        "detections": [
            {**redact_sensitive(asdict(alert)),
             "mitre": techniques_for_alert(alert),
             "classification_note": "Detection signal for analyst review; not proof of compromise."}
            for alert in alerts
        ],
        "incidents": [redact_sensitive(asdict(incident)) for incident in incidents],
    }


def _count_by(items, attribute):
    counts = {}
    for item in items:
        value = getattr(item, attribute)
        counts[value] = counts.get(value, 0) + 1
    return counts


def export_report(
    path: str,
    events: Iterable,
    alerts: Iterable,
    incidents: Iterable = (),
    report_format: str = "json",
) -> Path:
    """Write an investigation report and return its destination path."""
    if report_format not in {"json", "csv", "markdown"}:
        raise ValueError("report_format must be json, csv, or markdown")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    events, alerts, incidents = list(events), list(alerts), list(incidents)
    payload = _payload(events, alerts, incidents)
    if report_format == "json":
        path.write_text(json.dumps(payload, default=_serializable, indent=2), encoding="utf-8")
    elif report_format == "csv":
        columns = ["record_type", "rule_id", "rule_name", "username", "event_count",
                   "first_seen", "last_seen", "severity", "attack_techniques", "evidence",
                   "recommended_actions", "collection_start", "collection_end", "hosts",
                   "total_events", "total_detections", "total_incidents",
                   "severity_distribution", "incident_status_distribution", "incident_id",
                   "incident_title", "incident_status", "incident_description",
                   "related_event_ids", "analyst_notes"]
        with path.open("w", newline="", encoding="utf-8-sig") as output:
            writer = csv.DictWriter(output, fieldnames=columns)
            writer.writeheader()
            writer.writerow({
                "record_type": "SUMMARY",
                "collection_start": payload["collection_period"]["start"],
                "collection_end": payload["collection_period"]["end"],
                "hosts": ";".join(payload["hosts"]),
                "total_events": len(events),
                "total_detections": len(alerts),
                "total_incidents": len(incidents),
                "severity_distribution": json.dumps(payload["detection_summary"]["severity_distribution"]),
                "incident_status_distribution": json.dumps(payload["incident_summary"]["status_distribution"]),
            })
            for alert in alerts:
                row = asdict(alert)
                row["record_type"] = "DETECTION"
                row["first_seen"] = alert.first_seen.astimezone(timezone.utc).isoformat()
                row["last_seen"] = alert.last_seen.astimezone(timezone.utc).isoformat()
                row["attack_techniques"] = json.dumps(techniques_for_alert(alert))
                row["evidence"] = json.dumps(redact_sensitive(alert.evidence), default=_serializable)
                row["recommended_actions"] = json.dumps(alert.recommended_actions)
                writer.writerow({key: redact_sensitive(row.get(key)) for key in columns})
            for incident in incidents:
                writer.writerow({
                    "record_type": "INCIDENT",
                    "incident_id": incident.incident_id,
                    "incident_title": redact_sensitive(incident.title),
                    "incident_status": incident.status,
                    "severity": incident.severity,
                    "incident_description": redact_sensitive(incident.description),
                    "attack_techniques": json.dumps(incident.mitre_mapping),
                    "related_event_ids": json.dumps(incident.related_event_ids),
                    "analyst_notes": json.dumps(
                        [redact_sensitive(note) for note in incident.analyst_notes]
                    ),
                    "recommended_actions": json.dumps(incident.recommended_actions),
                })
    else:
        lines = ["# BlueSentinel Investigation Report", "",
                 "Generated: {}".format(payload["generated_at"]),
                 "Collection period: {} to {}".format(
                     payload["collection_period"]["start"] or "unknown",
                     payload["collection_period"]["end"] or "unknown"),
                 "Hosts: {}".format(redact_sensitive(", ".join(payload["hosts"])) or "unknown"), "",
                 "## Summary", "",
                 "- Events: {}".format(len(events)),
                 "- Detection signals: {}".format(len(alerts)),
                 "- Detection severity distribution: {}".format(
                     json.dumps(payload["detection_summary"]["severity_distribution"], sort_keys=True)),
                 "- Incidents: {}".format(len(incidents)), "", "## Detections", ""]
        for alert in alerts:
            techniques = techniques_for_alert(alert)
            technique_text = ", ".join(
                "{} ({})".format(item["id"], item["name"]) for item in techniques
            ) or "No ATT&CK mapping"
            lines.extend([
                "### {} — {}".format(alert.severity, redact_sensitive(alert.rule_name)), "",
                "{} failure/activity record(s); account: {}; period: {} to {}.".format(
                    alert.event_count, redact_sensitive(alert.username) or "unknown",
                    alert.first_seen.isoformat(), alert.last_seen.isoformat()),
                "", "ATT&CK: {}".format(technique_text),
                "Analytical signal; not proof of compromise.", "",
                "Recommended investigation:",
            ])
            lines.extend("- {}".format(redact_sensitive(action)) for action in alert.recommended_actions)
            if alert.evidence:
                lines.extend(["", "Evidence:"])
                lines.extend(
                    "- Event {} at {}".format(item.get("event_id", "?"), item.get("timestamp", "unknown"))
                    for item in alert.evidence
                )
            lines.append("")
        lines.extend(["## Incidents", ""])
        if incidents:
            for incident in incidents:
                lines.extend(["### {} — {}".format(incident.incident_id, redact_sensitive(incident.title)),
                              "", "Status: {}; severity: {}".format(incident.status, incident.severity),
                              "", redact_sensitive(incident.description), "",
                              "Related event database IDs: {}".format(
                                  ", ".join(map(str, incident.related_event_ids)) or "none"), "",
                              "Analyst notes:"])
                lines.extend("- {}".format(redact_sensitive(note)) for note in incident.analyst_notes)
                lines.append("Recommended actions:")
                lines.extend("- {}".format(redact_sensitive(action)) for action in incident.recommended_actions)
                lines.append("")
        else:
            lines.append("No incidents are currently recorded.")
        path.write_text("\n".join(str(line) for line in lines), encoding="utf-8")
    return path
