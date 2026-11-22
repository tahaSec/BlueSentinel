"""Incident lifecycle operations backed by SQLite."""

from datetime import datetime, timezone
import json
import sqlite3
from typing import Iterable, List, Optional

from backend.models.incident import INCIDENT_STATUSES, Incident
from backend.correlation.alert_correlator import correlate_alerts
from backend.storage.database import utc_iso
from backend.storage.event_repository import detection_id, related_event_ids
from backend.normalization.redaction import redact_sensitive


def create_incident(
    connection: sqlite3.Connection,
    title: str,
    description: str,
    severity: str,
    detection_ids: Iterable[int] = (),
    event_ids: Iterable[int] = (),
    detection_rule: Optional[str] = None,
    mitre_mapping: Iterable[str] = (),
    recommended_actions: Iterable[str] = (),
) -> int:
    """Create a new incident and link its evidence in one transaction."""
    if not title.strip():
        raise ValueError("incident title cannot be empty")
    now = utc_iso(datetime.now(timezone.utc))
    try:
        cursor = connection.execute(
            """INSERT INTO incidents
            (title,description,severity,status,created_at,updated_at,detection_rule,
             mitre_mapping,recommended_actions) VALUES (?,?,?,'NEW',?,?,?,?,?)""",
            (redact_sensitive(title.strip()), redact_sensitive(description), severity.upper(),
             now, now, detection_rule, json.dumps(list(mitre_mapping)),
             json.dumps([redact_sensitive(item) for item in recommended_actions])),
        )
        incident_id = cursor.lastrowid
        connection.executemany(
            "INSERT OR IGNORE INTO incident_detections(incident_id,detection_id) VALUES(?,?)",
            [(incident_id, value) for value in detection_ids],
        )
        connection.executemany(
            "INSERT OR IGNORE INTO incident_events(incident_id,event_id) VALUES(?,?)",
            [(incident_id, value) for value in event_ids],
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return incident_id


def update_status(connection: sqlite3.Connection, incident_id: int, status: str) -> None:
    """Change an incident to an allowed analyst-selected lifecycle state."""
    status = status.upper()
    if status not in INCIDENT_STATUSES:
        raise ValueError("status must be one of: {}".format(", ".join(INCIDENT_STATUSES)))
    try:
        cursor = connection.execute(
            "UPDATE incidents SET status=?, updated_at=? WHERE id=?",
            (status, utc_iso(datetime.now(timezone.utc)), incident_id),
        )
        if cursor.rowcount != 1:
            raise LookupError("incident {} was not found".format(incident_id))
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def add_note(connection: sqlite3.Connection, incident_id: int, note: str) -> None:
    """Append an analyst note without replacing earlier investigation notes."""
    if not note.strip():
        raise ValueError("note cannot be empty")
    exists = connection.execute("SELECT 1 FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if exists is None:
        raise LookupError("incident {} was not found".format(incident_id))
    try:
        connection.execute(
            "INSERT INTO analyst_notes(incident_id,note,created_at) VALUES(?,?,?)",
            (incident_id, redact_sensitive(note.strip()), utc_iso(datetime.now(timezone.utc))),
        )
        connection.execute(
            "UPDATE incidents SET updated_at=? WHERE id=?",
            (utc_iso(datetime.now(timezone.utc)), incident_id),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def get_incident(connection: sqlite3.Connection, incident_id: int) -> Incident:
    row = connection.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if row is None:
        raise LookupError("incident {} was not found".format(incident_id))
    event_ids = [item[0] for item in connection.execute(
        "SELECT event_id FROM incident_events WHERE incident_id=? ORDER BY event_id", (incident_id,)
    )]
    detection_ids = [item[0] for item in connection.execute(
        "SELECT detection_id FROM incident_detections WHERE incident_id=? ORDER BY detection_id", (incident_id,)
    )]
    notes = [item[0] for item in connection.execute(
        "SELECT note FROM analyst_notes WHERE incident_id=? ORDER BY id", (incident_id,)
    )]
    return Incident(
        incident_id=row["id"], title=row["title"], description=row["description"],
        severity=row["severity"], status=row["status"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]), related_event_ids=event_ids,
        detection_ids=detection_ids, detection_rule=row["detection_rule"],
        mitre_mapping=json.loads(row["mitre_mapping"] or "[]"), analyst_notes=notes,
        recommended_actions=json.loads(row["recommended_actions"] or "[]"),
    )


def list_incidents(connection: sqlite3.Connection, status: Optional[str] = None) -> List[Incident]:
    if status is None:
        rows = connection.execute("SELECT id FROM incidents ORDER BY updated_at DESC, id DESC").fetchall()
    else:
        status = status.upper()
        if status not in INCIDENT_STATUSES:
            raise ValueError("unsupported incident status")
        rows = connection.execute(
            "SELECT id FROM incidents WHERE status=? ORDER BY updated_at DESC, id DESC",
            (status,),
        ).fetchall()
    return [get_incident(connection, row[0]) for row in rows]


def create_incidents_for_alerts(connection: sqlite3.Connection, alerts) -> List[int]:
    """Create one new incident per unlinked alert, preserving evidence links.

    Re-running analysis will not create another incident for an already-linked
    detection. Analysts still control lifecycle state and closure.
    """
    created_ids = []
    alerts = list(alerts)
    grouped = correlate_alerts(alerts)
    grouped_ids = {id(alert) for group in grouped for alert in group.alerts}
    clusters = [(group.alerts, group.explanation) for group in grouped]
    clusters.extend(([alert], None) for alert in alerts if id(alert) not in grouped_ids)
    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    for cluster, explanation in clusters:
        stored_ids = [detection_id(connection, alert) for alert in cluster]
        pairs = [(alert, value) for alert, value in zip(cluster, stored_ids) if value is not None]
        if not pairs:
            continue
        existing = connection.execute(
            "SELECT incident_id FROM incident_detections WHERE detection_id IN ({}) ORDER BY incident_id LIMIT 1".format(
                ",".join("?" for _ in pairs)
            ),
            tuple(value for _, value in pairs),
        ).fetchone()
        if existing:
            incident_id = existing[0]
            connection.executemany(
                "INSERT OR IGNORE INTO incident_detections(incident_id,detection_id) VALUES(?,?)",
                [(incident_id, value) for _, value in pairs],
            )
            connection.commit()
            continue

        primary = max((alert for alert, _ in pairs),
                      key=lambda item: severity_rank.get(item.severity, 0))
        event_ids = sorted({
            event_id for alert, _ in pairs
            for event_id in related_event_ids(connection, alert)
        })
        detection_ids = [value for _, value in pairs]
        techniques = sorted({
            technique for alert, _ in pairs for technique in alert.attack_techniques
        })
        actions = list(dict.fromkeys(
            action for alert, _ in pairs for action in alert.recommended_actions
        ))
        if len(pairs) > 1:
            description = (
                "{} Correlated {} detection signals. This is an analytical grouping "
                "and does not confirm compromise."
            ).format(explanation or "Related signals were observed.", len(pairs))
            rule_name = "Correlated detections"
        else:
            description = primary.description or "Detection signal requires analyst review."
            rule_name = primary.rule_id or primary.rule_name
        incident_id = create_incident(
            connection, title="{}: {}".format(primary.severity, primary.rule_name),
            description=description, severity=primary.severity,
            detection_ids=detection_ids, event_ids=event_ids,
            detection_rule=rule_name, mitre_mapping=techniques,
            recommended_actions=actions,
        )
        created_ids.append(incident_id)
    return created_ids
