"""Persistence functions for normalized events, detections, and collection runs."""

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from typing import Iterable, List, Optional

from backend.models.detection_alert import DetectionAlert
from backend.models.security_event import SecurityEvent
from backend.normalization.redaction import redact_sensitive
from backend.storage.database import utc_iso


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _event_fingerprint(event: SecurityEvent) -> str:
    content = redact_sensitive(asdict(event))
    content["timestamp"] = utc_iso(event.timestamp)
    return hashlib.sha256(_json(content).encode("utf-8")).hexdigest()


def save_events(connection: sqlite3.Connection, events: Iterable[SecurityEvent]) -> int:
    """Insert events once, using a stable hash to avoid duplicate imports."""
    rows = []
    for event in events:
        safe = redact_sensitive(asdict(event))
        safe["timestamp"] = utc_iso(event.timestamp)
        rows.append((
            safe["event_id"], safe["source"], safe["computer"], safe["timestamp"],
            safe["username"], safe["description"], safe["severity"], safe["domain"],
            safe["source_ip"], safe["destination_ip"], safe["process_name"],
            safe["process_path"], safe["parent_process"], safe["command_line"],
            safe["logon_type"], _json(safe["raw_data"]), safe["account_sid"],
            _event_fingerprint(event),
        ))
    before = connection.total_changes
    try:
        connection.executemany(
            """INSERT OR IGNORE INTO events
            (event_id,source,computer,timestamp,username,description,severity,domain,
             source_ip,destination_ip,process_name,process_path,parent_process,
             command_line,logon_type,raw_data,account_sid,fingerprint)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return connection.total_changes - before


def load_events(
    connection: sqlite3.Connection, since: Optional[datetime] = None
) -> List[SecurityEvent]:
    """Load events ordered by UTC time, optionally after a timezone-aware date."""
    query = "SELECT * FROM events"
    params = ()
    if since is not None:
        query += " WHERE timestamp >= ?"
        params = (utc_iso(since),)
    query += " ORDER BY timestamp, id"
    rows = connection.execute(query, params).fetchall()
    result = []
    for row in rows:
        raw = row["raw_data"]
        result.append(SecurityEvent(
            event_id=row["event_id"], source=row["source"], computer=row["computer"],
            timestamp=datetime.fromisoformat(row["timestamp"]), username=row["username"],
            description=row["description"], severity=row["severity"],
            domain=row["domain"], source_ip=row["source_ip"],
            destination_ip=row["destination_ip"], process_name=row["process_name"],
            process_path=row["process_path"], parent_process=row["parent_process"],
            command_line=row["command_line"], logon_type=row["logon_type"],
            raw_data=json.loads(raw) if raw else {},
            account_sid=row["account_sid"],
        ))
    return result


def _detection_fingerprint(alert: DetectionAlert) -> str:
    values = (
        alert.rule_id, alert.rule_name, alert.username, alert.event_count,
        utc_iso(alert.first_seen), utc_iso(alert.last_seen), alert.threshold,
        alert.window_seconds, alert.correlation_keys, alert.evidence,
    )
    return hashlib.sha256(_json(values).encode("utf-8")).hexdigest()


def _legacy_detection_fingerprint(alert: DetectionAlert) -> str:
    """Fingerprint used before stable rule IDs were persisted."""
    values = (
        alert.rule_name, alert.username, alert.event_count,
        utc_iso(alert.first_seen), utc_iso(alert.last_seen), alert.threshold,
        alert.window_seconds, alert.correlation_keys,
    )
    return hashlib.sha256(_json(values).encode("utf-8")).hexdigest()


def save_detections(connection: sqlite3.Connection, alerts: Iterable[DetectionAlert]) -> int:
    """Store detections idempotently and return how many rows were added."""
    created_at = utc_iso(datetime.now(timezone.utc))
    before = connection.total_changes
    rows = []
    migrated = 0
    try:
        for alert in alerts:
            fingerprint = _detection_fingerprint(alert)
            row = (
                alert.rule_id or alert.rule_name.lower().replace(" ", "_"),
                alert.rule_name, alert.description,
                alert.username, alert.event_count, utc_iso(alert.first_seen),
                utc_iso(alert.last_seen), alert.threshold, alert.window_seconds, alert.severity,
                _json(alert.attack_techniques), _json(alert.evidence),
                _json(alert.recommended_actions), _json(alert.correlation_keys),
                fingerprint, created_at,
            )
            legacy_fingerprint = _legacy_detection_fingerprint(alert)
            legacy = connection.execute(
                "SELECT id FROM detections WHERE fingerprint=?",
                (legacy_fingerprint,),
            ).fetchone()
            if legacy and legacy_fingerprint != fingerprint:
                connection.execute(
                    """UPDATE detections SET rule_id=?,rule_name=?,description=?,username=?,
                       event_count=?,first_seen=?,last_seen=?,threshold=?,window_seconds=?,
                       severity=?,attack_techniques=?,evidence=?,recommended_actions=?,
                       correlation_keys=?,fingerprint=? WHERE id=?""",
                    row[:15] + (legacy[0],),
                )
                migrated += 1
            rows.append(row)
        connection.executemany(
            """INSERT OR IGNORE INTO detections
            (rule_id,rule_name,description,username,event_count,first_seen,last_seen,threshold,window_seconds,severity,
         attack_techniques,evidence,recommended_actions,correlation_keys,fingerprint,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return connection.total_changes - before - migrated


def load_detections(connection: sqlite3.Connection) -> List[DetectionAlert]:
    rows = connection.execute("SELECT * FROM detections ORDER BY first_seen, id").fetchall()
    return [DetectionAlert(
        rule_name=row["rule_name"], username=row["username"],
        event_count=row["event_count"], first_seen=datetime.fromisoformat(row["first_seen"]),
        last_seen=datetime.fromisoformat(row["last_seen"]), threshold=row["threshold"],
        window_seconds=row["window_seconds"], severity=row["severity"],
        attack_techniques=json.loads(row["attack_techniques"] or "[]"),
        rule_id=row["rule_id"], description=row["description"],
        evidence=json.loads(row["evidence"] or "[]"),
        recommended_actions=json.loads(row["recommended_actions"] or "[]"),
        correlation_keys=json.loads(row["correlation_keys"] or "[]"),
    ) for row in rows]


def detection_id(connection: sqlite3.Connection, alert: DetectionAlert) -> Optional[int]:
    """Find the persistent row matching an alert's stable fingerprint."""
    row = connection.execute(
        "SELECT id FROM detections WHERE fingerprint=?", (_detection_fingerprint(alert),)
    ).fetchone()
    return row[0] if row else None


def related_event_ids(connection: sqlite3.Connection, alert: DetectionAlert) -> List[int]:
    """Return database IDs for events that formed the alert evidence."""
    evidence_keys = {
        (item.get("event_id"), item.get("timestamp"))
        for item in alert.evidence
        if isinstance(item, dict) and item.get("event_id") is not None
    }
    found = []
    source_ip = next(
        (key.split(":", 1)[1] for key in alert.correlation_keys
         if key.startswith("source_ip:")),
        None,
    )
    username_key = next(
        (key.split(":", 1)[1] for key in alert.correlation_keys
         if key.startswith("username:")),
        None,
    )
    for event_id, timestamp in evidence_keys:
        if not timestamp:
            continue
        if alert.username:
            identity = username_key or alert.username.casefold()
            if "\\" in identity:
                domain, username = identity.rsplit("\\", 1)
            else:
                domain, username = "", identity
            rows = connection.execute(
                """SELECT id FROM events WHERE event_id=? AND timestamp=?
                   AND LOWER(username)=? AND COALESCE(LOWER(domain),'')=? ORDER BY id""",
                (event_id, timestamp, username, domain),
            ).fetchall()
        elif source_ip:
            rows = connection.execute(
                """SELECT id FROM events WHERE event_id=? AND timestamp=?
                   AND LOWER(source_ip)=? ORDER BY id""",
                (event_id, timestamp, source_ip),
            ).fetchall()
        else:
            rows = connection.execute(
                """SELECT id FROM events WHERE event_id=? AND timestamp=?
                   AND username IS NULL ORDER BY id""",
                (event_id, timestamp),
            ).fetchall()
        found.extend(row[0] for row in rows)
    return sorted(set(found))


def record_collection_run(
    connection: sqlite3.Connection, source: str, started_at: datetime,
    finished_at: datetime, records_scanned: int, events_stored: int,
    completed_normally: bool, max_records_reached: bool, error: Optional[str] = None,
) -> None:
    """Record non-sensitive collection counters and outcome."""
    connection.execute(
        """INSERT INTO collection_runs
        (source,started_at,finished_at,records_scanned,events_stored,
         completed_normally,max_records_reached,error)
        VALUES (?,?,?,?,?,?,?,?)""",
        (source, utc_iso(started_at), utc_iso(finished_at), records_scanned,
         events_stored, int(completed_normally), int(max_records_reached), error),
    )
    connection.commit()
