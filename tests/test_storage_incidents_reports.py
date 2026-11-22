import csv
import copy
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from backend.detection.engine import DetectionEngine
from backend.collectors.sample_collector import load_sample_events
from backend.incidents.incident_manager import (
    add_note, create_incidents_for_alerts, get_incident, list_incidents, update_status,
)
from backend.models.security_event import SecurityEvent
from backend.reporting.report_generator import export_report
from backend.storage.database import connect_database
from backend.storage.event_repository import (
    _legacy_detection_fingerprint, load_detections, load_events,
    save_detections, save_events,
)


BASE = datetime(2025, 1, 1, tzinfo=timezone.utc)


def sample_events():
    return [SecurityEvent(
        event_id=4625, source="Windows Security", computer="LAB", timestamp=BASE + timedelta(seconds=sec),
        username="analyst-test", description="Synthetic failed login", raw_data={"event_id": 4625},
        account_sid="S-1-5-21-555",
    ) for sec in (0, 10, 20, 30, 40)]


def test_event_and_detection_persistence_is_idempotent(tmp_path):
    connection = connect_database(str(tmp_path / "events.db"))
    try:
        events = sample_events()
        assert save_events(connection, events) == 5
        assert save_events(connection, events) == 0
        loaded = load_events(connection)
        assert len(loaded) == 5
        assert loaded[0].timestamp.tzinfo == timezone.utc
        assert loaded[0].account_sid == "S-1-5-21-555"
        alerts = DetectionEngine.from_directory("rules").detect(loaded)
        assert save_detections(connection, alerts) == 1
        assert save_detections(connection, alerts) == 0
        saved_alerts = load_detections(connection)
        assert len(saved_alerts) == 1
        assert saved_alerts[0].attack_techniques == ["T1110"]
    finally:
        connection.close()


def test_distinct_evidence_sequences_are_not_mistaken_for_duplicate_detections(tmp_path):
    connection = connect_database(str(tmp_path / "evidence-fingerprint.db"))
    try:
        alert = DetectionEngine.from_directory("rules").detect(sample_events())[0]
        other = copy.deepcopy(alert)
        other.evidence = [dict(item) for item in alert.evidence]
        other.evidence[0]["event_id"] = 4648
        assert save_detections(connection, [alert, other]) == 2
        assert save_detections(connection, [alert, other]) == 0
        assert len(load_detections(connection)) == 2
    finally:
        connection.close()


def test_legacy_detection_rule_slug_is_upgraded_without_losing_links(tmp_path):
    connection = connect_database(str(tmp_path / "legacy-detection.db"))
    try:
        alert = DetectionEngine.from_directory("rules").detect(sample_events())[0]
        old_fingerprint = _legacy_detection_fingerprint(alert)
        now = BASE.isoformat()
        cursor = connection.execute(
            """INSERT INTO detections
               (rule_id,rule_name,description,username,event_count,first_seen,last_seen,
                threshold,window_seconds,severity,attack_techniques,evidence,
                recommended_actions,correlation_keys,fingerprint,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "brute_force_detection", alert.rule_name, alert.description, alert.username,
                alert.event_count, alert.first_seen.isoformat(), alert.last_seen.isoformat(),
                alert.threshold, alert.window_seconds, alert.severity,
                json.dumps(alert.attack_techniques), json.dumps(alert.evidence),
                json.dumps(alert.recommended_actions), json.dumps(alert.correlation_keys),
                old_fingerprint, now,
            ),
        )
        detection_row_id = cursor.lastrowid
        incident_cursor = connection.execute(
            """INSERT INTO incidents
               (title,description,severity,status,created_at,updated_at)
               VALUES('Existing signal','Existing incident','HIGH','NEW',?,?)""",
            (now, now),
        )
        connection.execute(
            "INSERT INTO incident_detections(incident_id,detection_id) VALUES(?,?)",
            (incident_cursor.lastrowid, detection_row_id),
        )
        connection.commit()

        assert save_detections(connection, [alert]) == 0
        row = connection.execute(
            "SELECT id,rule_id FROM detections"
        ).fetchone()
        assert (row["id"], row["rule_id"]) == (detection_row_id, "BS-001")
        assert connection.execute("SELECT COUNT(*) FROM incident_detections").fetchone()[0] == 1
        assert load_detections(connection)[0].rule_id == "BS-001"
    finally:
        connection.close()


def test_incident_lifecycle_notes_and_evidence_links(tmp_path):
    connection = connect_database(str(tmp_path / "incidents.db"))
    try:
        events = sample_events()
        save_events(connection, events)
        alerts = DetectionEngine.from_directory("rules").detect(events)
        save_detections(connection, alerts)
        incident_ids = create_incidents_for_alerts(connection, alerts)
        assert len(incident_ids) == 1
        assert create_incidents_for_alerts(connection, alerts) == []
        incident_id = incident_ids[0]
        add_note(connection, incident_id, "Synthetic test note")
        update_status(connection, incident_id, "investigating")
        incident = get_incident(connection, incident_id)
        assert incident.status == "INVESTIGATING"
        assert incident.related_event_ids
        assert incident.analyst_notes == ["Synthetic test note"]
        assert len(list_incidents(connection, "INVESTIGATING")) == 1
        with pytest.raises(ValueError):
            update_status(connection, incident_id, "CLOSED")
    finally:
        connection.close()


def test_correlated_detection_signals_share_one_incident(tmp_path):
    connection = connect_database(str(tmp_path / "correlated.db"))
    try:
        events = sample_events() + [SecurityEvent(
            event_id=4624, source="Windows Security", computer="LAB",
            timestamp=BASE + timedelta(seconds=45), username="analyst-test",
            description="Synthetic successful login",
        )]
        save_events(connection, events)
        alerts = DetectionEngine.from_directory("rules").detect(events)
        assert {item.rule_id for item in alerts} == {"BS-001", "BS-002"}
        save_detections(connection, alerts)
        assert len(create_incidents_for_alerts(connection, alerts)) == 1
        incidents = list_incidents(connection)
        assert len(incidents) == 1
        assert len(incidents[0].detection_ids) == 2
        assert "Correlated 2 detection signals" in incidents[0].description
    finally:
        connection.close()


def test_event_chain_detection_persists_with_both_source_event_links(tmp_path):
    connection = connect_database(str(tmp_path / "event-chain.db"))
    try:
        events = [
            SecurityEvent(
                event_id=4624, source="Windows Security", computer="LAB",
                timestamp=BASE, username="chain-user", account_sid="S-1-5-21-777",
                description="Synthetic successful logon",
            ),
            SecurityEvent(
                event_id=4672, source="Windows Security", computer="LAB",
                timestamp=BASE + timedelta(seconds=30), username="CHAIN-USER",
                account_sid="S-1-5-21-777",
                description="Synthetic privileged logon",
            ),
        ]
        save_events(connection, events)
        alerts = DetectionEngine.from_directory("rules").detect(events)
        chain_alert = next(alert for alert in alerts if alert.rule_id == "BS-007")
        assert save_detections(connection, [chain_alert]) == 1
        incident_ids = create_incidents_for_alerts(connection, [chain_alert])
        assert len(incident_ids) == 1
        incident = get_incident(connection, incident_ids[0])
        assert len(incident.related_event_ids) == 2
        assert len(incident.detection_ids) == 1
    finally:
        connection.close()


def test_source_ip_brute_force_incident_links_events_with_different_users(tmp_path):
    connection = connect_database(str(tmp_path / "ip-brute-force.db"))
    try:
        events = [SecurityEvent(
            event_id=4625, source="Windows Security", computer="LAB",
            timestamp=BASE + timedelta(seconds=seconds), username="user-{}".format(index),
            description="Synthetic failed login", source_ip="192.0.2.88",
        ) for index, seconds in enumerate((0, 10, 20, 30, 40))]
        save_events(connection, events)
        alerts = DetectionEngine.from_directory("rules").detect(events)
        ip_alert = next(alert for alert in alerts if alert.rule_id == "BS-001")
        assert ip_alert.username is None
        assert save_detections(connection, [ip_alert]) == 1
        incident_id = create_incidents_for_alerts(connection, [ip_alert])[0]
        incident = get_incident(connection, incident_id)
        assert len(incident.related_event_ids) == 5
    finally:
        connection.close()


def test_mixed_security_and_sysmon_sample_runs_end_to_end(tmp_path):
    windows_events = load_sample_events("sample_data/events/mixed_windows_events.json")
    sysmon_events = load_sample_events("sample_data/events/sysmon_events.json")
    events = windows_events + sysmon_events
    connection = connect_database(str(tmp_path / "mixed-pipeline.db"))
    try:
        assert save_events(connection, events) == len(events)
        alerts = DetectionEngine.from_directory("rules").detect(load_events(connection))
        rule_ids = {alert.rule_id for alert in alerts}
        assert {
            "BS-001", "BS-002", "BS-003", "BS-004", "BS-005",
            "BS-007", "BS-008", "BS-009", "BS-010",
        }.issubset(rule_ids)
        assert save_detections(connection, alerts) > 0
        created_incidents = create_incidents_for_alerts(connection, alerts)
        assert created_incidents
        linked = connection.execute(
            "SELECT COUNT(*) FROM incident_detections"
        ).fetchone()[0]
        assert linked > 0
    finally:
        connection.close()


def test_legacy_database_schema_is_upgraded_without_data_loss(tmp_path):
    path = str(tmp_path / "legacy.db")
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL, source TEXT, computer TEXT, timestamp TEXT NOT NULL, username TEXT, description TEXT, severity TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO events(event_id,timestamp,severity) VALUES(4625,?,?)",
        (BASE.isoformat(), "INFO"),
    )
    connection.commit()
    connection.close()
    connection = connect_database(path)
    try:
        assert len(load_events(connection)) == 1
        columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
        assert {"raw_data", "fingerprint", "command_line", "account_sid"}.issubset(columns)
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
    finally:
        connection.close()


def test_json_csv_and_markdown_reports_are_generated_without_secret_values(tmp_path):
    events = sample_events()
    alerts = DetectionEngine.from_directory("rules").detect(events)
    outputs = {}
    for fmt in ("json", "csv", "markdown"):
        destination = tmp_path / ("report." + fmt)
        export_report(str(destination), events, alerts, [], fmt)
        outputs[fmt] = destination.read_text(encoding="utf-8-sig")
        assert destination.exists()
    payload = json.loads(outputs["json"])
    assert payload["detection_summary"]["alert_count"] == 1
    assert payload["detections"][0]["mitre"][0]["id"] == "T1110"
    assert "Analytical signal" in outputs["markdown"]
    with (tmp_path / "report.csv").open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
        assert [row["record_type"] for row in rows] == ["SUMMARY", "DETECTION"]


def test_report_and_normalization_redact_secret_shaped_data():
    from backend.normalization.event_normalizer import normalize_windows_event

    event = normalize_windows_event({
        "event_id": 4688,
        "timestamp": BASE,
        "command_line": "tool.exe --password=hunter2; Authorization: Bearer bearer-secret",
        "raw_data": {"api_key": "sample-secret"},
    })
    assert "hunter2" not in event.command_line
    assert "bearer-secret" not in event.command_line
    assert "[REDACTED]" in event.command_line
    assert event.raw_data["api_key"] == "[REDACTED]"


def test_reports_redact_untrusted_host_and_username_text(tmp_path):
    events = sample_events()
    events[0].computer = "LAB password=host-secret"
    alerts = DetectionEngine.from_directory("rules").detect(events)
    alerts[0].username = "password=user-secret"
    for report_format in ("json", "markdown"):
        destination = tmp_path / ("safe." + report_format)
        export_report(str(destination), events, alerts, [], report_format)
        content = destination.read_text(encoding="utf-8")
        assert "host-secret" not in content
        assert "user-secret" not in content
        assert "[REDACTED]" in content


def test_repository_redacts_direct_model_values_before_storage(tmp_path):
    connection = connect_database(str(tmp_path / "redact.db"))
    try:
        direct_event = SecurityEvent(
            event_id=4688, source="Windows Security", computer="LAB", timestamp=BASE,
            username="test-user", description=None,
            command_line="tool.exe --password=not-a-real-password",
            raw_data={"access_token": "not-a-real-token"},
        )
        save_events(connection, [direct_event])
        row = connection.execute("SELECT command_line,raw_data FROM events").fetchone()
        assert "not-a-real-password" not in row["command_line"]
        assert "not-a-real-token" not in row["raw_data"]
    finally:
        connection.close()
