"""SQLite schema setup and UTC serialization helpers."""

from datetime import datetime, timezone
from pathlib import Path
import sqlite3


SCHEMA_VERSION = 2


def utc_iso(value: datetime) -> str:
    """Serialize a datetime as timezone-aware UTC ISO 8601 text."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("database timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


def initialize_database(connection: sqlite3.Connection) -> None:
    """Create or upgrade the local schema without discarding existing data."""
    connection.execute("PRAGMA foreign_keys = ON")
    existing_version = connection.execute("PRAGMA user_version").fetchone()[0]
    if existing_version > SCHEMA_VERSION:
        raise RuntimeError("database schema is newer than this BlueSentinel version")
    connection.executescript(
        """CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL, source TEXT,
            computer TEXT, timestamp TEXT NOT NULL, username TEXT,
            description TEXT, severity TEXT NOT NULL,
            domain TEXT, source_ip TEXT, destination_ip TEXT,
            process_name TEXT, process_path TEXT, parent_process TEXT,
            command_line TEXT, logon_type TEXT, raw_data TEXT, account_sid TEXT
        );
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL, rule_name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            username TEXT, event_count INTEGER NOT NULL, first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, threshold INTEGER NOT NULL DEFAULT 0,
            window_seconds REAL NOT NULL DEFAULT 0, severity TEXT NOT NULL,
            attack_techniques TEXT NOT NULL DEFAULT '[]', evidence TEXT NOT NULL DEFAULT '[]',
            recommended_actions TEXT NOT NULL DEFAULT '[]', correlation_keys TEXT NOT NULL DEFAULT '[]',
            fingerprint TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY, rule_name TEXT NOT NULL, username TEXT NOT NULL,
            event_count INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            threshold INTEGER NOT NULL, window_seconds REAL NOT NULL, severity TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
            severity TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, detection_rule TEXT, mitre_mapping TEXT NOT NULL DEFAULT '[]',
            recommended_actions TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS incident_events (
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            PRIMARY KEY (incident_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS incident_detections (
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            detection_id INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
            PRIMARY KEY (incident_id, detection_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_detection_unique
            ON incident_detections(detection_id);
        CREATE TABLE IF NOT EXISTS analyst_notes (
            id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            note TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS collection_runs (
            id INTEGER PRIMARY KEY, source TEXT NOT NULL, started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL, records_scanned INTEGER NOT NULL,
            events_stored INTEGER NOT NULL, completed_normally INTEGER NOT NULL,
            max_records_reached INTEGER NOT NULL, error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_user_time ON events(username, timestamp);
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, updated_at);
        CREATE INDEX IF NOT EXISTS idx_notes_incident ON analyst_notes(incident_id, created_at);"""
    )

    # Upgrade databases created by the earlier CLI without dropping its data.
    event_columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
    for name, sql_type in (
        ("domain", "TEXT"), ("source_ip", "TEXT"), ("destination_ip", "TEXT"),
        ("process_name", "TEXT"), ("process_path", "TEXT"),
        ("parent_process", "TEXT"), ("command_line", "TEXT"),
        ("logon_type", "TEXT"), ("raw_data", "TEXT"), ("account_sid", "TEXT"),
        ("fingerprint", "TEXT"),
    ):
        if name not in event_columns:
            connection.execute("ALTER TABLE events ADD COLUMN {} {}".format(name, sql_type))
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint) WHERE fingerprint IS NOT NULL")
    detection_columns = {row[1] for row in connection.execute("PRAGMA table_info(detections)")}
    for name, definition in (
        ("description", "TEXT NOT NULL DEFAULT ''"),
        ("threshold", "INTEGER NOT NULL DEFAULT 0"),
        ("window_seconds", "REAL NOT NULL DEFAULT 0"),
        ("attack_techniques", "TEXT NOT NULL DEFAULT '[]'"),
        ("evidence", "TEXT NOT NULL DEFAULT '[]'"),
        ("recommended_actions", "TEXT NOT NULL DEFAULT '[]'"),
        ("correlation_keys", "TEXT NOT NULL DEFAULT '[]'"),
        ("fingerprint", "TEXT"),
    ):
        if name not in detection_columns:
            connection.execute("ALTER TABLE detections ADD COLUMN {} {}".format(name, definition))
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_detections_fingerprint ON detections(fingerprint) WHERE fingerprint IS NOT NULL")
    connection.execute("PRAGMA user_version = 2")
    connection.commit()


def connect_database(path: str) -> sqlite3.Connection:
    """Open and initialize a local database using parameterized SQLite APIs."""
    if path != ":memory:":
        Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        initialize_database(connection)
    except Exception:
        connection.close()
        raise
    return connection
