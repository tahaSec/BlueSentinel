"""Analyst-facing command line operations."""

import argparse
from datetime import datetime, timezone
import json
import logging
import sqlite3
import sys

from backend.attack.mitre import techniques_for_alert
from backend.collectors.sample_collector import load_sample_events
from backend.collectors.sysmon_collector import collect_sysmon_events_with_report
from backend.collectors.windows_collector import (
    SUPPORTED_SECURITY_EVENT_IDS,
    CollectorError,
    collect_security_events_with_report,
)
from backend.config.logging_config import configure_logging
from backend.config.settings import load_settings
from backend.detection.engine import DetectionEngine
from backend.detection.rule_loader import RuleValidationError, load_rules
from backend.incidents.incident_manager import (
    add_note,
    create_incidents_for_alerts,
    get_incident,
    list_incidents,
    update_status,
)
from backend.normalization.redaction import redact_sensitive
from backend.reporting.report_generator import export_report
from backend.storage.database import connect_database, utc_iso
from backend.storage.event_repository import (
    load_detections,
    load_events,
    record_collection_run,
    save_detections,
    save_events,
)


LOGGER = logging.getLogger("bluesentinel.cli")


def _date(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include Z or a UTC offset")
    return parsed.astimezone(timezone.utc)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="bluesentinel", description="Defensive Windows endpoint event investigation"
    )
    parser.add_argument("--config", help="Optional JSON configuration file")
    parser.add_argument("--db", help="SQLite database path")
    parser.add_argument("--rules", help="Directory containing JSON detection rules")
    parser.add_argument("--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"))
    commands = parser.add_subparsers(dest="command")

    collect = commands.add_parser("collect", help="Collect Windows or sample events")
    collect.add_argument("--source", choices=("security", "sysmon"), default="security")
    collect.add_argument("--input", help="Import an event JSON file instead of reading Windows")
    collect.add_argument("--max-events", type=int)
    collect.add_argument("--max-records", type=int)
    collect.add_argument("--since", type=_date, help="Only include events at or after this ISO 8601 time")

    detect = commands.add_parser("detect", aliases=["analyze"], help="Run enabled JSON detection rules")
    detect.add_argument("--since", type=_date)
    detect.add_argument("--output", help="Optional report destination")
    detect.add_argument("--format", choices=("json", "csv", "markdown"), default="json")

    incidents = commands.add_parser("incidents", help="Review incident records")
    incident_commands = incidents.add_subparsers(dest="incident_command")
    incident_list = incident_commands.add_parser("list", help="List incidents")
    incident_list.add_argument("--status", choices=("NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"))
    incident_show = incident_commands.add_parser("show", help="Show one incident")
    incident_show.add_argument("incident_id", type=int)
    incident_update = incident_commands.add_parser("update", help="Update incident status or add a note")
    incident_update.add_argument("incident_id", type=int)
    incident_update.add_argument("--status", choices=("NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"))
    incident_update.add_argument("--note")

    report = commands.add_parser("report", help="Export stored events, detections, and incidents")
    report.add_argument("--output", required=True)
    report.add_argument("--format", choices=("json", "csv", "markdown"), default="json")

    rules = commands.add_parser("rules", help="Inspect detection rule files")
    rules_commands = rules.add_subparsers(dest="rules_command")
    rules_commands.add_parser("list", help="List rules and enabled state")
    rules_commands.add_parser("validate", help="Validate every JSON rule")

    test_connection = commands.add_parser("test-connection", help="Check whether a Windows event channel can be opened")
    test_connection.add_argument("--source", choices=("security", "sysmon"), default="security")
    commands.add_parser("status", help="Show database and collection counts")
    return parser


def _print_incident(connection, incident):
    print("Incident #{} — {}".format(incident.incident_id, redact_sensitive(incident.title)))
    print("Status: {} | Severity: {}".format(incident.status, incident.severity))
    print("Created: {} | Updated: {}".format(utc_iso(incident.created_at), utc_iso(incident.updated_at)))
    print("Description: {}".format(redact_sensitive(incident.description)))
    print("Detection rule: {}".format(incident.detection_rule or "none"))
    print("ATT&CK: {}".format(", ".join(incident.mitre_mapping) or "none"))
    print("Related event IDs: {}".format(", ".join(map(str, incident.related_event_ids)) or "none"))
    event_rows = []
    if incident.related_event_ids:
        placeholders = ",".join("?" for _ in incident.related_event_ids)
        event_rows = connection.execute(
            """SELECT event_id,source,computer,timestamp,username,description,
                      process_name,command_line FROM events WHERE id IN ({}) ORDER BY timestamp""".format(
                placeholders
            ),
            tuple(incident.related_event_ids),
        )
    for event_row in event_rows:
        print("Evidence event {} at {} | source={} | host={} | user={}".format(
            event_row["event_id"], event_row["timestamp"], event_row["source"],
            event_row["computer"], event_row["username"],
        ))
        detail = event_row["command_line"] or event_row["description"]
        if detail:
            print("  Detail: {}".format(redact_sensitive(detail)))
    print("Analyst notes:")
    for note in incident.analyst_notes:
        print("- {}".format(redact_sensitive(note)))
    print("Recommended actions:")
    for action in incident.recommended_actions:
        print("- {}".format(action))


def _collect(connection, args, settings):
    started = datetime.now(timezone.utc)
    try:
        if args.input:
            events = load_sample_events(args.input)
            summary = None
        else:
            max_events = args.max_events if args.max_events is not None else settings.max_events
            max_records = args.max_records if args.max_records is not None else settings.max_records
            if args.source == "sysmon":
                result = collect_sysmon_events_with_report(max_events, max_records, args.since)
            else:
                result = collect_security_events_with_report(
                    SUPPORTED_SECURITY_EVENT_IDS, max_events, max_records, args.since
                )
            events, summary = result.events, result.summary
        added = save_events(connection, events)
        if summary is None:
            print("Imported {} synthetic event(s); stored {} new event(s).".format(len(events), added))
        else:
            print("Collected {} event(s); stored {} new event(s).".format(len(events), added))
            print("Scanned {}; max_records reached: {}; range exhausted: {}".format(
                summary.records_scanned, summary.max_records_reached, summary.completed_normally
            ))
            record_collection_run(
                connection, args.source, started, datetime.now(timezone.utc),
                summary.records_scanned, added, summary.completed_normally,
                summary.max_records_reached,
            )
        LOGGER.info("Collection completed: source=%s records=%d stored=%d", args.source, len(events), added)
    except Exception as error:
        if not args.input:
            try:
                record_collection_run(
                    connection, args.source, started, datetime.now(timezone.utc),
                    0, 0, False, False, "collection_failed",
                )
            except sqlite3.Error:
                LOGGER.error("Could not persist collection failure metadata")
        raise error


def _detect(connection, args, rules_directory):
    events = load_events(connection, args.since)
    alerts = DetectionEngine.from_directory(rules_directory).detect(events)
    inserted = save_detections(connection, alerts)
    new_incidents = create_incidents_for_alerts(connection, alerts)
    all_alerts = load_detections(connection)
    incidents = list_incidents(connection)
    print("Analyzed {} event(s); produced {} signal(s), stored {} new detection(s).".format(
        len(events), len(alerts), inserted
    ))
    print("Created {} incident(s); total open workflow records: {}.".format(
        len(new_incidents), len(incidents)
    ))
    for alert in alerts:
        mapped = ", ".join(item["id"] for item in techniques_for_alert(alert)) or "none"
        print("{} {}: {} signal(s), ATT&CK {}".format(
            alert.severity, alert.rule_name, alert.event_count, mapped
        ))
    if args.output:
        export_report(args.output, events, all_alerts, incidents, args.format)
        print("Report written to {}".format(args.output))


def run(argv=None) -> int:
    """Parse options, run one analyst command, and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        settings = load_settings(args.config)
        database_path = args.db or settings.database_path
        rules_directory = args.rules or settings.rules_directory
        configure_logging(args.log_level or settings.log_level)
        if args.command == "rules":
            loaded = load_rules(rules_directory)
            if args.rules_command == "validate":
                print("Validated {} rule(s).".format(len(loaded)))
            elif args.rules_command == "list":
                for rule in loaded:
                    print("{} [{}] {} — {}".format(
                        rule["id"], "enabled" if rule["enabled"] else "disabled",
                        rule["name"], rule["severity"].upper(),
                    ))
            else:
                parser.parse_args(["rules", "--help"])
            return 0

        if args.command == "test-connection":
            from backend.collectors.windows_collector import win32evtlog
            if win32evtlog is None:
                raise CollectorError("Event Log connection tests require pywin32 on Windows.")
            channel = "Security" if args.source == "security" else "Microsoft-Windows-Sysmon/Operational"
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
            except Exception as error:
                raise CollectorError("Cannot open {}: {}".format(channel, error)) from error
            try:
                print("Event channel opened successfully: {}.".format(channel))
            finally:
                try:
                    win32evtlog.CloseEventLog(handle)
                except Exception as error:
                    raise CollectorError("Cannot close {}: {}".format(channel, error)) from error
            return 0

        connection = connect_database(database_path)
        try:
            if args.command == "collect":
                _collect(connection, args, settings)
            elif args.command in ("detect", "analyze"):
                _detect(connection, args, rules_directory)
            elif args.command == "incidents":
                if args.incident_command == "list":
                    for incident in list_incidents(connection, args.status):
                        print("#{} [{}|{}] {}".format(
                            incident.incident_id, incident.status, incident.severity, incident.title
                        ))
                elif args.incident_command == "show":
                    _print_incident(connection, get_incident(connection, args.incident_id))
                elif args.incident_command == "update":
                    if not args.status and not args.note:
                        raise ValueError("supply --status and/or --note")
                    if args.status:
                        update_status(connection, args.incident_id, args.status)
                    if args.note:
                        add_note(connection, args.incident_id, args.note)
                    print("Updated incident #{}.".format(args.incident_id))
                else:
                    print("Use 'incidents --help' to see incident commands.")
            elif args.command == "report":
                output = export_report(
                    args.output, load_events(connection), load_detections(connection),
                    list_incidents(connection), args.format,
                )
                print("Report written to {}".format(output))
            elif args.command == "status":
                counts = {}
                for table in ("events", "detections", "incidents", "collection_runs"):
                    counts[table] = connection.execute(
                        "SELECT COUNT(*) FROM {}".format(table)
                    ).fetchone()[0]
                print("Database: {}".format(database_path))
                for table, count in counts.items():
                    print("{}: {}".format(table.replace("_", " ").title(), count))
        finally:
            connection.close()
        return 0
    except (CollectorError, RuleValidationError, OSError, sqlite3.Error,
            ValueError, TypeError, LookupError, ImportError) as error:
        LOGGER.error("%s", error)
        print("BlueSentinel: {}".format(error), file=sys.stderr)
        return 2
