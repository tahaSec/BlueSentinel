import json
from pathlib import Path

from backend.main import main


def test_offline_collection_detection_incident_and_report_pipeline(tmp_path, capsys):
    database = str(tmp_path / "blue.db")
    report = str(tmp_path / "investigation.json")
    sample_path = "sample_data/failed_logons.json"

    assert main(["--db", database, "collect", "--input", sample_path]) == 0
    assert "Imported 5 synthetic event(s)" in capsys.readouterr().out
    assert main(["--db", database, "detect", "--output", report]) == 0
    output = capsys.readouterr().out
    assert "produced 1 signal(s)" in output
    assert "Created 1 incident(s)" in output
    assert main(["--db", database, "incidents", "list"]) == 0
    assert "Brute Force Detection" in capsys.readouterr().out

    assert main(["--db", database, "report", "--output", report]) == 0
    capsys.readouterr()
    payload = json.loads(Path(report).read_text(encoding="utf-8"))
    assert payload["detection_summary"]["alert_count"] == 1
    assert payload["incident_summary"]["incident_count"] == 1


def test_rule_commands_work_without_opening_database(capsys):
    assert main(["rules", "validate"]) == 0
    assert "Validated 10 rule(s)" in capsys.readouterr().out


def test_cli_runs_mixed_synthetic_pipeline_with_ordered_correlations(tmp_path, capsys):
    database = str(tmp_path / "mixed.db")
    report = str(tmp_path / "mixed.json")
    assert main([
        "--db", database, "collect", "--input",
        "sample_data/events/mixed_windows_events.json",
    ]) == 0
    capsys.readouterr()
    assert main([
        "--db", database, "collect", "--input",
        "sample_data/events/sysmon_events.json",
    ]) == 0
    capsys.readouterr()
    assert main(["--db", database, "detect", "--output", report]) == 0
    capsys.readouterr()

    payload = json.loads(Path(report).read_text(encoding="utf-8"))
    rule_ids = {alert["rule_id"] for alert in payload["detections"]}
    assert {"BS-001", "BS-002", "BS-004", "BS-007", "BS-008", "BS-009", "BS-010"}.issubset(rule_ids)
    assert payload["incident_summary"]["incident_count"] > 0
