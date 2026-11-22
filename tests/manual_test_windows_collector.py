"""Manually check local Windows Security log access without printing PII.

Run from the project root with:
    py -3.9 tests\manual_test_windows_collector.py

This file is intentionally named so pytest's default ``test_*.py`` discovery
does not collect it as an automated test.
"""

import sys
from pathlib import Path

# Support direct execution from the project root without requiring installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.collectors.windows_collector import (  # noqa: E402
    CollectorError,
    collect_failed_logins_with_report,
)


def main():
    try:
        result = collect_failed_logins_with_report(max_events=5, max_records=20)
    except CollectorError as error:
        print("Windows Event Log collector error: {}".format(error))
        return 1

    summary = result.summary
    print("Records scanned: {}".format(summary.records_scanned))
    print("Event ID 4625 matches: {}".format(summary.event_count))
    print("max_records reached: {}".format(summary.max_records_reached))
    print("Read completed normally: {}".format(summary.completed_normally))
    for event in result.events:
        timestamp = event.timestamp.isoformat()
        print(
            "event_id={} timestamp={} source={} severity={}".format(
                event.event_id,
                timestamp,
                event.source,
                event.severity,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
