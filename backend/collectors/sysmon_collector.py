"""Optional collector for selected Sysmon Operational events."""

from datetime import datetime, timezone
import logging
from typing import List

from backend.collectors import windows_collector
from backend.collectors.windows_collector import CollectionResult, CollectionSummary, CollectorError
from backend.models.security_event import SecurityEvent
from backend.normalization.event_normalizer import normalize_windows_event


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SUPPORTED_SYSMON_EVENT_IDS = frozenset({1, 3, 7, 8, 10, 11, 12, 13, 14, 22})
LOGGER = logging.getLogger(__name__)


def _map_fields(event_id: int, inserts: List[str]):
    """Map documented Sysmon insertion order to common fields when present."""
    fields = {
        "username": None, "source_ip": None, "destination_ip": None,
        "process_name": None, "process_path": None, "parent_process": None,
        "command_line": None, "domain": None,
    }
    if event_id == 1:
        if len(inserts) > 4:
            fields["process_path"] = inserts[4] or None
            fields["process_name"] = inserts[4].rsplit("\\", 1)[-1] or None
        if len(inserts) > 10:
            fields["command_line"] = inserts[10] or None
        if len(inserts) > 12:
            fields["username"] = inserts[12] or None
        if len(inserts) > 20:
            fields["parent_process"] = inserts[20] or None
    elif event_id == 3:
        if len(inserts) > 5:
            fields["username"] = inserts[5] or None
        if len(inserts) > 9:
            fields["source_ip"] = inserts[9] or None
        if len(inserts) > 14:
            fields["destination_ip"] = inserts[14] or None
        if len(inserts) > 4:
            fields["process_path"] = inserts[4] or None
            fields["process_name"] = inserts[4].rsplit("\\", 1)[-1] or None
    return fields


def collect_sysmon_events_with_report(
    max_events: int = 100, max_records: int = 500, since: datetime = None
) -> CollectionResult:
    """Read supported events from the optional Sysmon channel.

    This function does not enable privileges or change Windows settings. If
    Sysmon is absent or unreadable, CollectorError distinguishes that from an
    empty successful scan.
    """
    for name, limit in (("max_events", max_events), ("max_records", max_records)):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError("{} must be a non-negative integer".format(name))
    if since is not None:
        if not isinstance(since, datetime) or since.tzinfo is None or since.utcoffset() is None:
            raise ValueError("since must be a timezone-aware datetime")
        since = since.astimezone(timezone.utc)
    if max_events == 0 or max_records == 0:
        return CollectionResult([], CollectionSummary(0, 0, max_records == 0, False))

    api = windows_collector.win32evtlog
    if api is None:
        raise CollectorError("Sysmon collection requires pywin32 on Windows.")
    handle = None
    records_scanned = 0
    events_found = []
    completed_normally = False
    try:
        handle = api.OpenEventLog(None, SYSMON_CHANNEL)
        flags = api.EVENTLOG_BACKWARDS_READ | api.EVENTLOG_SEQUENTIAL_READ
        while len(events_found) < max_events and records_scanned < max_records:
            batch = api.ReadEventLog(handle, flags, 0)
            if not batch:
                completed_normally = True
                break
            for event in batch:
                if records_scanned >= max_records:
                    break
                records_scanned += 1
                try:
                    timestamp = windows_collector._to_utc(event.TimeGenerated)
                    event_id = event.EventID & 0xFFFF
                    inserts = getattr(event, "StringInserts", None) or []
                except Exception as error:
                    LOGGER.warning("Skipping malformed Sysmon event (%s)", type(error).__name__)
                    continue
                if since is not None and timestamp < since:
                    completed_normally = True
                    break
                if event_id not in SUPPORTED_SYSMON_EVENT_IDS:
                    continue
                try:
                    fields = _map_fields(event_id, inserts)
                    raw = {
                        "event_id": event_id,
                        "source": "Sysmon",
                        "computer": getattr(event, "ComputerName", None),
                        "timestamp": timestamp,
                        "description": "; ".join(str(value) for value in inserts if value) or None,
                        "raw_data": {"event_id": event_id, "inserts": list(inserts)},
                    }
                    raw.update(fields)
                    events_found.append(normalize_windows_event(raw))
                except Exception as error:
                    LOGGER.warning("Skipping malformed Sysmon event data (%s)", type(error).__name__)
                    continue
                if len(events_found) >= max_events:
                    break
            if completed_normally:
                break
        summary = CollectionSummary(
            records_scanned, len(events_found), records_scanned >= max_records,
            completed_normally,
        )
        return CollectionResult(events_found, summary)
    except CollectorError:
        raise
    except Exception as error:
        LOGGER.error("Sysmon event collection failed (%s)", type(error).__name__)
        raise CollectorError(
            "Could not read the Sysmon Operational log: {}. Verify Sysmon is installed and the channel is readable.".format(error)
        ) from error
    finally:
        if handle is not None:
            import sys
            collection_failed = sys.exc_info()[0] is not None
            try:
                api.CloseEventLog(handle)
            except Exception as error:
                LOGGER.error("Could not close the Sysmon Event Log handle (%s)", type(error).__name__)
                if not collection_failed:
                    raise CollectorError("Failed to close the Sysmon event log.") from error
