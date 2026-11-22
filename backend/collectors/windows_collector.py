"""Read failed logons from the local Windows Security event log."""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import List

from backend.models.security_event import SecurityEvent
from backend.normalization.event_normalizer import normalize_windows_event

try:  # Keep the package importable on non-Windows hosts for mocked tests.
    import win32api
    import win32con
    import win32evtlog
    import win32security
except ImportError:  # pragma: no cover - exercised on non-Windows hosts
    win32api = win32con = win32evtlog = win32security = None


class CollectorError(RuntimeError):
    """Raised when Windows privilege setup or event log access fails."""


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CollectionSummary:
    """Counts and stop reason for one successful collector run."""

    records_scanned: int
    event_count: int
    max_records_reached: bool
    completed_normally: bool


@dataclass
class CollectionResult:
    """Collected events plus a privacy-safe summary of the scan."""

    events: List[SecurityEvent]
    summary: CollectionSummary


def _require_windows_api():
    if any(api is None for api in (win32api, win32con, win32evtlog, win32security)):
        raise CollectorError("Windows Event Log collection requires pywin32 on Windows.")


def enable_security_privilege():
    """Enable SeSecurityPrivilege for this process, without changing system policy."""
    _require_windows_api()
    token = None
    try:
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
        )
        privilege_id = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
        win32api.SetLastError(0)
        win32security.AdjustTokenPrivileges(
            token, False, [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)]
        )
        error = win32api.GetLastError()
        if error == getattr(win32con, "ERROR_NOT_ALL_ASSIGNED", 1300):
            raise CollectorError(
                "SeSecurityPrivilege is not assigned to this process token."
            )
        return True
    except CollectorError:
        raise
    except Exception as error:
        raise CollectorError("Could not enable SeSecurityPrivilege: {}".format(error)) from error
    finally:
        if token is not None:
            import sys
            privilege_failed = sys.exc_info()[0] is not None
            try:
                win32api.CloseHandle(token)
            except Exception as error:
                LOGGER.error("Could not close the process token handle (%s)", type(error).__name__)
                if not privilege_failed:
                    raise CollectorError("Could not close the process token handle.") from error


def _event_username(inserts):
    # Event 4625 insertion string 6 (index 5) is TargetUserName.
    return _insert(inserts, 5)


def _insert(inserts, index):
    """Return a non-empty mapped insertion value, treating Windows '-' as absent."""
    if len(inserts) <= index:
        return None
    value = inserts[index]
    if value is None or str(value).strip() in {"", "-"}:
        return None
    return str(value)


def _member_name(value):
    """Project a simple CN from a Windows group-member DN when unambiguous."""
    value = _insert([value] if value is not None else [], 0)
    if value is None:
        return None
    if value[:3].casefold() != "cn=":
        return value
    common_name = value[3:].split(",", 1)[0]
    # Escaped/encoded RDN values need a real LDAP DN parser; keep them unknown.
    if not common_name or "\\" in common_name or "=" in common_name:
        return None
    return common_name


def _to_utc(value):
    if not isinstance(value, datetime):
        raise CollectorError("Windows event timestamp is not a datetime value.")
    # Pywin32 exposes SYSTEMTIME as local, naive datetime. astimezone uses the
    # machine's configured local timezone and returns an explicit UTC offset.
    if value.tzinfo is None:
        value = value.astimezone()
    return value.astimezone(timezone.utc)


def collect_failed_logins(max_events=100, max_records=500) -> List[SecurityEvent]:
    """Return up to max_events failed logons as normalized SecurityEvent objects.

    An empty list means collection succeeded but found no matching events.
    Collection failures raise CollectorError and are never converted to empty data.
    """
    return collect_failed_logins_with_report(max_events, max_records).events


def collect_failed_logins_with_report(
    max_events=100, max_records=500
) -> CollectionResult:
    """Collect failed logons and return them with a non-sensitive scan summary.

    ``completed_normally`` is true only when the event log returned an empty
    batch, indicating that the available scan range was exhausted. A false
    value means collection stopped at a configured limit. API failures raise
    CollectorError, so they do not produce a misleading successful report.
    """
    return collect_security_events_with_report(
        event_ids={4625}, max_events=max_events, max_records=max_records
    )


SUPPORTED_SECURITY_EVENT_IDS = frozenset(
    {4624, 4625, 4634, 4648, 4672, 4688, 4720, 4722, 4728, 4732, 4740}
)


def _event_fields(event_id, inserts):
    """Map known Windows insertion-string positions to common event fields."""
    fields = {"username": None, "domain": None, "source_ip": None,
              "process_name": None, "process_path": None,
              "parent_process": None, "command_line": None, "logon_type": None,
              "account_sid": None}
    if event_id == 4624:
        fields["username"] = _insert(inserts, 5)
        fields["domain"] = _insert(inserts, 6)
        fields["account_sid"] = _insert(inserts, 4)
        fields["logon_type"] = _insert(inserts, 8)
        fields["source_ip"] = _insert(inserts, 18)
    elif event_id == 4625:
        fields["username"] = _insert(inserts, 5)
        fields["domain"] = _insert(inserts, 6)
        fields["account_sid"] = _insert(inserts, 4)
        fields["logon_type"] = _insert(inserts, 10)
        fields["source_ip"] = _insert(inserts, 19)
    elif event_id == 4672:
        fields["username"] = _insert(inserts, 1)
        fields["domain"] = _insert(inserts, 2)
        fields["account_sid"] = _insert(inserts, 0)
    elif event_id in (4720, 4722):
        # Both templates begin with the target account and target domain.
        fields["username"] = _insert(inserts, 0)
        fields["domain"] = _insert(inserts, 1)
        fields["account_sid"] = _insert(inserts, 2)
    elif event_id in (4728, 4732):
        # These templates begin with MemberName, then MemberSid, then group data.
        # MemberName may be a distinguished name or '-' for some local members.
        fields["username"] = _member_name(_insert(inserts, 0))
        fields["account_sid"] = _insert(inserts, 1)
    elif event_id == 4740:
        fields["username"] = _insert(inserts, 0)
        fields["domain"] = _insert(inserts, 1)
        fields["account_sid"] = _insert(inserts, 2)
    elif event_id == 4634:
        fields["username"] = _insert(inserts, 1)
        fields["domain"] = _insert(inserts, 2)
        fields["logon_type"] = _insert(inserts, 4)
    elif event_id == 4648:
        # TargetUserName/TargetDomainName describe whose credentials were used.
        fields["username"] = _insert(inserts, 5)
        fields["domain"] = _insert(inserts, 6)
        fields["source_ip"] = _insert(inserts, 12)
    elif event_id == 4688:
        fields["process_path"] = _insert(inserts, 5)
        if fields["process_path"]:
            fields["process_name"] = fields["process_path"].rsplit("\\", 1)[-1] or None
        fields["command_line"] = _insert(inserts, 8)
        fields["parent_process"] = _insert(inserts, 13)
        fields["username"] = _insert(inserts, 1)
        fields["domain"] = _insert(inserts, 2)
    return fields


def collect_security_events_with_report(
    event_ids=SUPPORTED_SECURITY_EVENT_IDS, max_events=100, max_records=500,
    since=None,
) -> CollectionResult:
    """Read selected local Security log events with bounded, optionally dated scans."""
    for name, limit in (("max_events", max_events), ("max_records", max_records)):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ValueError("{} must be a non-negative integer".format(name))
    event_ids = set(event_ids)
    if not event_ids or any(not isinstance(value, int) or isinstance(value, bool) for value in event_ids):
        raise ValueError("event_ids must contain one or more integer event IDs")
    if since is not None:
        if not isinstance(since, datetime) or since.tzinfo is None or since.utcoffset() is None:
            raise ValueError("since must be a timezone-aware datetime")
        since = since.astimezone(timezone.utc)
    if max_events == 0 or max_records == 0:
        summary = CollectionSummary(
            records_scanned=0,
            event_count=0,
            max_records_reached=(max_records == 0),
            completed_normally=False,
        )
        return CollectionResult(events=[], summary=summary)

    _require_windows_api()
    enable_security_privilege()
    handle = None
    events_found = []
    records_scanned = 0
    completed_normally = False
    try:
        handle = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        while len(events_found) < max_events and records_scanned < max_records:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                completed_normally = True
                break
            for event in batch:
                if records_scanned >= max_records:
                    break
                records_scanned += 1
                try:
                    event_id = event.EventID & 0xFFFF
                    event_time = _to_utc(event.TimeGenerated)
                except Exception as error:
                    LOGGER.warning("Skipping malformed Security event (%s)", type(error).__name__)
                    continue
                if since is not None and event_time < since:
                    completed_normally = True
                    break
                if event_id not in event_ids:
                    continue
                try:
                    inserts = getattr(event, "StringInserts", None) or []
                    description = "; ".join(str(item) for item in inserts if item) or None
                    mapped = _event_fields(event_id, inserts)
                    raw = {
                        "event_id": event_id,
                        "source": getattr(event, "SourceName", None),
                        "computer": getattr(event, "ComputerName", None),
                        "timestamp": event_time,
                        "username": mapped["username"],
                        "domain": mapped["domain"],
                        "source_ip": mapped["source_ip"],
                        "process_name": mapped["process_name"],
                        "process_path": mapped["process_path"],
                        "parent_process": mapped["parent_process"],
                        "command_line": mapped["command_line"],
                        "logon_type": mapped["logon_type"],
                        "account_sid": mapped["account_sid"],
                        "description": description,
                        "raw_data": {"event_id": event_id, "inserts": list(inserts)},
                    }
                    events_found.append(normalize_windows_event(raw))
                except Exception as error:
                    LOGGER.warning("Skipping malformed Security event data (%s)", type(error).__name__)
                    continue
                if len(events_found) >= max_events:
                    break
            if completed_normally:
                break
        summary = CollectionSummary(
            records_scanned=records_scanned,
            event_count=len(events_found),
            max_records_reached=(records_scanned >= max_records),
            completed_normally=completed_normally,
        )
        return CollectionResult(events=events_found, summary=summary)
    except CollectorError:
        raise
    except Exception as error:
        LOGGER.error("Security event collection failed (%s)", type(error).__name__)
        raise CollectorError("Failed to read the Windows Security event log: {}".format(error)) from error
    finally:
        if handle is not None:
            import sys
            collection_failed = sys.exc_info()[0] is not None
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception as error:
                LOGGER.error("Could not close the Security Event Log handle (%s)", type(error).__name__)
                # Do not mask an earlier collection exception; a close failure
                # itself is still reported when it is the only failure.
                if not collection_failed:
                    raise CollectorError("Failed to close the Windows event log.") from error


if __name__ == "__main__":  # pragma: no cover - manual Windows entry point
    for record in collect_failed_logins():
        print(record)
