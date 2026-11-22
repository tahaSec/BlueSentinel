# Detection rules

Rule files live in `rules/`. Validate them before use:

```powershell
py -3.9 -m backend.main rules validate
py -3.9 -m backend.main rules list
```

## Rule fields

- `id`: stable unique identifier.
- `name` and `description`: analyst-facing explanation.
- `sources`: event source scope such as Windows Security or Sysmon.
- `conditions.event_ids`: source event IDs the detector evaluates.
- `detector`: a supported implementation name; unknown types are rejected.
- `options`: threshold, window, indicators, and detector-specific settings.
- `enabled`: explicit boolean switch.
- `severity`: LOW, MEDIUM, HIGH, or CRITICAL.
- `mitre_tactics`, `mitre`: analytic classification; only supported mappings appear in report metadata.
- `recommended_actions`: investigation suggestions, never automatic actions.

## Implemented signals

### Brute force

Five or more 4625 events for the same non-empty username (scoped by domain when present) or source IP in 60 seconds. The boundary is inclusive. One alert is emitted when the rolling count first reaches the threshold for a continuous qualifying burst. If the same exact event sequence qualifies by both username and IP, it is reported once under the username. ATT&CK T1110 is an analytic mapping; the alert does not establish maliciousness.

### Successful login after failures

At least three 4625 events followed by a 4624 for the same username within five minutes. This can be legitimate password correction or a user returning to a session; validate the account, logon type, source, and surrounding activity.

### Privileged logon

An event 4672 is a signal that special privileges were assigned to a new logon. It can be normal for administrators and services. The rule intentionally has no forced ATT&CK mapping.

### Suspicious process command

Security 4688 or Sysmon 1 records are compared with configured strings for encoded PowerShell and known scripting/download markers. This is a narrow heuristic and can produce false positives. Event layout determines whether command-line data is available.

### Account/group changes

Events 4720, 4722, 4728, and 4732 are surfaced for analyst review. Account creation maps to T1136; local/domain group membership change maps to T1098.007. Account enablement by itself receives no forced technique mapping.

### High-volume Sysmon network signal

Fifty or more Sysmon 3 events for the same account or source IP in 60 seconds. It is a low-severity volume signal, not proof of command-and-control. Tune the JSON threshold to the host's expected workload.

### Ordered event chains

Rules with the `event_correlation` detector specify two or more ordered `conditions.stages`, a `window_seconds`, and explicit `correlation_fields` (`account_sid`, username, source IP, computer, or process). A record in each stage must occur in order, within the total window, and share the same configured non-empty key. Current examples cover successful-to-privileged logon, process-to-network activity, account-creation-to-group-addition, and failed-logon-to-lockout. The group-addition rule uses the added member SID, not the administrator who performed the change; a simple `CN=` member name is retained for display, while `-` or ambiguous escaped names are left unmatched. Missing identities are not inferred from host context. A chain only generates a signal and does not assert that the sequence is malicious.

## False positives and confidence

The first release has no organization-specific baselines, allowlists, reputation checks, or threat intelligence. Review source telemetry before escalating a signal. ATT&CK mapping means the analytic is associated with a behavior category; it is not attribution and does not prove that an adversary performed the behavior.
