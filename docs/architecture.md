# Architecture

BlueSentinel keeps platform APIs at the collection boundary. Normalization, rule evaluation, persistence, correlation, incident workflow, and reporting operate on Python models and can be tested without Windows.

## Data flow

1. A Windows Security, Sysmon, or JSON sample collector returns source records and bounded collection metadata.
2. The normalizer builds timezone-aware UTC `SecurityEvent` values, maps fields when their source layout is known, preserves remaining raw inserts, and redacts common secret-shaped values.
3. The SQLite event repository stores normalized fields and raw data. A stable hash prevents duplicate imports of the same event.
4. The JSON rule loader validates each definition. `DetectionEngine` runs the enabled detector implementation scoped to its configured sources.
5. Detections include the trigger window, evidence references, recommended actions, severity, and supported ATT&CK mappings.
6. The detection engine evaluates configured ordered event chains using explicit shared identity keys and time windows. The alert correlation engine groups nearby detections by shared account, IP, host, or process. Incident management links detections and source events, records notes, and maintains analyst-controlled status.
7. JSON, CSV, and Markdown exporters present event, detection, and incident context.

## Package responsibilities

- `collectors`: Windows APIs and offline JSON import.
- `normalization`: input validation, common fields, UTC conversion, secret-shaped value redaction.
- `models`: events, detections, correlation groups, and incidents.
- `detection`: JSON validation and detector dispatch.
- `correlation`: explainable grouping of time-adjacent detections; event-chain rules run in `detection`.
- `storage`: schema initialization, migrations, duplicate handling, and repository queries.
- `incidents`: lifecycle, evidence associations, and analyst notes.
- `reporting`: export formats and report summaries.
- `cli`: command parsing and use-case orchestration.

SQLite uses parameterized values, UTC ISO-8601 timestamps, foreign keys, indexes, and a versioned schema. The initial migration preserves existing `events` and `alerts` tables while adding richer fields and investigation tables.

## Trust boundaries and limitations

The event log insertion-string maps depend on provider event layouts. Unknown data is preserved as raw inserts for review, but mapped fields must be validated against the Windows/Sysmon version in the target lab. Rule output is analytic evidence, not an assertion of malicious intent. The local database is sensitive operational data and must be protected accordingly.

The Security collector maps target account SIDs, usernames, logon types, process paths, and network fields using the documented event templates for [4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624), [4625](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625), [4720](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4720), [4722](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4722), [4732](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732), [4740](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740), [4648](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648), and [4688](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688). A simple group-member `CN=` is retained as a display name; account-chain correlation uses the member SID. Escaped or ambiguous distinguished names remain unmapped. Version-specific templates still require validation against the actual host.
