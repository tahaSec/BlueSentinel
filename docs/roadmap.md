# Roadmap

## Current implementation

- Local Security and optional Sysmon collectors with bounded scans.
- Normalized, UTC event model and JSON import for synthetic/offline testing.
- JSON-configured detection rules for authentication, privileged logon, process, account/group, and network-volume signals.
- Same-account alert grouping, SQLite event/detection/incident storage, analyst statuses and notes.
- JSON, CSV, and Markdown reports.
- ATT&CK references for supported analytic signals.

## Future work

- Parse Windows event XML by named data fields rather than relying primarily on insertion order.
- Sigma-inspired rule compatibility and stronger per-rule schema/versioning.
- Broader multi-stage correlation patterns and timeline queries beyond the currently configured event chains.
- Baselines and host-specific tuning for network and process activity.
- Additional test coverage on supported Windows versions with synthetic event channels.
- Retention controls, database backup, and access-control guidance.
- Optional scheduled collection, multi-host ingestion, threat-intelligence enrichment, REST API, and dashboard after core reliability work.

No roadmap item should be presented as implemented until it has code, tests, and documentation.
