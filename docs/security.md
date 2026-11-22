# Security considerations

## Permissions

Security Event Log access may require `SeSecurityPrivilege`. BlueSentinel requests it in the current process token, checks for `ERROR_NOT_ALL_ASSIGNED`, and reports failure. It does not change user rights, audit policy, registry values, firewall, antivirus, or account state. Sysmon is optional and is not installed or configured by this application.

## Telemetry handling

Events and reports may contain usernames, domains, account SIDs, hostnames, IP addresses, process paths, and command lines. SQLite and report outputs are local files; store them with appropriate Windows ACLs and remove them according to your own retention policy. Git ignores generated database and report files by default.

The normalizer redacts common password, token, API-key, and authorization patterns before storing imported event fields. This is best-effort pattern matching, not a guarantee. Do not submit real Security Log samples to public issues or commits. Review any report before sharing.

## Operational behavior

Collection is read-only and bounded by `max_events`, `max_records`, and optional `since`. Read and privilege errors are surfaced. Malformed individual records are skipped with a warning that includes the error type but not event content. Logs record operational outcomes and avoid raw event payloads.

Detections and correlation groups are leads for human investigation. No process termination, account disabling, remediation, persistence, credential capture, or remote access is implemented.

## Reporting a concern

Use the private reporting route in [SECURITY.md](../SECURITY.md). Avoid publishing sensitive telemetry.
