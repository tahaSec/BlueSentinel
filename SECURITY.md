# Security Policy

## Supported versions

Security fixes target the current default branch. There is no formal release support policy yet.

## Reporting a vulnerability

Do not publish real event records, credentials, or exploit details in a public issue. Use GitHub's private vulnerability reporting for the repository when it is enabled. Otherwise contact the repository maintainer privately before public disclosure.

## Scope and safe use

BlueSentinel is a defensive, local event collection and investigation project. It does not automatically remediate hosts or change Windows security settings. Test only with synthetic events, your own system, or an expressly authorized lab. Treat SQLite databases and generated reports as sensitive because they can contain account, host, network, and process telemetry.

Secret redaction is best-effort and is not a substitute for access controls or review before sharing reports.
