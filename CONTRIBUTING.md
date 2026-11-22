# Contributing to BlueSentinel

Thank you for helping improve this defensive project.

## Before opening a change

- Keep changes focused and compatible with Python 3.9.
- Do not add real user, host, IP, or Security Log data to fixtures. Use synthetic values and documentation-only IP ranges.
- Do not add code that changes audit policy, account rights, firewall, antivirus, or host security settings.
- Keep Windows APIs behind collector modules so unit tests can run with mocks on other systems.
- Add tests for behavior changes and update the relevant documentation.

## Development checks

```powershell
py -3.9 -m pip install -r requirements-dev.txt
py -3.9 -m pytest -q
py -3.9 -m backend.main rules validate
```

For CLI changes, add a test that uses a temporary SQLite database and synthetic input. Do not require real Security or Sysmon records in automated tests.

## Detection rule changes

Put rule configuration in `rules/*.json`. Include source scope, event IDs, conditions, severity, ATT&CK mapping only when supported by the signal, false-positive context, and recommended investigation steps. Detection alerts are leads for an analyst, not verdicts of compromise.

## Pull request notes

Describe the behavior, test command and actual result, Windows-specific manual checks, required permissions, and known limitations. Never include collected telemetry or secrets in a pull request.
