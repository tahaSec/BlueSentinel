# Installation and first run

## Requirements

- Python 3.9 or newer.
- Windows 10 or Windows 11 for live Security/Sysmon collection.
- `pywin32` on Windows. It is conditionally declared in `requirements.txt`.
- `pytest` for development tests, declared in `requirements-dev.txt`.

## Install

```powershell
py -3.9 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

For a non-Windows system used only for sample input, install `requirements-dev.txt`; pywin32 is excluded by its environment marker.

## Offline smoke workflow

```powershell
py -3.9 -m backend.main rules validate
py -3.9 -m backend.main --db .\demo.db collect --input .\sample_data\failed_logons.json
py -3.9 -m backend.main --db .\demo.db detect --output .\reports\demo.json
py -3.9 -m backend.main --db .\demo.db incidents list
```

The sample data is synthetic. It should produce five imported events, one brute-force signal, and one new incident.

For cross-source and sequence detections, import both synthetic fixtures before running detection:

```powershell
py -3.9 -m backend.main --db .\mixed-demo.db collect --input .\sample_data\events\mixed_windows_events.json
py -3.9 -m backend.main --db .\mixed-demo.db collect --input .\sample_data\events\sysmon_events.json
py -3.9 -m backend.main --db .\mixed-demo.db detect --output .\reports\mixed-demo.json
```

The integration test `test_mixed_security_and_sysmon_sample_runs_end_to_end` verifies that this same synthetic dataset produces detections and linked incidents without Windows APIs.

## Windows permissions

The Security collector requests `SeSecurityPrivilege` in its own process token because access to the Security channel may require it. The right must already be assigned to the running account; Administrator membership alone does not guarantee that. BlueSentinel reports missing rights and does not grant them. Ask the system administrator to assess any required manual policy change. Sysmon is optional and is read only when its Operational channel exists and is accessible.

No installer or elevated setup step is provided. Collection reads event records and does not change machine policy.
