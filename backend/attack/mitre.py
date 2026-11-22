"""Small MITRE ATT&CK reference used by built-in detection rules."""

from typing import Dict, List


TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access, Persistence, Privilege Escalation, Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1136/",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "T1098.007": {
        "name": "Additional Local or Domain Groups",
        "tactic": "Persistence, Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1098/007/",
    },
}


def techniques_for_alert(alert) -> List[Dict[str, str]]:
    """Return known ATT&CK technique metadata attached to an alert."""
    return [
        {"id": technique_id, **TECHNIQUES[technique_id]}
        for technique_id in alert.attack_techniques
        if technique_id in TECHNIQUES
    ]
