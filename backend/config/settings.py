"""Small JSON/environment configuration layer with safe defaults."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Settings:
    database_path: str = "bluesentinel.db"
    rules_directory: str = "rules"
    log_level: str = "INFO"
    max_events: int = 100
    max_records: int = 500


def load_settings(path: Optional[str] = None) -> Settings:
    """Load supported settings from optional JSON then environment overrides."""
    values = {}
    if path:
        loaded = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("configuration file must contain a JSON object")
        values.update(loaded)
    env_fields = {
        "database_path": "BLUESENTINEL_DATABASE",
        "rules_directory": "BLUESENTINEL_RULES",
        "log_level": "BLUESENTINEL_LOG_LEVEL",
        "max_events": "BLUESENTINEL_MAX_EVENTS",
        "max_records": "BLUESENTINEL_MAX_RECORDS",
    }
    for field, variable in env_fields.items():
        if variable in os.environ:
            values[field] = os.environ[variable]
    allowed = {"database_path", "rules_directory", "log_level", "max_events", "max_records"}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError("unknown settings: {}".format(", ".join(sorted(unknown))))
    for field in ("max_events", "max_records"):
        if field in values:
            values[field] = int(values[field])
            if values[field] < 0:
                raise ValueError("{} must be non-negative".format(field))
    if "log_level" in values:
        values["log_level"] = str(values["log_level"]).upper()
        if values["log_level"] not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("log_level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
    return Settings(**values)
