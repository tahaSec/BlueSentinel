"""Helpers for removing common secret-shaped values before storage or export."""

import re
from typing import Any


_SECRET_KEY = re.compile(r"(?i)(password|passwd|pwd|token|access_token|client_secret|api_key|authorization)")
_SECRET_VALUE = re.compile(
    r"(?i)(password|passwd|pwd|token|access[_-]?token|client[_-]?secret|api[_-]?key)"
    r"(\s*(?:=|:)\s*|\s+)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_AUTHORIZATION_VALUE = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(?:(?:bearer|basic)\s+)?[^\s,;&]+"
)


def redact_sensitive(value: Any) -> Any:
    """Redact values in secret-named fields and common command-line patterns."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if isinstance(key, str) and _SECRET_KEY.search(key):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_sensitive(item)
        return result
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)
    if isinstance(value, str):
        value = _AUTHORIZATION_VALUE.sub(lambda match: match.group(1) + "[REDACTED]", value)
        return _SECRET_VALUE.sub(
            lambda match: match.group(1) + match.group(2) + "[REDACTED]", value
        )
    return value
