from __future__ import annotations

import re
from typing import Any


_SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)\b("
    r"authorization|bearer|cookie|jwt|token|secret|password|"
    r"credential|proxy|cdp|sql|shell|path|file"
    r")\b(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_PATTERN = re.compile(
    r"(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]+)"
)
_WINDOWS_PATH_PATTERN = re.compile(
    r"(?i)\b[A-Z]:\\(?:[^\s,;]+)"
)
_UNIX_PATH_PATTERN = re.compile(r"(?<![A-Za-z0-9])/(?:[^\s,;]+)")


def redact_audit_value(value: Any) -> Any:
    """Redact values before append-only audit storage."""
    if isinstance(value, dict):
        return {
            str(key): (
                "[REDACTED]"
                if re.search(
                    r"(?i)(token|secret|cookie|jwt|password|"
                    r"credential|proxy|path|file|cdp|sql|shell)",
                    str(key),
                )
                else redact_audit_value(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_audit_value(item) for item in value]
    if not isinstance(value, str):
        return value
    text = _BEARER_PATTERN.sub(r"\1[REDACTED]", value)
    text = _SENSITIVE_VALUE_PATTERN.sub(r"\1\2[REDACTED]", text)
    text = _WINDOWS_PATH_PATTERN.sub("[REDACTED_PATH]", text)
    return _UNIX_PATH_PATTERN.sub("[REDACTED_PATH]", text)
