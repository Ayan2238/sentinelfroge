"""Small, conservative redaction helpers for user-visible output."""

from __future__ import annotations

import re
from typing import Any

_SECRET_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:password|passwd|pass|api[_-]?key|secret|token)\b\s*[:=]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:authorization|cookie|set-cookie)\b\s*:\s*)[^;\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(https?://[^/\s:@]+:)[^@\s]+(@)"), r"\1[REDACTED]\2"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
)
_SENSITIVE_KEYS = re.compile(
    r"(?i)(?:password|passwd|api[_-]?key|secret|token|authorization|cookie|credential)"
)


def redact_text(value: str) -> str:
    """Redact common credential forms while preserving surrounding context."""
    for pattern, replacement in _SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def redact_value(value: Any) -> Any:
    """Recursively redact strings in serializable mappings and sequences."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SENSITIVE_KEYS.search(str(key)) and item is not None
            else redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value