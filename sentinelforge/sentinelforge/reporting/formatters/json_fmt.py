"""JSON Report Formatter."""
from __future__ import annotations
import json
from typing import Any


def render(data: dict[str, Any]) -> tuple[str, str]:
    """Return (json_string, 'json')."""
    return json.dumps(data, indent=2, default=str), "json"
