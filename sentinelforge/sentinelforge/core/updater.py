"""SentinelForge self-update check.

Compares the installed version against the latest on PyPI and
reports whether an upgrade is available. The check is strictly
read-only — it never installs anything without explicit user action.
"""
from __future__ import annotations

import json
import logging
import urllib.request
from typing import Optional

from sentinelforge import __version__

logger = logging.getLogger(__name__)

PYPI_URL = "https://pypi.org/pypi/sentinelforge/json"
_REQUEST_TIMEOUT = 10  # seconds


def _parse_version(v: str) -> tuple[int, ...]:
    """Convert a dotted-version string into a tuple of ints for comparison."""
    try:
        return tuple(int(x) for x in v.split(".") if x.isdigit())
    except ValueError:
        return (0,)


def fetch_latest_version(timeout: int = _REQUEST_TIMEOUT) -> Optional[str]:
    """Return the latest SentinelForge version string from PyPI, or None on failure."""
    try:
        with urllib.request.urlopen(PYPI_URL, timeout=timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
            return data["info"]["version"]
    except Exception:
        logger.debug("Update check failed")
        return None


def check_for_update(timeout: int = _REQUEST_TIMEOUT) -> dict:
    """Check PyPI for a newer version of SentinelForge.

    Returns a dict with keys:
        current_version  str
        latest_version   str | None
        update_available bool
        up_to_date       bool
        error            str | None
    """
    current = __version__
    latest = fetch_latest_version(timeout=timeout)

    if latest is None:
        return {
            "current_version": current,
            "latest_version": None,
            "update_available": False,
            "up_to_date": True,
            "error": "Could not reach PyPI",
        }

    update_available = _parse_version(latest) > _parse_version(current)
    return {
        "current_version": current,
        "latest_version": latest,
        "update_available": update_available,
        "up_to_date": not update_available,
        "error": None,
    }


def upgrade_command() -> str:
    """Return the pip command the user should run to upgrade."""
    return "pip install --upgrade sentinelforge"
