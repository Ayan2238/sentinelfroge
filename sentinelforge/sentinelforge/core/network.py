"""Small shared helpers for network configuration."""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinelforge.core.config import ConfigManager


def ssl_context(config: "ConfigManager") -> ssl.SSLContext:
    """Create a context honoring the configured TLS verification policy.

    Verification is enabled by default.  Disabling it is an explicit,
    per-request configuration choice for assessment targets using private or
    self-signed certificates.
    """
    if config.get("network.verify_ssl", True):
        return ssl.create_default_context()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context