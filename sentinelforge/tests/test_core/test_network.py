"""Regression tests for the configured TLS verification policy."""
from __future__ import annotations

import ssl

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.network import ssl_context


def test_tls_verification_is_enabled_by_default() -> None:
    context = ssl_context(ConfigManager())
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_tls_verification_can_be_explicitly_disabled(tmp_path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("network:\n  verify_ssl: false\n")
    context = ssl_context(ConfigManager(config_path=config))
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False