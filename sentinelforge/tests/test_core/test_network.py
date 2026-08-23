"""Regression tests for the configured TLS verification policy."""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.network import open_url, ssl_context


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


def test_open_url_retries_transient_failures(monkeypatch) -> None:
    calls = {"count": 0}

    class Response:
        status = 200
        def close(self):
            pass

    def fake_open(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] < 3:
            raise urllib.error.URLError("temporary failure")
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    monkeypatch.setattr("sentinelforge.core.network.time.sleep", lambda _: None)
    config = ConfigManager()
    config.set("general.retries", 2)
    with open_url("https://example.com", config):
        pass
    assert calls["count"] == 3


def test_open_url_does_not_retry_non_idempotent_request(monkeypatch) -> None:
    calls = {"count": 0}

    def fake_open(*args, **kwargs):
        calls["count"] += 1
        raise urllib.error.URLError("temporary failure")

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    config = ConfigManager()
    config.set("general.retries", 3)
    request = urllib.request.Request("https://example.com", method="POST")
    with pytest.raises(urllib.error.URLError):
        with open_url(request, config, retryable=False):
            pass
    assert calls["count"] == 1