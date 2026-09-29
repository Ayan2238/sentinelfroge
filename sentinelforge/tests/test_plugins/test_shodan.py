from __future__ import annotations

import json
import urllib.error

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.target import Target, TargetType
from sentinelforge.plugins.shodan.plugin import ShodanPlugin


def make_target() -> Target:
    return Target("8.8.8.8", TargetType.IP, "8.8.8.8")


def make_plugin() -> ShodanPlugin:
    config = ConfigManager()
    config.set("integrations.shodan.enabled", True)
    config.set("integrations.shodan.api_key", "test-key")
    plugin = ShodanPlugin(config)
    plugin.initialize()
    return plugin


def fake_response(payload: dict):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, *_args):
            return json.dumps(payload).encode()

    return Response()


def test_shodan_successful_host_enrichment(monkeypatch) -> None:
    responses = [
        {
            "plan": "oss",
            "query_credits": 0,
            "scan_credits": 0,
        },
        {
            "ip_str": "8.8.8.8",
            "ports": [53, 443],
            "hostnames": ["dns.google"],
            "domains": ["google.com"],
            "os": "Linux",
            "org": "Google",
            "isp": "Google",
            "asn": "AS15169",
            "vulns": [],
        },
    ]

    def fake_open(*_args, **_kwargs):
        return fake_response(responses.pop(0))

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_open,
    )

    result = make_plugin().execute(make_target())

    assert result.status == "success"
    assert result.error is None
    assert result.metadata["plan"] == "oss"
    assert result.metadata["query_credits"] == 0
    assert result.metadata["capabilities"]["host_lookup"] is True
    assert result.metadata["capabilities"]["host_count"] is False
    assert result.metadata["capabilities"]["search"] is False
    assert result.metadata["capabilities"]["on_demand_scan"] is False
    assert len(result.findings) == 2


def test_shodan_host_not_found_is_partial(monkeypatch) -> None:
    calls = {"count": 0}

    def fake_open(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return fake_response(
                {
                    "plan": "oss",
                    "query_credits": 0,
                    "scan_credits": 0,
                }
            )
        raise urllib.error.HTTPError(
            "https://api.shodan.io/shodan/host/8.8.8.8",
            404,
            "Not Found",
            {},
            None,
        )

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_open,
    )

    result = make_plugin().execute(make_target())

    assert result.status == "partial"
    assert result.error is None
    assert result.metadata["reason"] == "Shodan has no host data for this target."


def test_shodan_access_denied_is_unavailable(monkeypatch) -> None:
    def fake_open(*_args, **_kwargs):
        raise urllib.error.HTTPError(
            "https://api.shodan.io/api-info",
            403,
            "Forbidden",
            {},
            None,
        )

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_open,
    )

    result = make_plugin().execute(make_target())

    assert result.status == "unavailable"
    assert result.error is None


def test_shodan_payment_required_is_unavailable(monkeypatch) -> None:
    calls = {"count": 0}

    def fake_open(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return fake_response(
                {
                    "plan": "oss",
                    "query_credits": 0,
                    "scan_credits": 0,
                }
            )
        raise urllib.error.HTTPError(
            "https://api.shodan.io/shodan/host/8.8.8.8",
            402,
            "Payment Required",
            {},
            None,
        )

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_open,
    )

    result = make_plugin().execute(make_target())

    assert result.status == "unavailable"
    assert result.error is None


def test_shodan_network_failure_is_failed(monkeypatch) -> None:
    def fake_open(*_args, **_kwargs):
        raise urllib.error.URLError("temporary failure")

    monkeypatch.setattr(
        "urllib.request.urlopen",
        fake_open,
    )

    result = make_plugin().execute(make_target())

    assert result.status == "failed"
    assert result.error is not None
    assert "URLError" in result.error
