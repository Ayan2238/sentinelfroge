"""Tests for TargetManager."""
from __future__ import annotations

import pytest

from sentinelforge.core.target import Target, TargetError, TargetManager, TargetType


@pytest.fixture
def mgr() -> TargetManager:
    return TargetManager(resolve=False)  # no DNS lookups in unit tests


class TestTargetParsing:
    def test_domain(self, mgr: TargetManager) -> None:
        t = mgr.add("example.com")
        assert t.kind == TargetType.DOMAIN
        assert t.host == "example.com"

    def test_subdomain(self, mgr: TargetManager) -> None:
        t = mgr.add("api.example.com")
        assert t.kind == TargetType.DOMAIN
        assert t.host == "api.example.com"

    def test_https_url(self, mgr: TargetManager) -> None:
        t = mgr.add("https://example.com/app")
        assert t.kind == TargetType.URL
        assert t.host == "example.com"
        assert t.scheme == "https"
        assert t.port is None

    def test_http_url_with_port(self, mgr: TargetManager) -> None:
        t = mgr.add("http://example.com:8080/api")
        assert t.kind == TargetType.URL
        assert t.port == 8080
        assert t.scheme == "http"

    def test_ipv4_address(self, mgr: TargetManager) -> None:
        t = mgr.add("192.168.1.1")
        assert t.kind == TargetType.IP
        assert t.host == "192.168.1.1"
        assert t.resolved_ips == ["192.168.1.1"]

    def test_ipv6_address(self, mgr: TargetManager) -> None:
        t = mgr.add("::1")
        assert t.kind == TargetType.IP
        assert "::1" in t.host

    def test_cidr_range(self, mgr: TargetManager) -> None:
        t = mgr.add("10.0.0.0/24")
        assert t.kind == TargetType.CIDR

    def test_wildcard_domain(self, mgr: TargetManager) -> None:
        t = mgr.add("*.example.com")
        assert t.kind == TargetType.WILDCARD
        assert t.host == "example.com"

    def test_invalid_target_raises(self, mgr: TargetManager) -> None:
        with pytest.raises(TargetError):
            mgr.add("not a valid target!!!")

    def test_empty_string_raises(self, mgr: TargetManager) -> None:
        with pytest.raises(TargetError):
            mgr.add("   ")


class TestTargetProperties:
    def test_base_url_domain(self, mgr: TargetManager) -> None:
        t = mgr.add("example.com")
        assert t.base_url == "https://example.com"

    def test_base_url_https_url(self, mgr: TargetManager) -> None:
        t = mgr.add("https://example.com")
        assert t.base_url == "https://example.com"

    def test_base_url_with_port(self, mgr: TargetManager) -> None:
        t = mgr.add("https://example.com:8443")
        assert "8443" in t.base_url

    def test_str_representation(self, mgr: TargetManager) -> None:
        t = mgr.add("example.com")
        assert str(t) == "example.com"

    def test_display(self, mgr: TargetManager) -> None:
        t = mgr.add("example.com")
        assert t.display == "example.com"


class TestTargetManager:
    def test_len_after_adds(self, mgr: TargetManager) -> None:
        mgr.add("example.com")
        mgr.add("192.168.1.1")
        assert len(mgr) == 2

    def test_iterate_targets(self, mgr: TargetManager) -> None:
        mgr.add("example.com")
        mgr.add("test.org")
        names = [t.host for t in mgr]
        assert "example.com" in names
        assert "test.org" in names

    def test_add_many_success(self, mgr: TargetManager) -> None:
        targets = mgr.add_many(["example.com", "192.168.1.1"])
        assert len(targets) == 2

    def test_add_many_with_invalid_raises(self, mgr: TargetManager) -> None:
        with pytest.raises(TargetError, match="failed validation"):
            mgr.add_many(["example.com", "!!!invalid!!!"])

    def test_targets_property(self, mgr: TargetManager) -> None:
        mgr.add("example.com")
        result = mgr.targets
        assert len(result) == 1
        assert isinstance(result[0], Target)
