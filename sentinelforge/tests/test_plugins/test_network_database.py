"""Regression tests for conservative database protocol security findings."""

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.protocol_probe import ProtocolObservation
from sentinelforge.core.target import Target, TargetType
from sentinelforge.plugins.network.plugin import (
    NetworkPlugin,
    _mysql_security_findings,
)


def make_target():
    return Target(
        raw="192.0.2.10",
        kind=TargetType.IP,
        host="192.0.2.10",
    )


def make_observation(
    *,
    protocol="mysql",
    success=True,
    data=None,
    evidence=(),
):
    return ProtocolObservation(
        target="192.0.2.10",
        address="192.0.2.10",
        address_family="ipv4",
        port=3306,
        transport="tcp",
        protocol=protocol,
        success=success,
        identification_method="mysql_initial_handshake",
        confidence=0.98 if success else 0.0,
        timestamp="2026-01-01T00:00:00Z",
        data=data or {},
        evidence=tuple(evidence),
    )


def make_plugin():
    return NetworkPlugin(ConfigManager())


def test_mysql_helper_ignores_unsuccessful_observation():
    findings = _mysql_security_findings(
        make_plugin(),
        make_target(),
        make_observation(success=False),
    )
    assert findings == []


def test_mysql_helper_ignores_other_protocols():
    findings = _mysql_security_findings(
        make_plugin(),
        make_target(),
        make_observation(protocol="postgresql"),
    )
    assert findings == []


def test_normal_mysql_handshake_does_not_create_security_finding():
    observation = make_observation(
        data={
            "handshake_complete": True,
            "server_family": "mysql",
            "server_version": "8.0.36",
            "capabilities": ["protocol_41", "ssl", "secure_connection"],
            "authentication_plugin": "caching_sha2_password",
            "authentication_salt_length": 20,
        },
        evidence=("MySQL protocol-10 initial handshake parsed successfully",),
    )

    findings = _mysql_security_findings(
        make_plugin(),
        make_target(),
        observation,
    )

    assert findings == []


def test_mysql_helper_ignores_incomplete_handshake():
    observation = make_observation(
        data={
            "handshake_complete": False,
            "server_family": "mysql",
            "authentication_plugin": "mysql_native_password",
        }
    )

    findings = _mysql_security_findings(
        make_plugin(),
        make_target(),
        observation,
    )

    assert findings == []


def test_mysql_helper_ignores_unknown_authentication_plugin():
    observation = make_observation(
        data={
            "handshake_complete": True,
            "authentication_plugin": "unknown_plugin",
        }
    )

    findings = _mysql_security_findings(
        make_plugin(),
        make_target(),
        observation,
    )

    assert findings == []
