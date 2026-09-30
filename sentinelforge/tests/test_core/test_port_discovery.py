import socket
from unittest.mock import patch

import pytest

from sentinelforge.core.port_discovery import (
    COMMON_TCP_PORTS,
    PortDiscovery,
    PortDiscoveryConfig,
    PortObservation,
    PortSelector,
)


def test_explicit_ports_are_sorted_and_deduplicated():
    config = PortDiscoveryConfig(
        mode="explicit",
        ports=(443, 22, 443, 80),
    )
    assert PortSelector.select(config) == [22, 80, 443]


def test_common_ports_are_sorted_and_unique():
    config = PortDiscoveryConfig(mode="common")
    ports = PortSelector.select(config)

    assert ports == sorted(set(COMMON_TCP_PORTS))
    assert all(1 <= port <= 65535 for port in ports)


def test_top_mode_requires_top_value():
    config = PortDiscoveryConfig(mode="top", top=3)
    ports = PortSelector.select(config)

    assert len(ports) == 3
    assert ports == sorted(set(COMMON_TCP_PORTS))[:3]


def test_range_mode_expands_ranges():
    config = PortDiscoveryConfig(
        mode="range",
        ranges=((80, 82), (443, 443)),
    )
    assert PortSelector.select(config) == [80, 81, 82, 443]


def test_all_mode_selects_entire_tcp_port_space():
    config = PortDiscoveryConfig(mode="all")
    ports = PortSelector.select(config)

    assert len(ports) == 65535
    assert ports[0] == 1
    assert ports[-1] == 65535


def test_invalid_port_rejected():
    with pytest.raises(ValueError):
        PortDiscoveryConfig(mode="explicit", ports=(0,))


def test_invalid_port_above_max_rejected():
    with pytest.raises(ValueError):
        PortDiscoveryConfig(mode="explicit", ports=(65536,))


def test_invalid_range_rejected():
    with pytest.raises(ValueError):
        PortDiscoveryConfig(mode="range", ranges=((100, 50),))


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        PortDiscoveryConfig(mode="invalid")


def test_invalid_worker_count_rejected():
    with pytest.raises(ValueError):
        PortDiscoveryConfig(max_workers=0)


def test_invalid_timeout_rejected():
    with pytest.raises(ValueError):
        PortDiscoveryConfig(timeout=0.01)


def test_normalize_addresses_deduplicates_ipv4_and_ipv6():
    discovery = PortDiscovery(PortDiscoveryConfig(mode="explicit", ports=(80,)))

    addresses = discovery._normalize_addresses(
        [
            "192.168.1.10",
            "192.168.1.10",
            "::1",
            "2001:db8::1",
        ]
    )

    assert addresses == [
        "192.168.1.10",
        "::1",
        "2001:db8::1",
    ]


def test_probe_connection_refused_is_closed():
    config = PortDiscoveryConfig(
        mode="explicit",
        ports=(80,),
        timeout=1,
    )
    discovery = PortDiscovery(config)

    with patch("socket.socket.connect", side_effect=ConnectionRefusedError()):
        observation = discovery._probe("example.com", "127.0.0.1", 80, config.timeout)

    assert isinstance(observation, PortObservation)
    assert observation.address == "127.0.0.1"
    assert observation.address_family == "ipv4"
    assert observation.port == 80
    assert observation.transport == "tcp"
    assert observation.state == "closed"
    assert observation.error == "connection_refused"
    assert observation.latency_ms >= 0
    assert observation.timestamp


def test_probe_timeout_is_timeout():
    config = PortDiscoveryConfig(
        mode="explicit",
        ports=(443,),
        timeout=1,
    )
    discovery = PortDiscovery(config)

    with patch("socket.socket.connect", side_effect=socket.timeout()):
        observation = discovery._probe("example.com", "127.0.0.1", 443, config.timeout)

    assert observation.state == "timeout"
    assert observation.error == "timeout"


def test_probe_ipv6_uses_ipv6_family():
    config = PortDiscoveryConfig(
        mode="explicit",
        ports=(443,),
        timeout=1,
    )
    discovery = PortDiscovery(config)

    with patch("socket.socket.connect", return_value=None) as connect:
        observation = discovery._probe("example.com", "::1", 443, config.timeout)

    assert observation.address_family == "ipv6"
    assert observation.state == "open"
    assert connect.call_args.args[0] == ("::1", 443, 0, 0)


def test_discover_probes_all_addresses():
    config = PortDiscoveryConfig(
        mode="explicit",
        ports=(80, 443),
        max_workers=4,
    )
    discovery = PortDiscovery(config)

    with patch.object(
        discovery,
        "_probe",
        side_effect=lambda target, address, port, timeout: PortObservation(
            target=target,
            address=address,
            address_family="IPv6" if ":" in address else "IPv4",
            port=port,
            transport="tcp",
            state="open",
            latency_ms=1.0,
            timestamp="2026-01-01T00:00:00+00:00",
        ),
    ) as probe:
        result = discovery.discover(
            "example.com",
            ["192.168.1.10", "::1"],
        )

    assert probe.call_count == 4
    assert result.ports_scanned == 4
    assert result.open_count == 4
    assert result.closed_count == 0
    assert result.timeout_count == 0
    assert result.error_count == 0
    assert result.open_ports == (80, 443)
    assert result.elapsed >= 0


def test_discover_deduplicates_addresses():
    config = PortDiscoveryConfig(
        mode="explicit",
        ports=(80,),
    )
    discovery = PortDiscovery(config)

    with patch.object(
        discovery,
        "_probe",
        return_value=PortObservation(
            target="example.com",
            address="127.0.0.1",
            address_family="ipv4",
            port=80,
            transport="tcp",
            state="closed",
            latency_ms=1.0,
            timestamp="2026-01-01T00:00:00+00:00",
            error="connection_refused",
        ),
    ) as probe:
        result = discovery.discover(
            "example.com",
            ["127.0.0.1", "127.0.0.1"],
        )

    assert probe.call_count == 1
    assert result.ports_scanned == 1
    assert result.closed_count == 1


def test_observation_contains_required_fields():
    observation = PortObservation(
        target="example.com",
        address="127.0.0.1",
        address_family="ipv4",
        port=443,
        transport="tcp",
        state="open",
        latency_ms=12.5,
        timestamp="2026-01-01T00:00:00+00:00",
    )

    assert observation.target == "example.com"
    assert observation.address == "127.0.0.1"
    assert observation.address_family == "ipv4"
    assert observation.port == 443
    assert observation.transport == "tcp"
    assert observation.state == "open"
    assert observation.latency_ms == 12.5
    assert observation.error is None

def test_discovery_bounds_in_flight_probes():
    import threading
    import time

    active = 0
    max_active = 0
    lock = threading.Lock()

    class BoundedDiscovery(PortDiscovery):
        def _probe(self, target, address, port, timeout):
            nonlocal active, max_active

            with lock:
                active += 1
                max_active = max(max_active, active)

            time.sleep(0.002)

            with lock:
                active -= 1

            return PortObservation(
                target=target,
                address=address,
                address_family="ipv4",
                port=port,
                transport="tcp",
                state="closed",
                latency_ms=0.0,
                timestamp="2026-01-01T00:00:00+00:00",
                error=None,
            )

    config = PortDiscoveryConfig(
        mode="range",
        ranges=((1, 100),),
        max_workers=8,
        timeout=1,
    )

    result = BoundedDiscovery(config).discover(
        "127.0.0.1",
        ["127.0.0.1"],
    )

    assert result.ports_scanned == 100
    assert len(result.observations) == 100
    assert max_active <= config.max_workers
