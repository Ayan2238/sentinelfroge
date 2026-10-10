from sentinelforge.core.udp_discovery import (
    UdpDiscovery,
    UdpDiscoveryConfig,
    UdpObservation,
    UdpPortSelector,
)


def make_observation(target, address, port, state="responsive", probe="test"):
    return UdpObservation(
        target=target,
        address=address,
        address_family="ipv4",
        port=port,
        transport="udp",
        state=state,
        latency_ms=1.0,
        timestamp="2026-01-01T00:00:00+00:00",
        probe=probe,
        evidence=("test evidence",),
    )


def test_explicit_ports_are_sorted_and_deduplicated():
    config = UdpDiscoveryConfig(
        mode="explicit",
        ports=(53, 161, 53, 123),
    )

    assert UdpPortSelector.select(config) == [53, 123, 161]


def test_range_ports_are_expanded_and_deduplicated():
    config = UdpDiscoveryConfig(
        mode="range",
        ranges=((50, 52), (52, 54)),
    )

    assert UdpPortSelector.select(config) == [50, 51, 52, 53, 54]


def test_explicit_mode_requires_ports():
    try:
        UdpDiscoveryConfig(mode="explicit")
    except ValueError as exc:
        assert "requires at least one port" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_range_mode_requires_ranges():
    try:
        UdpDiscoveryConfig(mode="range")
    except ValueError as exc:
        assert "requires at least one range" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_invalid_configuration_is_rejected():
    for kwargs in (
        {"mode": "common", "ports": (53,)},
        {"mode": "explicit", "ports": (0,)},
        {"mode": "explicit", "ports": (65536,)},
        {"mode": "range", "ranges": ((100, 99),)},
        {"mode": "explicit", "ports": (53,), "max_workers": 0},
        {"mode": "explicit", "ports": (53,), "max_workers": 1025},
        {"mode": "explicit", "ports": (53,), "timeout": 0.01},
        {"mode": "explicit", "ports": (53,), "timeout": 3601},
    ):
        try:
            UdpDiscoveryConfig(**kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {kwargs!r}")


def test_normalize_addresses_deduplicates_ipv4_and_ipv6():
    addresses = UdpDiscovery._normalize_addresses(
        ["127.0.0.1", "127.0.0.1", "::1", "::1"]
    )

    assert addresses == ["127.0.0.1", "::1"]


def test_invalid_address_is_rejected():
    try:
        UdpDiscovery._normalize_addresses(["not-an-ip"])
    except ValueError as exc:
        assert "invalid IP address" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_discovery_runs_every_address_port_pair():
    config = UdpDiscoveryConfig(
        mode="explicit",
        ports=(53, 123),
        max_workers=2,
    )
    discovery = UdpDiscovery(config)

    calls = []

    def probe(target, address, port, timeout):
        calls.append((target, address, port, timeout))
        return make_observation(target, address, port)

    result = discovery.discover(
        "example.test",
        ["127.0.0.1", "127.0.0.2"],
        probe,
    )

    assert len(calls) == 4
    assert result.ports_scanned == 4
    assert result.responsive_count == 4
    assert result.responsive_ports == (53, 123)


def test_discovery_counts_states():
    config = UdpDiscoveryConfig(
        mode="explicit",
        ports=(53, 123, 161, 999),
        max_workers=4,
    )
    discovery = UdpDiscovery(config)

    states = {
        53: "responsive",
        123: "closed",
        161: "no_response",
        999: "error",
    }

    def probe(target, address, port, timeout):
        return make_observation(
            target,
            address,
            port,
            state=states[port],
        )

    result = discovery.discover(
        "example.test",
        ["127.0.0.1"],
        probe,
    )

    assert result.responsive_count == 1
    assert result.closed_count == 1
    assert result.no_response_count == 1
    assert result.error_count == 1
    assert result.responsive_ports == (53,)


def test_probe_exception_becomes_structured_error():
    config = UdpDiscoveryConfig(
        mode="explicit",
        ports=(53,),
    )
    discovery = UdpDiscovery(config)

    def probe(target, address, port, timeout):
        raise TimeoutError("simulated timeout")

    result = discovery.discover(
        "example.test",
        ["127.0.0.1"],
        probe,
    )

    observation = result.observations[0]

    assert observation.state == "error"
    assert observation.transport == "udp"
    assert observation.port == 53
    assert "TimeoutError" in observation.error


def test_observation_has_required_fields():
    observation = make_observation(
        "example.test",
        "127.0.0.1",
        53,
    )

    assert observation.target == "example.test"
    assert observation.address == "127.0.0.1"
    assert observation.address_family == "ipv4"
    assert observation.port == 53
    assert observation.transport == "udp"
    assert observation.state == "responsive"
    assert observation.probe == "test"
    assert observation.evidence == ("test evidence",)
