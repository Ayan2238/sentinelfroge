from sentinelforge.core.port_discovery import PortObservation
from sentinelforge.core.service_identifier import (
    ServiceIdentifier,
    ServiceObservation,
)


def make_observation(
    port: int,
    *,
    state: str = "open",
    address: str = "127.0.0.1",
    family: str = "IPv4",
    transport: str = "tcp",
) -> PortObservation:
    return PortObservation(
        target="example.test",
        address=address,
        address_family=family,
        port=port,
        transport=transport,
        state=state,
        latency_ms=1.0,
        timestamp="2026-01-01T00:00:00+00:00",
        error=None,
    )


def test_identifies_common_service_as_port_hint():
    result = ServiceIdentifier().identify([make_observation(22)])

    assert len(result) == 1
    service = result[0]

    assert isinstance(service, ServiceObservation)
    assert service.service == "SSH"
    assert service.protocol == "ssh"
    assert service.identification_method == "port_hint"
    assert service.confidence == 0.50
    assert service.transport == "tcp"
    assert "port 22" in service.evidence[0]


def test_unknown_port_is_not_assumed_to_be_a_service():
    result = ServiceIdentifier().identify([make_observation(49152)])

    assert len(result) == 1
    service = result[0]

    assert service.service == "unknown"
    assert service.protocol == "unknown"
    assert service.identification_method == "unknown"
    assert service.confidence == 0.10


def test_closed_ports_are_not_identified():
    result = ServiceIdentifier().identify(
        [
            make_observation(22, state="closed"),
            make_observation(80, state="timeout"),
            make_observation(443, state="error"),
        ]
    )

    assert result == ()


def test_preserves_ipv4_and_transport_metadata():
    result = ServiceIdentifier().identify([make_observation(443)])

    service = result[0]

    assert service.address == "127.0.0.1"
    assert service.address_family == "IPv4"
    assert service.transport == "tcp"
    assert service.port == 443


def test_preserves_ipv6_metadata():
    result = ServiceIdentifier().identify(
        [
            make_observation(
                22,
                address="::1",
                family="IPv6",
            )
        ]
    )

    service = result[0]

    assert service.address == "::1"
    assert service.address_family == "IPv6"
    assert service.service == "SSH"


def test_multiple_services_are_sorted_deterministically():
    result = ServiceIdentifier().identify(
        [
            make_observation(443, address="10.0.0.2"),
            make_observation(22, address="10.0.0.1"),
            make_observation(80, address="10.0.0.1"),
        ]
    )

    assert [
        (item.address, item.port)
        for item in result
    ] == [
        ("10.0.0.1", 22),
        ("10.0.0.1", 80),
        ("10.0.0.2", 443),
    ]


def test_identification_does_not_modify_input_observations():
    observations = [
        make_observation(22),
        make_observation(3306),
    ]

    original = tuple(observations)

    ServiceIdentifier().identify(observations)

    assert tuple(observations) == original
