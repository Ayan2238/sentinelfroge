"""UDP discovery primitives for SentinelForge.

This module provides bounded, protocol-aware UDP discovery.
Unlike TCP, UDP connectivity cannot be established by a generic connect
operation, so probes must provide protocol-level evidence of responsiveness.

The discovery engine itself does not implement a specific protocol. Protocol
strategies are supplied by the caller, allowing DNS and future UDP protocols
to share the same bounded discovery infrastructure.
"""

from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable


UDP_PORT_MODES = {"explicit", "range"}


@dataclass(frozen=True)
class UdpDiscoveryConfig:
    """Normalized configuration for protocol-aware UDP discovery."""

    mode: str = "explicit"
    ports: tuple[int, ...] = ()
    ranges: tuple[tuple[int, int], ...] = ()
    max_workers: int = 32
    timeout: float = 2.0

    def __post_init__(self) -> None:
        if self.mode not in UDP_PORT_MODES:
            raise ValueError(
                f"invalid UDP discovery mode: {self.mode!r}; "
                f"expected one of {sorted(UDP_PORT_MODES)}"
            )

        for port in self.ports:
            _validate_port(port)

        for start, end in self.ranges:
            _validate_range(start, end)

        if self.mode == "explicit" and not self.ports:
            raise ValueError("explicit UDP mode requires at least one port")

        if self.mode == "range" and not self.ranges:
            raise ValueError("range UDP mode requires at least one range")

        if not 1 <= self.max_workers <= 1024:
            raise ValueError("max_workers must be between 1 and 1024")

        if not 0.1 <= self.timeout <= 3600:
            raise ValueError("timeout must be between 0.1 and 3600 seconds")


@dataclass(frozen=True)
class UdpObservation:
    """Structured result produced by one protocol-aware UDP probe."""

    target: str
    address: str
    address_family: str
    port: int
    transport: str
    state: str
    latency_ms: float | None
    timestamp: str
    probe: str
    evidence: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class UdpDiscoveryResult:
    """Aggregate result of a UDP discovery operation."""

    observations: tuple[UdpObservation, ...]
    ports_scanned: int
    responsive_count: int
    closed_count: int
    no_response_count: int
    error_count: int
    elapsed: float

    @property
    def responsive_ports(self) -> tuple[int, ...]:
        """Return unique responsive UDP ports in deterministic order."""
        return tuple(
            sorted(
                {
                    observation.port
                    for observation in self.observations
                    if observation.state == "responsive"
                }
            )
        )


class UdpPortSelector:
    """Resolve UDP discovery configuration into a deterministic port list."""

    @staticmethod
    def select(config: UdpDiscoveryConfig) -> list[int]:
        if config.mode == "explicit":
            selected = list(config.ports)
        elif config.mode == "range":
            selected = []
            for start, end in config.ranges:
                selected.extend(range(start, end + 1))
        else:
            raise ValueError(f"unsupported UDP port mode: {config.mode!r}")

        return sorted(set(selected))


class UdpDiscovery:
    """Bounded protocol-aware UDP discovery engine."""

    def __init__(self, config: UdpDiscoveryConfig) -> None:
        self.config = config

    def discover(
        self,
        target: str,
        addresses: Iterable[str],
        probe: Callable[
            [str, str, int, float],
            UdpObservation,
        ],
    ) -> UdpDiscoveryResult:
        """Run a supplied UDP protocol probe against selected ports."""

        normalized_addresses = self._normalize_addresses(addresses)
        ports = UdpPortSelector.select(self.config)

        work_items = (
            (address, port)
            for address in normalized_addresses
            for port in ports
        )

        started = time.monotonic()
        observations: list[UdpObservation] = []

        with ThreadPoolExecutor(
            max_workers=self.config.max_workers
        ) as executor:
            in_flight = {}
            exhausted = False

            def submit_next() -> bool:
                nonlocal exhausted

                if exhausted:
                    return False

                try:
                    address, port = next(work_items)
                except StopIteration:
                    exhausted = True
                    return False

                future = executor.submit(
                    probe,
                    target,
                    address,
                    port,
                    self.config.timeout,
                )
                in_flight[future] = (address, port)
                return True

            for _ in range(self.config.max_workers):
                if not submit_next():
                    break

            while in_flight:
                done = next(iter(as_completed(in_flight)))

                try:
                    observation = done.result()
                except Exception as exc:
                    address, port = in_flight[done]
                    observation = self._probe_error(
                        target,
                        address,
                        port,
                        self.config.timeout,
                        exc,
                    )

                observations.append(observation)
                del in_flight[done]

                submit_next()

        observations.sort(
            key=lambda item: (
                item.address,
                item.port,
                item.probe,
            )
        )

        elapsed = time.monotonic() - started

        return UdpDiscoveryResult(
            observations=tuple(observations),
            ports_scanned=len(observations),
            responsive_count=sum(
                observation.state == "responsive"
                for observation in observations
            ),
            closed_count=sum(
                observation.state == "closed"
                for observation in observations
            ),
            no_response_count=sum(
                observation.state == "no_response"
                for observation in observations
            ),
            error_count=sum(
                observation.state == "error"
                for observation in observations
            ),
            elapsed=elapsed,
        )

    @staticmethod
    def _normalize_addresses(addresses: Iterable[str]) -> list[str]:
        normalized: set[str] = set()

        for address in addresses:
            value = str(address).strip()
            if not value:
                continue

            try:
                normalized.add(str(ipaddress.ip_address(value)))
            except ValueError as exc:
                raise ValueError(
                    f"invalid IP address for UDP discovery: {value!r}"
                ) from exc

        return sorted(
            normalized,
            key=lambda value: (
                ipaddress.ip_address(value).version,
                int(ipaddress.ip_address(value)),
            ),
        )

    @staticmethod
    def _probe_error(
        target: str,
        address: str,
        port: int,
        timeout: float,
        exc: Exception,
    ) -> UdpObservation:
        del timeout

        ip = ipaddress.ip_address(address)
        family_name = "ipv4" if ip.version == 4 else "ipv6"

        return UdpObservation(
            target=target,
            address=address,
            address_family=family_name,
            port=port,
            transport="udp",
            state="error",
            latency_ms=None,
            timestamp=datetime.now(timezone.utc).isoformat(),
            probe="unknown",
            evidence=(
                f"UDP probe failed before producing a protocol observation: "
                f"{type(exc).__name__}: {exc}",
            ),
            error=f"{type(exc).__name__}: {exc}",
        )


def _validate_port(port: int) -> None:
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError(f"port must be an integer: {port!r}")

    if not 1 <= port <= 65535:
        raise ValueError(f"port must be between 1 and 65535: {port!r}")


def _validate_range(start: int, end: int) -> None:
    _validate_port(start)
    _validate_port(end)

    if start > end:
        raise ValueError(
            f"UDP port range start must not exceed end: {start}-{end}"
        )


__all__ = [
    "UDP_PORT_MODES",
    "UdpDiscovery",
    "UdpDiscoveryConfig",
    "UdpDiscoveryResult",
    "UdpObservation",
    "UdpPortSelector",
]
