"""TCP port discovery primitives for SentinelForge.

This module performs bounded TCP connectivity discovery only.
It does not perform service detection, banner grabbing, protocol
identification, version detection, or vulnerability assessment.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable


PORT_MODES = {"common", "top", "explicit", "range", "all"}

# Initial deterministic SentinelForge common TCP set.
COMMON_TCP_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    389,
    443,
    445,
    465,
    587,
    636,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    3000,
    3306,
    3389,
    5000,
    5432,
    5900,
    5985,
    6379,
    6443,
    8000,
    8080,
    8443,
    8888,
    9200,
    9300,
    11211,
    27017,
)

# Deterministic initial top-port ranking. This is deliberately separate
# from COMMON_TCP_PORTS so the ranking can be expanded independently.
TOP_TCP_PORTS: tuple[int, ...] = COMMON_TCP_PORTS


@dataclass(frozen=True)
class PortDiscoveryConfig:
    """Normalized configuration for TCP port discovery."""

    mode: str = "common"
    ports: tuple[int, ...] = ()
    ranges: tuple[tuple[int, int], ...] = ()
    top: int | None = None
    max_workers: int = 100
    timeout: float = 2.0

    def __post_init__(self) -> None:
        if self.mode not in PORT_MODES:
            raise ValueError(
                f"invalid port discovery mode: {self.mode!r}; "
                f"expected one of {sorted(PORT_MODES)}"
            )

        for port in self.ports:
            _validate_port(port)

        for start, end in self.ranges:
            _validate_range(start, end)

        if self.top is not None and self.top <= 0:
            raise ValueError("top must be greater than zero")

        if not 1 <= self.max_workers <= 1024:
            raise ValueError("max_workers must be between 1 and 1024")

        if not 0.1 <= self.timeout <= 3600:
            raise ValueError("timeout must be between 0.1 and 3600 seconds")


@dataclass(frozen=True)
class PortObservation:
    """Normalized observation produced by one TCP connectivity probe."""

    target: str
    address: str
    address_family: str
    port: int
    transport: str
    state: str
    latency_ms: float | None
    timestamp: str
    error: str | None = None


@dataclass(frozen=True)
class PortDiscoveryResult:
    """Aggregate result of a TCP port-discovery operation."""

    observations: tuple[PortObservation, ...]
    ports_scanned: int
    open_count: int
    closed_count: int
    timeout_count: int
    error_count: int
    elapsed: float

    @property
    def open_ports(self) -> tuple[int, ...]:
        """Return unique open TCP ports in deterministic order."""
        return tuple(
            sorted(
                {
                    observation.port
                    for observation in self.observations
                    if observation.state == "open"
                }
            )
        )


class PortSelector:
    """Resolve normalized port configuration into a deterministic port list."""

    @staticmethod
    def select(config: PortDiscoveryConfig) -> list[int]:
        if config.mode == "common":
            selected = list(COMMON_TCP_PORTS)
        elif config.mode == "top":
            limit = config.top
            if limit is None:
                raise ValueError("top mode requires a top value")
            selected = list(TOP_TCP_PORTS[:limit])
        elif config.mode == "explicit":
            selected = list(config.ports)
        elif config.mode == "range":
            selected = []
            for start, end in config.ranges:
                selected.extend(range(start, end + 1))
        elif config.mode == "all":
            selected = list(range(1, 65536))
        else:
            raise ValueError(f"unsupported port mode: {config.mode!r}")

        return sorted(set(selected))


class PortDiscovery:
    """Bounded TCP connectivity discovery."""

    def __init__(self, config: PortDiscoveryConfig) -> None:
        self.config = config

    def discover(
        self,
        target: str,
        addresses: Iterable[str],
    ) -> PortDiscoveryResult:
        """Probe every selected port on every unique supplied address."""
        normalized_addresses = self._normalize_addresses(addresses)
        ports = PortSelector.select(self.config)

        work_items = (
            (address, port)
            for address in normalized_addresses
            for port in ports
        )

        started = time.monotonic()

        observations: list[PortObservation] = []

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
                    self._probe,
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

                observations.append(done.result())
                del in_flight[done]

                submit_next()

        observations.sort(
            key=lambda item: (
                item.address,
                item.port,
            )
        )

        elapsed = time.monotonic() - started

        return PortDiscoveryResult(
            observations=tuple(observations),
            ports_scanned=len(observations),
            open_count=sum(
                observation.state == "open"
                for observation in observations
            ),
            closed_count=sum(
                observation.state == "closed"
                for observation in observations
            ),
            timeout_count=sum(
                observation.state == "timeout"
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
                    f"invalid IP address for port discovery: {value!r}"
                ) from exc

        return sorted(
            normalized,
            key=lambda value: (
                ipaddress.ip_address(value).version,
                int(ipaddress.ip_address(value)),
            ),
        )

    @staticmethod
    def _probe(
        target: str,
        address: str,
        port: int,
        timeout: float,
    ) -> PortObservation:
        ip = ipaddress.ip_address(address)
        family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
        family_name = "ipv4" if ip.version == 4 else "ipv6"

        started = time.monotonic()
        timestamp = datetime.now(timezone.utc).isoformat()

        state = "error"
        error: str | None = None

        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)

                if family == socket.AF_INET6:
                    sock.connect((address, port, 0, 0))
                else:
                    sock.connect((address, port))

                state = "open"

        except ConnectionRefusedError:
            state = "closed"
            error = "connection_refused"

        except socket.timeout:
            state = "timeout"
            error = "timeout"

        except TimeoutError:
            state = "timeout"
            error = "timeout"

        except OSError as exc:
            state = "error"
            error = f"{type(exc).__name__}: {exc}"

        latency_ms = round(
            (time.monotonic() - started) * 1000,
            3,
        )

        return PortObservation(
            target=target,
            address=address,
            address_family=family_name,
            port=port,
            transport="tcp",
            state=state,
            latency_ms=latency_ms,
            timestamp=timestamp,
            error=error,
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
            f"port range start must not exceed end: {start}-{end}"
        )
