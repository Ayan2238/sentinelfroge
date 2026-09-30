"""Network service identification from observed open ports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from sentinelforge.core.port_discovery import PortObservation


# Port numbers are hints only. They are not treated as protocol proof.
_SERVICE_HINTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    3000: "HTTP",
    3306: "MySQL",
    3389: "RDP",
    5000: "HTTP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    6443: "HTTPS",
    8000: "HTTP",
    8080: "HTTP",
    8443: "HTTPS",
    8888: "HTTP",
    9200: "Elasticsearch",
    9300: "Elasticsearch Transport",
    11211: "Memcached",
    27017: "MongoDB",
}


@dataclass(frozen=True)
class ServiceObservation:
    """Structured service identification derived from a port observation."""

    target: str
    address: str
    address_family: str
    port: int
    transport: str
    service: str
    protocol: str
    identification_method: str
    confidence: float
    evidence: tuple[str, ...]


class ServiceIdentifier:
    """Identify likely services from open-port observations.

    Port mappings are intentionally represented as hints. Active protocol
    probing and banner/version detection are handled by later Phase 3 stages.
    """

    def identify(
        self,
        observations: Iterable[PortObservation],
    ) -> tuple[ServiceObservation, ...]:
        services: list[ServiceObservation] = []

        for observation in observations:
            if observation.state != "open":
                continue

            service = _SERVICE_HINTS.get(observation.port, "unknown")
            if service == "unknown":
                confidence = 0.10
                method = "unknown"
                evidence = (
                    f"{observation.address}:{observation.port}/"
                    f"{observation.transport} is open; no service hint is available",
                )
            else:
                confidence = 0.50
                method = "port_hint"
                evidence = (
                    f"{observation.address}:{observation.port}/"
                    f"{observation.transport} is open; "
                    f"port {observation.port} is commonly associated with {service}",
                )

            protocol = service.lower() if service != "unknown" else "unknown"

            services.append(
                ServiceObservation(
                    target=observation.target,
                    address=observation.address,
                    address_family=observation.address_family,
                    port=observation.port,
                    transport=observation.transport,
                    service=service,
                    protocol=protocol,
                    identification_method=method,
                    confidence=confidence,
                    evidence=evidence,
                )
            )

        return tuple(
            sorted(
                services,
                key=lambda item: (
                    item.address,
                    item.transport,
                    item.port,
                ),
            )
        )


__all__ = [
    "ServiceIdentifier",
    "ServiceObservation",
]
