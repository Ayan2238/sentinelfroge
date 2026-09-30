"""TCP service banner grabbing with protocol-aware initial interaction."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Iterable

from sentinelforge.core.service_identifier import ServiceObservation


@dataclass(frozen=True)
class BannerObservation:
    """Raw banner evidence collected from one TCP service."""

    target: str
    address: str
    address_family: str
    port: int
    transport: str
    service: str
    interaction: str
    data: bytes
    text: str
    truncated: bool
    error: str | None = None


class BannerGrabber:
    """Collect initial TCP service responses without assuming version data."""

    _MAX_BYTES = 4096

    def __init__(self, timeout: float = 2.0, max_bytes: int = 4096) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        if max_bytes <= 0:
            raise ValueError("max_bytes must be greater than 0")

        self.timeout = float(timeout)
        self.max_bytes = int(max_bytes)

    def grab(
        self,
        services: Iterable[ServiceObservation],
    ) -> tuple[BannerObservation, ...]:
        observations: list[BannerObservation] = []

        for service in services:
            if service.transport.lower() != "tcp":
                continue

            observations.append(self._grab_one(service))

        return tuple(
            sorted(
                observations,
                key=lambda item: (
                    item.address,
                    item.port,
                ),
            )
        )

    def _grab_one(self, service: ServiceObservation) -> BannerObservation:
        interaction, payload = self._initial_interaction(service)

        try:
            family = (
                socket.AF_INET6
                if service.address_family.lower() in {"ipv6", "af_inet6"}
                else socket.AF_INET
            )

            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)

                if family == socket.AF_INET6:
                    endpoint = (service.address, service.port, 0, 0)
                else:
                    endpoint = (service.address, service.port)

                sock.connect(endpoint)

                if payload:
                    sock.sendall(payload)

                data = sock.recv(self.max_bytes)

            truncated = len(data) >= self.max_bytes
            text = data.decode("utf-8", errors="replace")

            return BannerObservation(
                target=service.target,
                address=service.address,
                address_family=service.address_family,
                port=service.port,
                transport=service.transport,
                service=service.service,
                interaction=interaction,
                data=data,
                text=text,
                truncated=truncated,
            )

        except socket.timeout as exc:
            return self._error(service, interaction, "timeout", exc)
        except (ConnectionRefusedError, ConnectionResetError) as exc:
            return self._error(service, interaction, "connection_failed", exc)
        except OSError as exc:
            return self._error(service, interaction, "socket_error", exc)

    @staticmethod
    def _initial_interaction(
        service: ServiceObservation,
    ) -> tuple[str, bytes]:
        service_name = service.service.lower()

        # These protocols commonly provide useful information immediately.
        if service_name in {
            "ssh",
            "ftp",
            "smtp",
            "pop3",
            "imap",
            "telnet",
            "redis",
            "mysql",
            "postgresql",
            "mongodb",
        }:
            return "passive", b""

        # HTTP requires a request to obtain a response banner.
        if service_name in {"http", "https"}:
            return (
                "http_head",
                (
                    b"HEAD / HTTP/1.0\r\n"
                    b"Host: localhost\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                ),
            )

        # Unknown services receive no speculative payload.
        return "passive", b""

    def _error(
        self,
        service: ServiceObservation,
        interaction: str,
        category: str,
        exc: BaseException,
    ) -> BannerObservation:
        return BannerObservation(
            target=service.target,
            address=service.address,
            address_family=service.address_family,
            port=service.port,
            transport=service.transport,
            service=service.service,
            interaction=interaction,
            data=b"",
            text="",
            truncated=False,
            error=f"{category}: {exc}",
        )


__all__ = [
    "BannerGrabber",
    "BannerObservation",
]
