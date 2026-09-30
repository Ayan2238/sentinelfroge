"""Product and version fingerprinting from observed service banners."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from sentinelforge.core.banner_grabber import BannerObservation


@dataclass(frozen=True)
class VersionObservation:
    """Product/version identification derived from banner evidence."""

    target: str
    address: str
    address_family: str
    port: int
    transport: str
    service: str
    product: str
    version: str
    confidence: float
    identification_method: str
    evidence: tuple[str, ...]
    banner: str
    error: str | None = None


class VersionIdentifier:
    """Identify products and versions only from explicit banner evidence."""

    _PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
        (
            "ssh",
            "OpenSSH",
            "openssh",
            re.compile(
                r"\bOpenSSH[_\s-]?([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        ),
        (
            "ssh",
            "Dropbear SSH",
            "dropbear",
            re.compile(
                r"\bDropbear[_\s-]?([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        ),
        (
            "ftp",
            "vsftpd",
            "vsftpd",
            re.compile(
                r"\bvsftpd\s+([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        ),
        (
            "smtp",
            "Postfix",
            "postfix",
            re.compile(
                r"\bPostfix(?:\s+SMTP)?\b.*?\b([0-9]+(?:\.[0-9]+)+)\b",
                re.IGNORECASE,
            ),
        ),
        (
            "http",
            "nginx",
            "nginx",
            re.compile(
                r"\bnginx/?([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        ),
        (
            "http",
            "Apache HTTP Server",
            "apache",
            re.compile(
                r"\bApache(?:/|\s+)([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        ),
        (
            "http",
            "Microsoft IIS",
            "iis",
            re.compile(
                r"\bMicrosoft-IIS/([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        ),
        (
            "http",
            "Caddy",
            "caddy",
            re.compile(
                r"\bCaddy/?([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        ),
        (
            "redis",
            "Redis",
            "redis",
            re.compile(
                r"\bRedis(?:\s+server)?\s+v?([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        ),
        (
            "mongodb",
            "MongoDB",
            "mongodb",
            re.compile(
                r"\bMongoDB\b.*?\bv?([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        ),
    )

    def identify(
        self,
        observations: Iterable[BannerObservation],
    ) -> tuple[VersionObservation, ...]:
        results = [
            self._identify_one(observation)
            for observation in observations
        ]

        return tuple(
            sorted(
                results,
                key=lambda item: (
                    item.address,
                    item.port,
                    item.product,
                    item.version,
                ),
            )
        )

    def _identify_one(
        self,
        observation: BannerObservation,
    ) -> VersionObservation:
        banner = observation.text

        if observation.error:
            return self._unknown(
                observation,
                method="banner_error",
                error=observation.error,
            )

        if not banner:
            return self._unknown(
                observation,
                method="no_banner",
            )

        service_name = observation.service.lower()

        for pattern_service, product, method, pattern in self._PATTERNS:
            if service_name not in {pattern_service, "unknown"}:
                continue

            match = pattern.search(banner)
            if not match:
                continue

            version = match.group(1)

            return VersionObservation(
                target=observation.target,
                address=observation.address,
                address_family=observation.address_family,
                port=observation.port,
                transport=observation.transport,
                service=observation.service,
                product=product,
                version=version,
                confidence=0.95,
                identification_method=f"banner:{method}",
                evidence=(
                    f"Banner explicitly identifies {product} {version}",
                    f"Raw banner: {banner}",
                ),
                banner=banner,
            )

        return self._unknown(
            observation,
            method="banner_unrecognized",
        )

    @staticmethod
    def _unknown(
        observation: BannerObservation,
        *,
        method: str,
        error: str | None = None,
    ) -> VersionObservation:
        evidence: list[str] = []

        if observation.text:
            evidence.append(
                f"Raw banner did not provide a recognized product/version: "
                f"{observation.text}"
            )
        else:
            evidence.append("No usable version evidence was obtained from the banner.")

        return VersionObservation(
            target=observation.target,
            address=observation.address,
            address_family=observation.address_family,
            port=observation.port,
            transport=observation.transport,
            service=observation.service,
            product="unknown",
            version="unknown",
            confidence=0.0,
            identification_method=method,
            evidence=tuple(evidence),
            banner=observation.text,
            error=error,
        )


__all__ = [
    "VersionIdentifier",
    "VersionObservation",
]
