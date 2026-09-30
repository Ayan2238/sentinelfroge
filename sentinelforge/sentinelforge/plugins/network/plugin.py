"""Network Plugin — service identification and banner intelligence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sentinelforge.core.port_discovery import PortDiscovery, PortDiscoveryConfig
from sentinelforge.core.service_identifier import ServiceIdentifier
from sentinelforge.core.banner_grabber import BannerGrabber
from sentinelforge.core.version_identifier import VersionIdentifier
from sentinelforge.modules.base import Severity
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.target import Target


class NetworkPlugin(BasePlugin):
    """
    Network service identification.

    TCP port discovery is delegated to the shared PortDiscovery component.
    Service identification is delegated to ServiceIdentifier.
    TCP banner grabbing is integrated through the shared BannerGrabber component.
    """

    name = "network"
    description = "Network service identification"
    category = "network"

    def initialize(self) -> None:
        pass

    def can_run(self, target: "Target") -> bool:
        return True

    def cleanup(self) -> None:
        pass

    def run(self, target: "Target") -> PluginResult:
        result = PluginResult(plugin_name=self.name)

        addresses = list(target.resolved_ips)
        if not addresses:
            result.status = "success"
            result.metadata["services_identified"] = 0
            return result

        ports_config = self._cfg("scanning.ports", {}) or {}
        config = PortDiscoveryConfig(
            mode=str(ports_config.get("mode", "common")),
            ports=tuple(ports_config.get("ports", []) or []),
            ranges=tuple(
                tuple(port_range)
                for port_range in (ports_config.get("ranges", []) or [])
            ),
            top=ports_config.get("top"),
            max_workers=int(ports_config.get("max_workers", 100)),
            timeout=float(ports_config.get("timeout", 2)),
        )

        discovery = PortDiscovery(config).discover(
            target.host,
            addresses,
        )

        services = ServiceIdentifier().identify(discovery.observations)

        banners = BannerGrabber(
            timeout=config.timeout,
            max_bytes=4096,
        ).grab(services)
        banner_by_key = {
            (banner.address, banner.port, banner.transport): banner
            for banner in banners
        }

        versions = VersionIdentifier().identify(banners)
        version_by_key = {
            (version.address, version.port, version.transport): version
            for version in versions
        }

        for service in services:
            key = (service.address, service.port, service.transport)
            banner = banner_by_key.get(key)
            version = version_by_key.get(key)

            evidence = list(service.evidence)

            if banner is not None and banner.text:
                evidence.append(
                    f"Raw banner ({banner.interaction}): {banner.text}"
                )

            if (
                version is not None
                and version.product != "unknown"
                and version.version != "unknown"
            ):
                evidence.extend(version.evidence)

            severity = Severity.INFO

            result.add_finding(
                self._finding(
                    title=(
                        f"Network Service Identified: "
                        f"{service.service} (port {service.port})"
                    ),
                    severity=severity,
                    target=target,
                    description=(
                        f"A TCP service was identified on "
                        f"{service.address}:{service.port}. "
                        f"Identification method: "
                        f"{service.identification_method}."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Verify that the identified service is expected "
                        "and appropriately secured."
                    ),
                    tags=[
                        "network",
                        "service-identification",
                        service.service.lower(),
                    ],
                    raw_data={
                        "address": service.address,
                        "address_family": service.address_family,
                        "port": service.port,
                        "transport": service.transport,
                        "service": service.service,
                        "protocol": service.protocol,
                        "identification_method": service.identification_method,
                        "confidence": service.confidence,
                        **(
                            {
                                "banner": banner.text[:500],
                                "banner_interaction": banner.interaction,
                                "banner_error": banner.error,
                                "banner_truncated": banner.truncated,
                            }
                            if banner is not None
                            else {}
                        ),
                        **(
                            {
                                "product": version.product,
                                "version": version.version,
                                "version_confidence": version.confidence,
                                "version_identification_method": (
                                    version.identification_method
                                ),
                                "version_error": version.error,
                            }
                            if version is not None
                            else {}
                        ),
                    },
                )
            )

        result.metadata["ports_scanned"] = discovery.ports_scanned
        result.metadata["open_ports"] = list(discovery.open_ports)
        result.metadata["services_identified"] = len(services)
        result.metadata["versions_identified"] = sum(
            1
            for version in versions
            if version.product != "unknown"
            and version.version != "unknown"
        )

        result.status = "success"
        return result
