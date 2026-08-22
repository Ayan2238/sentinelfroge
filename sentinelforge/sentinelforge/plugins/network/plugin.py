"""Network Plugin — banner grabbing and service fingerprinting."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

from sentinelforge.modules.base import Severity
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.target import Target


_SERVICE_MAP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    110: "POP3", 143: "IMAP", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch",
    27017: "MongoDB", 3389: "RDP",
}


class NetworkPlugin(BasePlugin):
    """
    Network service banner grabbing and fingerprinting.
    Identifies service versions exposed in connection banners.
    """

    name = "network"
    description = "Banner grabbing and network service fingerprinting"
    category = "network"

    def initialize(self) -> None:
        pass

    def can_run(self, target: "Target") -> bool:
        return True   # Works for all target types

    def cleanup(self) -> None:
        pass

    def run(self, target: "Target") -> PluginResult:
        result = PluginResult(plugin_name=self.name)
        host = target.resolved_ips[0] if target.resolved_ips else target.host
        timeout = 3

        banners: dict[int, str] = {}
        for port, service in _SERVICE_MAP.items():
            banner = self._grab_banner(host, port, timeout)
            if banner:
                banners[port] = banner

        if banners:
            for port, banner in banners.items():
                service = _SERVICE_MAP.get(port, str(port))
                severity = Severity.MEDIUM if port in (23, 3389) else Severity.LOW
                result.add_finding(
                    self._finding(
                        title=f"Service Banner Disclosed: {service} (port {port})",
                        severity=severity,
                        target=target,
                        description=(
                            f"The {service} service on port {port} discloses version "
                            "information in its connection banner."
                        ),
                        evidence=[f"Port {port}/tcp ({service}): {banner[:200]}"],
                        recommendation=(
                            f"Configure {service} to suppress version information in banners. "
                            f"Disable {service} if it is not required."
                        ),
                        tags=["network", "banner", service.lower()],
                        raw_data={"port": port, "service": service, "banner": banner[:500]},
                    )
                )

        result.status = "success"
        return result

    @staticmethod
    def _grab_banner(host: str, port: int, timeout: float) -> str:
        """Attempt to read a service banner from a TCP port."""
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                data = sock.recv(1024)
                return data.decode("utf-8", errors="replace").strip()
        except (OSError, ConnectionRefusedError, TimeoutError, UnicodeDecodeError):
            return ""
