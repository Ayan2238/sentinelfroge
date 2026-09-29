from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any

from sentinelforge.modules.base import Severity
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.target import Target


class ShodanPlugin(BasePlugin):
    """
    Shodan enrichment plugin.

    Uses the Shodan REST API to enrich IP targets with externally observed
    services and host intelligence. Account capabilities are detected before
    capability-dependent operations are attempted.
    """

    name = "shodan"
    description = "Shodan host intelligence and service exposure enrichment"
    category = "osint"

    _API_BASE = "https://api.shodan.io"

    def initialize(self) -> None:
        self._api_key = self._cfg("integrations.shodan.api_key")
        self._enabled = bool(
            self._cfg("integrations.shodan.enabled", False)
            and self._api_key
        )

    def can_run(self, target: "Target") -> bool:
        from sentinelforge.core.target import TargetType

        return self._enabled and target.kind in (
            TargetType.IP,
            TargetType.DOMAIN,
            TargetType.URL,
        )

    def cleanup(self) -> None:
        pass

    def run(self, target: "Target") -> PluginResult:
        result = PluginResult(plugin_name=self.name)

        if not self._enabled:
            result.status = "skipped"
            result.metadata["reason"] = "Shodan integration is disabled or not configured."
            return result

        host = target.host

        try:
            account = self._api_get("/api-info")
            result.metadata["plan"] = account.get("plan")
            result.metadata["query_credits"] = account.get("query_credits")
            result.metadata["scan_credits"] = account.get("scan_credits")

            result.metadata["capabilities"] = {
                "host_lookup": True,
                "host_count": False,
                "search": self._has_credits(account, "query_credits"),
                "on_demand_scan": self._has_credits(account, "scan_credits"),
            }

            # Host lookup is the primary no-query-credit enrichment operation.
            ip = self._resolve_target_ip(host)
            if not ip:
                result.status = "partial"
                result.metadata["host_lookup"] = "skipped"
                result.metadata["reason"] = "Could not resolve target to an IP address."
                return result

            result.metadata["resolved_ip"] = ip

            host_data = self._api_get(f"/shodan/host/{urllib.parse.quote(ip, safe='')}")
            self._add_host_metadata(result, host_data)
            self._add_host_findings(result, target, host_data)

            result.status = "success"

        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                result.status = "unavailable"
                result.metadata["reason"] = (
                    "Shodan rejected the operation because the current API "
                    "account/key does not have access to it."
                )
            elif exc.code == 402:
                result.status = "unavailable"
                result.metadata["reason"] = (
                    "This Shodan operation requires additional credits or plan access."
                )
            elif exc.code == 404:
                result.status = "partial"
                result.metadata["reason"] = "Shodan has no host data for this target."
            else:
                result.status = "failed"
                result.error = f"Shodan HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
        except Exception as exc:  # noqa: BLE001
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"

        return result

    # ------------------------------------------------------------------

    def _api_get(self, path: str) -> dict[str, Any]:
        params = urllib.parse.urlencode({"key": self._api_key})
        url = f"{self._API_BASE}{path}?{params}"

        timeout = self._cfg("general.timeout", 10)
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": self._cfg(
                    "general.user_agent",
                    "SentinelForge/1.0",
                ),
            },
        )

        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(2_000_000).decode("utf-8", errors="replace")

        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("Unexpected Shodan API response.")

        return data

    def _resolve_target_ip(self, host: str) -> str | None:
        try:
            import socket

            return socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            return None

    @staticmethod
    def _has_credits(account: dict[str, Any], field: str) -> bool:
        value = account.get(field)
        try:
            return int(value or 0) > 0
        except (TypeError, ValueError):
            return False

    def _add_host_metadata(
        self,
        result: PluginResult,
        data: dict[str, Any],
    ) -> None:
        result.metadata["hostnames"] = data.get("hostnames", [])
        result.metadata["domains"] = data.get("domains", [])
        result.metadata["os"] = data.get("os")
        result.metadata["organization"] = data.get("org")
        result.metadata["isp"] = data.get("isp")
        result.metadata["asn"] = data.get("asn")
        result.metadata["ports"] = data.get("ports", [])
        result.metadata["vulnerabilities"] = data.get("vulns", [])

    def _add_host_findings(
        self,
        result: PluginResult,
        target: "Target",
        data: dict[str, Any],
    ) -> None:
        ports = data.get("ports", [])

        if ports:
            result.add_finding(
                self._finding(
                    title="Shodan Externally Observed Services",
                    severity=Severity.INFO,
                    target=target,
                    description=(
                        "Shodan reports network services exposed on the target's "
                        "publicly observed IP address."
                    ),
                    evidence=[
                        f"IP: {data.get('ip_str', target.host)}",
                        f"Ports: {', '.join(str(p) for p in ports)}",
                    ],
                    recommendation=(
                        "Review externally exposed services and restrict "
                        "unnecessary services using appropriate network controls."
                    ),
                    references=["https://www.shodan.io/"],
                    tags=["shodan", "osint", "exposure"],
                )
            )

        hostnames = data.get("hostnames", [])
        if hostnames:
            result.add_finding(
                self._finding(
                    title="Shodan Hostnames Discovered",
                    severity=Severity.INFO,
                    target=target,
                    description="Shodan has associated public hostnames with the target IP.",
                    evidence=[str(h) for h in hostnames[:20]],
                    recommendation="Review discovered hostnames for unexpected public exposure.",
                    tags=["shodan", "osint", "hostname"],
                )
            )

        vulns = data.get("vulns", [])
        if vulns:
            result.add_finding(
                self._finding(
                    title="Shodan Reported Vulnerability References",
                    severity=Severity.MEDIUM,
                    target=target,
                    description=(
                        "Shodan reports vulnerability identifiers associated with "
                        "services observed on this host. These references require "
                        "independent verification."
                    ),
                    evidence=[str(v) for v in vulns[:50]],
                    recommendation=(
                        "Verify each reported vulnerability against the actual "
                        "service, version, configuration, and vendor advisory."
                    ),
                    tags=["shodan", "osint", "vulnerability-reference"],
                )
            )
