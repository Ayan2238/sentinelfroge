"""OSINT Plugin — passive open-source intelligence gathering."""

from __future__ import annotations

import urllib.request
from typing import TYPE_CHECKING

from sentinelforge.modules.base import Severity
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.target import Target


class OsintPlugin(BasePlugin):
    """
    OSINT checks:
    - robots.txt and sitemap.xml content analysis
    - Security.txt presence
    - .well-known/security.txt RFC 9116 compliance
    - Exposed Swagger/OpenAPI documentation
    """

    name = "osint"
    description = "OSINT: robots.txt, security.txt, exposed API documentation"
    category = "osint"

    def initialize(self) -> None:
        pass

    def can_run(self, target: "Target") -> bool:
        from sentinelforge.core.target import TargetType
        return target.kind in (TargetType.DOMAIN, TargetType.URL)

    def cleanup(self) -> None:
        pass

    def run(self, target: "Target") -> PluginResult:
        result = PluginResult(plugin_name=self.name)
        base_url = target.base_url
        timeout = self._cfg("general.timeout", 10)
        ua = self._cfg("general.user_agent", "SentinelForge/2.0")

        checks = [
            self._check_robots_txt,
            self._check_security_txt,
            self._check_api_docs,
        ]
        for fn in checks:
            try:
                for f in fn(base_url, target, timeout, ua):
                    result.add_finding(f)
            except Exception as exc:  # noqa: BLE001
                result.metadata[fn.__name__ + "_error"] = str(exc)

        result.status = "success"
        return result

    # ------------------------------------------------------------------

    def _fetch(self, url: str, ua: str, timeout: int) -> tuple[int, str]:
        from sentinelforge.core.network import ssl_context
        req = urllib.request.Request(url)
        req.add_header("User-Agent", ua)
        ctx = ssl_context(self._config)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
                return resp.status, resp.read(50_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except Exception:  # noqa: BLE001
            return 0, ""

    def _check_robots_txt(self, base_url: str, target: "Target", timeout: int, ua: str) -> list:
        status, body = self._fetch(base_url.rstrip("/") + "/robots.txt", ua, timeout)
        if status != 200 or not body:
            return []

        findings = [
            self._finding(
                title="robots.txt Discovered",
                severity=Severity.INFO,
                target=target,
                description="robots.txt is publicly accessible. Review for sensitive path disclosure.",
                evidence=body.split("\n")[:10],
                recommendation=(
                    "Review robots.txt to ensure it does not disclose admin paths, "
                    "backup locations, or internal API routes."
                ),
                tags=["osint", "robots"],
            )
        ]

        sensitive = [
            line for line in body.split("\n")
            if any(kw in line.lower() for kw in ("admin", "backup", "config", "private", "secret", "token"))
        ]
        if sensitive:
            findings.append(
                self._finding(
                    title="Sensitive Paths Disclosed in robots.txt",
                    severity=Severity.MEDIUM,
                    target=target,
                    description="robots.txt lists sensitive paths that may attract targeted attacks.",
                    evidence=sensitive[:10],
                    recommendation=(
                        "Remove sensitive paths from robots.txt — they are not hidden by it. "
                        "Use access controls, not obscurity."
                    ),
                    tags=["osint", "robots", "information-disclosure"],
                )
            )
        return findings

    def _check_security_txt(self, base_url: str, target: "Target", timeout: int, ua: str) -> list:
        paths = ["/.well-known/security.txt", "/security.txt"]
        for path in paths:
            status, body = self._fetch(base_url.rstrip("/") + path, ua, timeout)
            if status == 200 and "Contact:" in body:
                return [
                    self._finding(
                        title="security.txt Present (RFC 9116)",
                        severity=Severity.INFO,
                        target=target,
                        description="A security.txt file is present, providing a responsible disclosure contact.",
                        evidence=body.split("\n")[:5],
                        recommendation="Ensure security.txt is kept up to date with valid contact information.",
                        tags=["osint", "security.txt"],
                    )
                ]
        return [
            self._finding(
                title="Missing security.txt (RFC 9116)",
                severity=Severity.INFO,
                target=target,
                description="No security.txt file found. Security researchers have no official disclosure contact.",
                evidence=["/.well-known/security.txt not found"],
                recommendation=(
                    "Create a security.txt file at /.well-known/security.txt following RFC 9116 "
                    "to provide a responsible disclosure contact."
                ),
                references=["https://securitytxt.org/"],
                tags=["osint", "security.txt"],
            )
        ]

    def _check_api_docs(self, base_url: str, target: "Target", timeout: int, ua: str) -> list:
        api_doc_paths = [
            "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
            "/api-docs", "/api/docs", "/docs", "/v1/api-docs", "/v2/api-docs",
        ]
        findings = []
        for path in api_doc_paths:
            status, body = self._fetch(base_url.rstrip("/") + path, ua, timeout)
            if status == 200 and ('"swagger"' in body or '"openapi"' in body or "swagger:" in body):
                findings.append(
                    self._finding(
                        title="Exposed API Documentation (Swagger/OpenAPI)",
                        severity=Severity.MEDIUM,
                        target=target,
                        description=(
                            f"API documentation is publicly accessible at '{path}'. "
                            "This exposes all API endpoints, parameters, and authentication schemes to attackers."
                        ),
                        evidence=[f"HTTP 200 at {base_url}{path}"],
                        recommendation=(
                            "Restrict API documentation to authenticated users or internal networks. "
                            "Never expose API docs to the public internet without authentication."
                        ),
                        tags=["osint", "api", "information-disclosure"],
                    )
                )
        return findings
