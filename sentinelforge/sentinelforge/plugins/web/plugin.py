"""Web Technology Fingerprinting Plugin."""

from __future__ import annotations

import re
import urllib.request
from typing import TYPE_CHECKING
import ssl

from sentinelforge.modules.base import Severity
from sentinelforge.core.network import open_url, ssl_context
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.config import ConfigManager
    from sentinelforge.core.target import Target

# Fingerprinting signatures: pattern → (technology, category)
_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"wp-content/themes", re.I),         "WordPress",         "cms"),
    (re.compile(r"Drupal\.settings",    re.I),         "Drupal",            "cms"),
    (re.compile(r"<meta name=\"generator\" content=\"Joomla", re.I), "Joomla", "cms"),
    (re.compile(r"laravel_session",     re.I),         "Laravel",           "framework"),
    (re.compile(r"__django_session",    re.I),         "Django",            "framework"),
    (re.compile(r"PHPSESSID",           re.I),         "PHP",               "language"),
    (re.compile(r"X-Powered-By.*ASP",  re.I),         "ASP.NET",           "framework"),
    (re.compile(r"ng-version=",         re.I),         "Angular",           "frontend"),
    (re.compile(r"__NEXT_DATA__",       re.I),         "Next.js",           "framework"),
    (re.compile(r"react-root",          re.I),         "React",             "frontend"),
]


class WebPlugin(BasePlugin):
    """Web technology fingerprinting and CMS version detection."""

    name = "web"
    description = "Web technology fingerprinting and CMS version detection"
    category = "web"

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
        ua = self._cfg("general.user_agent", "SentinelForge/1.0")

        req = urllib.request.Request(base_url)
        req.add_header("User-Agent", ua)
        ctx = ssl_context(self._config)

        try:
            with open_url(req, self._config, timeout=timeout, context=ctx) as resp:
                headers = dict(resp.headers)
                body = resp.read(100_000).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            result.status = "skipped"
            result.metadata["reason"] = str(exc)
            return result

        detected: list[tuple[str, str]] = []
        combined = body + str(headers)

        for pattern, tech, category in _SIGNATURES:
            if pattern.search(combined):
                detected.append((tech, category))

        if detected:
            evidence = [f"{tech} ({cat})" for tech, cat in detected]
            result.add_finding(
                self._finding(
                    title="Web Technologies Identified",
                    severity=Severity.INFO,
                    target=target,
                    description=(
                        f"Fingerprinting identified {len(detected)} web technology(ies). "
                        "This information aids attackers in targeting known vulnerabilities."
                    ),
                    evidence=evidence,
                    recommendation=(
                        "Remove version information from response headers and HTML. "
                        "Keep all frameworks and CMS installations fully patched."
                    ),
                    tags=["fingerprint", "web"],
                    raw_data={"technologies": [{"name": t, "category": c} for t, c in detected]},
                )
            )

        # Check for WordPress-specific risks
        if any(t == "WordPress" for t, _ in detected):
            status, _, xmlrpc_body = self._fetch_raw(
                base_url + "/xmlrpc.php", ua, timeout, self._config
            )
            if status == 200 and "XML-RPC server accepts" in xmlrpc_body:
                result.add_finding(
                    self._finding(
                        title="WordPress XML-RPC Enabled",
                        severity=Severity.MEDIUM,
                        target=target,
                        description=(
                            "WordPress XML-RPC is enabled and accessible. "
                            "Attackers use it for brute force amplification and SSRF."
                        ),
                        evidence=[f"HTTP 200 at {base_url}/xmlrpc.php"],
                        recommendation=(
                            "Disable XML-RPC via your web server config or a security plugin "
                            "unless it is explicitly required (e.g. for Jetpack)."
                        ),
                        tags=["wordpress", "xmlrpc"],
                    )
                )

        result.status = "success"
        return result

    @staticmethod
    def _fetch_raw(url: str, ua: str, timeout: int, config) -> tuple[int, dict, str]:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", ua)
        ctx = ssl_context(config)
        try:
            with open_url(req, config, timeout=timeout, context=ctx) as resp:
                return resp.status, dict(resp.headers), resp.read(10_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), ""
        except Exception:  # noqa: BLE001
            return 0, {}, ""
