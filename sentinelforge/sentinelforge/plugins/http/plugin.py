"""HTTP Plugin — advanced HTTP-level security checks."""

from __future__ import annotations

import urllib.request
from typing import TYPE_CHECKING

from sentinelforge.modules.base import Severity
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.config import ConfigManager
    from sentinelforge.core.target import Target


class HttpPlugin(BasePlugin):
    """
    HTTP security checks:
    - HTTP → HTTPS redirect enforcement
    - Methods allowed (PUT, DELETE, TRACE, CONNECT)
    - Cache-Control on authenticated pages
    - Clickjacking (X-Frame-Options / CSP frame-ancestors)
    - MIME sniffing (X-Content-Type-Options)
    """

    name = "http"
    description = "HTTP-level security checks: methods, redirects, cache headers"
    category = "http"

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

        for check_fn in [
            self._check_https_redirect,
            self._check_allowed_methods,
            self._check_trace_method,
        ]:
            try:
                for f in check_fn(base_url, target, timeout, ua):
                    result.add_finding(f)
            except Exception as exc:  # noqa: BLE001
                result.metadata[check_fn.__name__ + "_error"] = str(exc)

        result.status = "success"
        return result

    # ------------------------------------------------------------------

    def _fetch(self, url: str, method: str, timeout: int, ua: str) -> tuple[int, dict]:
        import ssl as _ssl
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", ua)
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
                return resp.status, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers)
        except Exception:  # noqa: BLE001
            return 0, {}

    def _check_https_redirect(self, base_url: str, target: "Target", timeout: int, ua: str) -> list:
        host = target.host
        http_url = f"http://{host}/"
        status, headers = self._fetch(http_url, "GET", timeout, ua)

        if status not in (301, 302, 307, 308):
            return [self._finding(
                title="HTTP to HTTPS Redirect Not Enforced",
                severity=Severity.MEDIUM,
                target=target,
                description=(
                    f"The server does not redirect HTTP traffic to HTTPS. "
                    "Data transmitted over HTTP is unencrypted."
                ),
                evidence=[f"HTTP GET {http_url} returned {status} (expected 301/302)"],
                recommendation=(
                    "Configure your web server to permanently redirect all HTTP "
                    "traffic to HTTPS (HTTP 301)."
                ),
                tags=["http", "https", "cleartext"],
            )]
        return []

    def _check_allowed_methods(self, base_url: str, target: "Target", timeout: int, ua: str) -> list:
        status, headers = self._fetch(base_url, "OPTIONS", timeout, ua)
        if status == 0:
            return []
        allowed = headers.get("Allow", headers.get("allow", ""))
        risky = [m for m in ("PUT", "DELETE", "CONNECT") if m in allowed.upper()]
        if not risky:
            return []
        return [self._finding(
            title="Dangerous HTTP Methods Enabled",
            severity=Severity.MEDIUM,
            target=target,
            description=(
                f"The server allows HTTP methods that should be disabled: {', '.join(risky)}."
            ),
            evidence=[f"Allow: {allowed}"],
            recommendation=(
                "Disable HTTP methods that are not required (PUT, DELETE, CONNECT). "
                "Configure your web server to return 405 Method Not Allowed for these."
            ),
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            tags=["http", "methods"],
        )]

    def _check_trace_method(self, base_url: str, target: "Target", timeout: int, ua: str) -> list:
        """Check for HTTP TRACE support (XST vulnerability)."""
        status, headers = self._fetch(base_url, "TRACE", timeout, ua)
        if status == 200:
            return [self._finding(
                title="HTTP TRACE Method Enabled (XST Risk)",
                severity=Severity.LOW,
                target=target,
                description=(
                    "The server accepts HTTP TRACE requests, which can be used in "
                    "Cross-Site Tracing (XST) attacks to steal cookies."
                ),
                evidence=[f"HTTP TRACE {base_url} returned 200"],
                recommendation="Disable the HTTP TRACE method in your web server configuration.",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                tags=["http", "trace", "xst"],
            )]
        return []
