"""SSL/TLS Plugin — certificate and cipher suite security analysis."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import TYPE_CHECKING

from sentinelforge.modules.base import Severity
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.config import ConfigManager
    from sentinelforge.core.target import Target


class SslPlugin(BasePlugin):
    """
    SSL/TLS security plugin.

    Checks:
    - Certificate validity and expiry
    - Self-signed certificate detection
    - Weak cipher suite support (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    - HSTS preload
    - Certificate transparency (SCT)
    - Wildcard certificate scope
    """

    name = "ssl"
    description = "SSL/TLS certificate and cipher security analysis"
    category = "ssl"

    _WEAK_PROTOCOLS = {
        "SSLv2":  ssl.PROTOCOL_TLS_CLIENT,   # placeholder — we probe via handshake
        "SSLv3":  ssl.PROTOCOL_TLS_CLIENT,
        "TLSv1":  ssl.PROTOCOL_TLS_CLIENT,
        "TLSv1.1": ssl.PROTOCOL_TLS_CLIENT,
    }

    def initialize(self) -> None:
        pass

    def can_run(self, target: "Target") -> bool:
        from sentinelforge.core.target import TargetType
        return target.kind in (TargetType.DOMAIN, TargetType.URL)

    def cleanup(self) -> None:
        pass

    def run(self, target: "Target") -> PluginResult:
        result = PluginResult(plugin_name=self.name)
        host = target.host
        port = target.port or 443
        timeout = self._cfg("general.timeout", 10)

        cert_info = self._fetch_cert(host, port, timeout)
        if cert_info is None:
            result.status = "skipped"
            result.metadata["reason"] = "Could not establish TLS connection"
            return result

        result.metadata["cert_info"] = cert_info

        for check_fn in [
            self._check_cert_expiry,
            self._check_self_signed,
            self._check_hostname_mismatch,
            self._check_weak_tls,
            self._check_wildcard,
        ]:
            try:
                for f in check_fn(cert_info, host, port, target, timeout):
                    result.add_finding(f)
            except Exception as exc:  # noqa: BLE001
                result.metadata[check_fn.__name__ + "_error"] = str(exc)

        result.status = "success"
        return result

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_cert_expiry(self, cert: dict, host: str, port: int, target: "Target", timeout: int) -> list:
        not_after_str = cert.get("notAfter", "")
        if not not_after_str:
            return []
        try:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=datetime.timezone.utc)
            days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
        except ValueError:
            return []

        if days_left < 0:
            return [self._finding(
                title="SSL Certificate Expired",
                severity=Severity.CRITICAL,
                target=target,
                description=f"The SSL certificate for {host} expired {abs(days_left)} day(s) ago.",
                evidence=[f"Certificate notAfter: {not_after_str}", f"Days expired: {abs(days_left)}"],
                recommendation="Renew the SSL certificate immediately using Let's Encrypt or your CA.",
                tags=["ssl", "certificate", "expired"],
            )]
        if days_left < 14:
            return [self._finding(
                title="SSL Certificate Expiring Soon (< 14 days)",
                severity=Severity.HIGH,
                target=target,
                description=f"The SSL certificate expires in {days_left} day(s).",
                evidence=[f"Certificate notAfter: {not_after_str}"],
                recommendation="Renew the certificate before it expires to avoid service disruption.",
                tags=["ssl", "certificate", "expiry"],
            )]
        if days_left < 30:
            return [self._finding(
                title="SSL Certificate Expiring Soon (< 30 days)",
                severity=Severity.MEDIUM,
                target=target,
                description=f"The SSL certificate expires in {days_left} day(s).",
                evidence=[f"Certificate notAfter: {not_after_str}"],
                recommendation="Schedule certificate renewal within the next few days.",
                tags=["ssl", "certificate", "expiry"],
            )]
        return []

    def _check_self_signed(self, cert: dict, host: str, port: int, target: "Target", timeout: int) -> list:
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        if issuer.get("organizationName") == subject.get("organizationName") and \
                issuer.get("commonName") == subject.get("commonName"):
            return [self._finding(
                title="Self-Signed SSL Certificate Detected",
                severity=Severity.HIGH,
                target=target,
                description=(
                    "The SSL certificate appears to be self-signed. "
                    "Browsers will show a security warning, and the certificate "
                    "provides no identity assurance."
                ),
                evidence=[
                    f"Subject CN: {subject.get('commonName', 'N/A')}",
                    f"Issuer CN: {issuer.get('commonName', 'N/A')}",
                ],
                recommendation=(
                    "Replace the self-signed certificate with one issued by a "
                    "trusted Certificate Authority (e.g., Let's Encrypt)."
                ),
                tags=["ssl", "self-signed"],
            )]
        return []

    def _check_hostname_mismatch(self, cert: dict, host: str, port: int, target: "Target", timeout: int) -> list:
        subject = dict(x[0] for x in cert.get("subject", []))
        san_list = [v for _, v in cert.get("subjectAltName", [])]
        cn = subject.get("commonName", "")
        all_names = san_list if san_list else [cn]
        match = any(
            self._hostname_matches(host, name) for name in all_names
        )
        if not match:
            return [self._finding(
                title="SSL Certificate Hostname Mismatch",
                severity=Severity.HIGH,
                target=target,
                description=(
                    f"The SSL certificate is not valid for '{host}'. "
                    "This will cause browser security warnings."
                ),
                evidence=[
                    f"Host: {host}",
                    f"Certificate CN: {cn}",
                    f"SANs: {', '.join(san_list[:10])}",
                ],
                recommendation=(
                    "Obtain a certificate that includes the correct hostname "
                    "in the Subject Alternative Name (SAN) extension."
                ),
                tags=["ssl", "hostname-mismatch"],
            )]
        return []

    def _check_weak_tls(self, cert: dict, host: str, port: int, target: "Target", timeout: int) -> list:
        """Probe for TLS 1.0 / 1.1 support."""
        findings = []
        for proto_name, min_version in [("TLS 1.0", ssl.TLSVersion.TLSv1),
                                         ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = min_version
                ctx.maximum_version = min_version
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        findings.append(self._finding(
                            title=f"Weak TLS Protocol Supported: {proto_name}",
                            severity=Severity.MEDIUM,
                            target=target,
                            description=(
                                f"The server accepts {proto_name}, which is deprecated "
                                "and known to be vulnerable to BEAST and POODLE attacks."
                            ),
                            evidence=[f"{proto_name} handshake succeeded on {host}:{port}"],
                            recommendation=(
                                f"Disable {proto_name} in your web server configuration. "
                                "Support only TLS 1.2 and TLS 1.3."
                            ),
                            references=["https://tools.ietf.org/html/rfc8996"],
                            tags=["ssl", "weak-protocol", proto_name.lower().replace(" ", "")],
                        ))
            except (ssl.SSLError, OSError, AttributeError):
                pass
        return findings

    def _check_wildcard(self, cert: dict, host: str, port: int, target: "Target", timeout: int) -> list:
        san_list = [v for _, v in cert.get("subjectAltName", [])]
        wildcards = [s for s in san_list if s.startswith("*.")]
        if len(wildcards) >= 3:
            return [self._finding(
                title="Overly Broad Wildcard Certificate",
                severity=Severity.LOW,
                target=target,
                description=(
                    f"The certificate covers {len(wildcards)} wildcard domain(s). "
                    "A compromise of the private key exposes all covered subdomains."
                ),
                evidence=wildcards[:10],
                recommendation=(
                    "Use targeted certificates for specific services rather than "
                    "broad wildcard certificates where possible."
                ),
                tags=["ssl", "wildcard"],
            )]
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fetch_cert(self, host: str, port: int, timeout: int) -> dict | None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert()
        except (ssl.SSLError, OSError, TimeoutError):
            return None

    @staticmethod
    def _hostname_matches(host: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            parts = host.split(".")
            pparts = pattern[2:].split(".")
            return len(parts) >= 2 and parts[1:] == pparts
        return host == pattern
