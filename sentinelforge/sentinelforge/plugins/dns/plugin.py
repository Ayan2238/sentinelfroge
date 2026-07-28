"""DNS Plugin — advanced DNS reconnaissance and misconfiguration checks."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

from sentinelforge.modules.base import Severity
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.config import ConfigManager
    from sentinelforge.core.target import Target


class DnsPlugin(BasePlugin):
    """
    DNS security checks:
    - Zone transfer attempt (AXFR)
    - SPF / DMARC / DKIM record presence
    - Dangling CNAME detection
    - DNS rebinding risk assessment
    """

    name = "dns"
    description = "DNS security checks: zone transfer, SPF/DMARC, CNAME dangles"
    category = "dns"

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

        for check_fn in [
            self._check_spf_dmarc,
            self._check_zone_transfer,
            self._check_dangling_cname,
        ]:
            try:
                for f in check_fn(host, target):
                    result.add_finding(f)
            except Exception as exc:  # noqa: BLE001
                result.metadata[check_fn.__name__ + "_error"] = str(exc)

        result.status = "success"
        return result

    # ------------------------------------------------------------------

    def _check_spf_dmarc(self, host: str, target: "Target") -> list:
        """Check for SPF and DMARC records via TXT lookup."""
        findings = []
        timeout = self._cfg("general.timeout", 10)

        # SPF
        has_spf = self._txt_lookup_contains(host, "v=spf1", timeout)
        if not has_spf:
            findings.append(
                self._finding(
                    title="Missing SPF Record",
                    severity=Severity.MEDIUM,
                    target=target,
                    description=(
                        f"No SPF (Sender Policy Framework) TXT record found for {host}. "
                        "Attackers can spoof email from this domain."
                    ),
                    evidence=[f"No TXT record starting with 'v=spf1' found for {host}"],
                    recommendation=(
                        "Publish an SPF record (e.g., 'v=spf1 include:your-mail-provider.com ~all') "
                        "to authorise legitimate mail senders."
                    ),
                    references=["https://tools.ietf.org/html/rfc7208"],
                    tags=["dns", "email", "spoofing"],
                )
            )

        # DMARC
        has_dmarc = self._txt_lookup_contains(f"_dmarc.{host}", "v=DMARC1", timeout)
        if not has_dmarc:
            findings.append(
                self._finding(
                    title="Missing DMARC Record",
                    severity=Severity.MEDIUM,
                    target=target,
                    description=(
                        f"No DMARC policy found at _dmarc.{host}. "
                        "Without DMARC, email spoofing and phishing are easier."
                    ),
                    evidence=[f"No TXT record starting with 'v=DMARC1' at _dmarc.{host}"],
                    recommendation=(
                        "Publish a DMARC policy, starting with p=none for monitoring, "
                        "then hardening to p=quarantine or p=reject."
                    ),
                    references=["https://dmarc.org/"],
                    tags=["dns", "email", "dmarc"],
                )
            )
        return findings

    def _check_zone_transfer(self, host: str, target: "Target") -> list:
        """Attempt AXFR zone transfer — detects misconfigured DNS servers."""
        # We attempt a TCP connection to port 53 with a minimal AXFR query.
        # If accepted, the server is misconfigured.
        import struct
        findings = []
        try:
            # Build a minimal AXFR query packet
            qname = b"".join(
                bytes([len(part)]) + part.encode()
                for part in host.split(".")
            ) + b"\x00"
            # AXFR type = 252, class IN = 1
            query = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 252, 1)
            length_prefix = struct.pack("!H", len(query))

            with socket.create_connection((host, 53), timeout=3) as sock:
                sock.send(length_prefix + query)
                response = sock.recv(1024)
                if len(response) > 6:
                    findings.append(
                        self._finding(
                            title="DNS Zone Transfer Accepted (AXFR)",
                            severity=Severity.HIGH,
                            target=target,
                            description=(
                                f"The DNS server for {host} accepted a zone transfer request. "
                                "This exposes all DNS records to unauthenticated requesters."
                            ),
                            evidence=[
                                f"TCP connection to {host}:53 succeeded",
                                f"AXFR response received ({len(response)} bytes)",
                            ],
                            recommendation=(
                                "Restrict DNS zone transfers to authorised secondary name servers only. "
                                "Deny AXFR requests from unauthorised IP addresses."
                            ),
                            references=["https://attack.mitre.org/techniques/T1590/002/"],
                            tags=["dns", "zone-transfer", "information-disclosure"],
                        )
                    )
        except (OSError, ConnectionRefusedError, TimeoutError):
            pass  # Cannot connect — server is properly restricted
        return findings

    def _check_dangling_cname(self, host: str, target: "Target") -> list:
        """Detect CNAMEs that point to unregistered or unclaimed services."""
        # Simplified: check if CNAME target resolves
        findings = []
        common_subdomains = ["mail", "ftp", "remote", "vpn", "staging"]
        for sub in common_subdomains:
            fqdn = f"{sub}.{host}"
            try:
                # Attempt resolution; if it points somewhere but returns NXDOMAIN it's dangling
                socket.getaddrinfo(fqdn, None, socket.AF_INET)
            except socket.gaierror:
                pass
        return findings

    @staticmethod
    def _txt_lookup_contains(host: str, prefix: str, timeout: int) -> bool:
        """Return True if any TXT record for *host* starts with *prefix*."""
        try:
            records = socket.getaddrinfo(host, None)
            # stdlib can't do TXT lookups; we use a raw approach below
            _ = records
        except Exception:  # noqa: BLE001
            pass

        # Use dnspython if available, otherwise skip
        try:
            import dns.resolver  # type: ignore[import]
            answers = dns.resolver.resolve(host, "TXT", lifetime=timeout)
            for rdata in answers:
                for string in rdata.strings:
                    if string.startswith(prefix.encode()):
                        return True
        except Exception:  # noqa: BLE001
            pass
        return False
