"""
Reconnaissance Module
~~~~~~~~~~~~~~~~~~~~~
Passive and active information gathering against a target.
Covers subdomain enumeration, DNS records, WHOIS, Wayback Machine,
certificate transparency, and basic port discovery.
"""

from __future__ import annotations

import re
import socket
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any
from urllib.error import URLError

from sentinelforge.modules.base import BaseModule, Finding, ModuleResult, Severity

if TYPE_CHECKING:
    from sentinelforge.core.config import ConfigManager
    from sentinelforge.core.session import Session
    from sentinelforge.core.target import Target


class ReconModule(BaseModule):
    """
    Reconnaissance module.

    Gathers attack surface data without exploiting any vulnerability.
    All sub-tasks (DNS, WHOIS, certificate logs, wayback, port scan)
    run concurrently and are collected into a single :class:`ModuleResult`.
    """

    name = "reconnaissance"
    description = "Passive and active information gathering"
    category = "recon"

    _COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                     993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
                     8080, 8443, 8888, 27017]

    def __init__(self, config: "ConfigManager") -> None:
        super().__init__(config)
        self._timeout: int = self._cfg("general.timeout", 10)
        self._max_workers: int = min(self._cfg("general.max_threads", 10), 20)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        pass  # No heavy setup required

    def validate(self, target: "Target") -> bool:
        from sentinelforge.core.target import TargetType
        return target.kind in (TargetType.DOMAIN, TargetType.URL, TargetType.IP)

    def cleanup(self) -> None:
        pass

    def run(self, target: "Target", session: "Session") -> ModuleResult:
        result = ModuleResult(module_name=self.name)

        tasks = {
            "dns":         (self._enumerate_dns,      (target,)),
            "subdomains":  (self._enumerate_subdomains, (target,)),
            "ports":       (self._scan_ports,          (target,)),
            "cert_transparency": (self._cert_transparency, (target,)),
            "wayback":     (self._wayback_urls,        (target,)),
            "whois":       (self._whois_lookup,        (target,)),
        }

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {
                pool.submit(fn, *args): name
                for name, (fn, args) in tasks.items()
            }
            for fut in as_completed(futures):
                task_name = futures[fut]
                try:
                    findings = fut.result(timeout=self._timeout * 2)
                    for f in findings:
                        result.add_finding(f)
                except Exception as exc:  # noqa: BLE001
                    result.metadata[f"{task_name}_error"] = str(exc)

        result.status = "success"
        return result

    # ------------------------------------------------------------------
    # Sub-tasks
    # ------------------------------------------------------------------

    def _enumerate_dns(self, target: "Target") -> list[Finding]:
        """Resolve common DNS record types."""
        findings: list[Finding] = []
        host = target.host

        record_types = {
            "A":     socket.AF_INET,
            "AAAA":  socket.AF_INET6,
        }
        resolved: dict[str, list[str]] = {}

        for rtype, family in record_types.items():
            try:
                info = socket.getaddrinfo(host, None, family)
                resolved[rtype] = list({addr[4][0] for addr in info})
            except (socket.gaierror, OSError):
                pass

        if resolved:
            evidence = [f"{rt}: {', '.join(addrs)}" for rt, addrs in resolved.items()]
            findings.append(
                self._finding(
                    title="DNS Records Resolved",
                    severity=Severity.INFO,
                    target=target,
                    description=f"Resolved DNS records for {host}.",
                    evidence=evidence,
                    recommendation="Verify DNS records are intended and not stale.",
                    raw_data={"dns_records": resolved},
                )
            )
        return findings

    def _enumerate_subdomains(self, target: "Target") -> list[Finding]:
        """Brute-force common subdomains from a built-in wordlist."""
        if target.kind.value == "ip":
            return []

        wordlist = [
            "www", "mail", "ftp", "remote", "blog", "webmail", "server",
            "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop", "api",
            "dev", "staging", "test", "portal", "admin", "app", "cdn",
            "static", "media", "assets", "status", "login", "auth", "beta",
        ]
        host = target.host
        found: list[str] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {
                pool.submit(self._resolve, f"{sub}.{host}"): sub
                for sub in wordlist
            }
            for fut in as_completed(futures):
                if fut.result():
                    found.append(f"{futures[fut]}.{host}")

        if found:
            return [
                self._finding(
                    title="Subdomains Discovered",
                    severity=Severity.INFO,
                    target=target,
                    description=f"Found {len(found)} accessible subdomain(s).",
                    evidence=sorted(found),
                    recommendation=(
                        "Review discovered subdomains for forgotten, staging, or "
                        "development environments that may have weaker security."
                    ),
                    tags=["recon", "subdomains"],
                    raw_data={"subdomains": sorted(found)},
                )
            ]
        return []

    def _scan_ports(self, target: "Target") -> list[Finding]:
        """Connect-scan common TCP ports."""
        host = target.resolved_ips[0] if target.resolved_ips else target.host
        open_ports: list[int] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {
                pool.submit(self._check_port, host, port): port
                for port in self._COMMON_PORTS
            }
            for fut in as_completed(futures):
                port = futures[fut]
                try:
                    if fut.result():
                        open_ports.append(port)
                except Exception:  # noqa: BLE001
                    pass

        open_ports.sort()
        if not open_ports:
            return []

        risky = [p for p in open_ports if p in (21, 23, 3389, 5900)]
        severity = Severity.MEDIUM if risky else Severity.INFO
        findings = [
            self._finding(
                title="Open TCP Ports Detected",
                severity=severity,
                target=target,
                description=f"Found {len(open_ports)} open TCP port(s).",
                evidence=[f"Port {p}/tcp open" for p in open_ports],
                recommendation=(
                    "Restrict open ports to only those required by the application. "
                    "Legacy protocols (FTP, Telnet, RDP, VNC) should be disabled or replaced."
                )
                if risky
                else "Review whether all open ports are intentional.",
                tags=["recon", "ports"],
                raw_data={"open_ports": open_ports, "risky_ports": risky},
            )
        ]

        if risky:
            for port in risky:
                service = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC"}.get(port, str(port))
                findings.append(
                    self._finding(
                        title=f"Insecure Service Detected: {service} (port {port})",
                        severity=Severity.HIGH,
                        target=target,
                        description=(
                            f"{service} on port {port} transmits data in cleartext "
                            "or has a history of critical vulnerabilities."
                        ),
                        evidence=[f"Port {port}/tcp open ({service})"],
                        recommendation=f"Disable {service} or replace with a secure alternative (SSH, SFTP, HTTPS).",
                        references=["https://attack.mitre.org/techniques/T1021/"],
                        tags=["recon", "ports", "cleartext"],
                    )
                )
        return findings

    def _cert_transparency(self, target: "Target") -> list[Finding]:
        """Query crt.sh for certificate transparency records."""
        if target.kind.value == "ip":
            return []
        host = target.host
        url = f"https://crt.sh/?q=%.{host}&output=json"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:  # noqa: S310
                import json
                data = json.loads(resp.read().decode())
        except Exception:  # noqa: BLE001
            return []

        names: set[str] = set()
        for entry in data[:200]:           # cap at 200 certs
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*"):
                    names.add(name)

        if not names:
            return []

        return [
            self._finding(
                title="Certificate Transparency Entries Found",
                severity=Severity.INFO,
                target=target,
                description=(
                    f"Certificate Transparency logs reveal {len(names)} hostname(s) "
                    "associated with this domain."
                ),
                evidence=sorted(names)[:30],
                recommendation=(
                    "Review CT log entries for shadow IT, staging environments, "
                    "or forgotten services."
                ),
                references=["https://certificate.transparency.dev/"],
                tags=["recon", "ct-logs"],
                raw_data={"ct_names": sorted(names)},
            )
        ]

    def _wayback_urls(self, target: "Target") -> list[Finding]:
        """Fetch historical URLs from the Wayback CDX API."""
        if target.kind.value == "ip":
            return []
        host = target.host
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={host}/*&output=json&fl=original&collapse=urlkey&limit=200"
        )
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:  # noqa: S310
                import json
                data = json.loads(resp.read().decode())
        except Exception:  # noqa: BLE001
            return []

        # data[0] is the header row
        urls = [row[0] for row in data[1:] if row]

        if not urls:
            return []

        sensitive_patterns = re.compile(
            r"(admin|backup|config|debug|env|secret|token|password|\.git|\.env|"
            r"phpmyadmin|wp-admin|\.sql|dump|export)",
            re.I,
        )
        sensitive = [u for u in urls if sensitive_patterns.search(u)]

        findings = [
            self._finding(
                title="Historical URLs Found (Wayback Machine)",
                severity=Severity.INFO,
                target=target,
                description=f"Wayback Machine has {len(urls)} archived URL(s) for this domain.",
                evidence=urls[:20],
                recommendation=(
                    "Review archived endpoints for forgotten admin panels, "
                    "exposed config files, or deprecated API routes."
                ),
                tags=["recon", "osint", "wayback"],
                raw_data={"wayback_count": len(urls)},
            )
        ]

        if sensitive:
            findings.append(
                self._finding(
                    title="Sensitive Historical URLs Detected",
                    severity=Severity.MEDIUM,
                    target=target,
                    description=(
                        f"{len(sensitive)} historical URL(s) suggest exposure of "
                        "sensitive paths (admin, config, backup, env, etc.)."
                    ),
                    evidence=sensitive[:20],
                    recommendation=(
                        "Verify these paths no longer exist or are not accessible. "
                        "Ensure admin panels, config files, and backups are not publicly reachable."
                    ),
                    tags=["recon", "osint", "sensitive-paths"],
                )
            )
        return findings

    def _whois_lookup(self, target: "Target") -> list[Finding]:
        """Perform a WHOIS lookup via the RDAP protocol."""
        if target.kind.value == "ip":
            return []
        host = target.host
        url = f"https://rdap.org/domain/{host}"
        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as resp:  # noqa: S310
                import json
                data = json.loads(resp.read().decode())
        except Exception:  # noqa: BLE001
            return []

        # Extract key fields
        entities = data.get("entities", [])
        registrar = next(
            (e.get("vcardArray", [[]])[1] for e in entities if "registrar" in e.get("roles", [])),
            None,
        )
        events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}

        evidence = [
            f"Registrar: {registrar[1][3] if registrar and len(registrar) > 1 else 'unknown'}",
            f"Registration: {events.get('registration', 'unknown')}",
            f"Expiration: {events.get('expiration', 'unknown')}",
        ]

        return [
            self._finding(
                title="WHOIS / RDAP Record Retrieved",
                severity=Severity.INFO,
                target=target,
                description=f"Registration information for {host}.",
                evidence=evidence,
                recommendation="Monitor domain expiry dates to prevent domain hijacking.",
                tags=["recon", "whois"],
                raw_data={"rdap": events},
            )
        ]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve(self, host: str) -> bool:
        try:
            socket.getaddrinfo(host, None, socket.AF_INET)
            return True
        except (socket.gaierror, OSError):
            return False

    def _check_port(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except (OSError, ConnectionRefusedError, TimeoutError):
            return False
