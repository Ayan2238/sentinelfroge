"""
Target Manager
~~~~~~~~~~~~~~
Parses, validates, normalises, and scopes scan targets.
Supports domains, IP addresses, CIDR ranges, and URLs.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"
    WILDCARD = "wildcard"


class TargetScope(str, Enum):
    """How far out-of-scope resolution is allowed during scanning."""
    STRICT = "strict"       # Only the exact target
    DOMAIN = "domain"       # Includes all subdomains
    SUBDOMAIN = "subdomain" # Only the listed subdomains
    IP = "ip"               # Single IP
    CIDR = "cidr"           # Whole subnet


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TargetError(Exception):
    """Raised when a target is invalid or out of scope."""


# ---------------------------------------------------------------------------
# Target data-class
# ---------------------------------------------------------------------------


@dataclass
class Target:
    """
    Represents a single validated scan target.

    Attributes
    ----------
    raw:
        The original string the user provided.
    kind:
        Parsed target type (domain, IP, CIDR, URL, wildcard).
    host:
        Canonical hostname or IP address extracted from *raw*.
    port:
        TCP port if explicitly present in a URL; ``None`` otherwise.
    scheme:
        ``"https"`` / ``"http"`` if a URL was given; ``None`` otherwise.
    resolved_ips:
        IPv4/IPv6 addresses resolved at validation time.
    metadata:
        Free-form dict that modules can populate (e.g. OS, headers).
    """

    raw: str
    kind: TargetType
    host: str
    port: int | None = None
    scheme: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------

    @property
    def base_url(self) -> str:
        """Reconstruct a usable base URL from this target."""
        if self.scheme and self.host:
            if self.port:
                return f"{self.scheme}://{self.host}:{self.port}"
            return f"{self.scheme}://{self.host}"
        if self.kind == TargetType.URL and self.scheme:
            return self.raw
        return f"https://{self.host}"

    @property
    def display(self) -> str:
        return self.raw

    def __str__(self) -> str:
        return self.host

    def __repr__(self) -> str:
        return f"<Target {self.kind.value}:{self.host!r}>"


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class TargetManager:
    """
    Parses and validates a list of target strings.

    Parameters
    ----------
    resolve:
        If ``True`` each domain target is resolved to IPs during
        ``validate()``. Set to ``False`` in tests or offline mode.
    """

    # Loose domain regex (FQDN + wildcard)
    _DOMAIN_RE = re.compile(
        r"^(\*\.)?"                          # optional wildcard prefix
        r"([a-zA-Z0-9]"                      # first label char
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"\.)"
        r"+[a-zA-Z]{2,63}$"
    )

    def __init__(self, resolve: bool = True) -> None:
        self._resolve = resolve
        self._targets: list[Target] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, raw: str) -> Target:
        """
        Parse, validate, and register a target.

        Parameters
        ----------
        raw:
            A domain name, IP address, CIDR range, or URL.

        Returns
        -------
        Target
            The validated :class:`Target` object.

        Raises
        ------
        TargetError
            If *raw* is not a recognisable target format.
        """
        raw = raw.strip()
        target = self._parse(raw)
        if self._resolve and target.kind in (TargetType.DOMAIN, TargetType.URL):
            target.resolved_ips = self._resolve_host(target.host)
        self._targets.append(target)
        return target

    def add_many(self, raws: list[str]) -> list[Target]:
        """Add multiple targets, collecting errors rather than aborting."""
        results: list[Target] = []
        errors: list[str] = []
        for raw in raws:
            try:
                results.append(self.add(raw))
            except TargetError as exc:
                errors.append(str(exc))
        if errors:
            raise TargetError(
                f"{len(errors)} target(s) failed validation:\n"
                + "\n".join(f"  • {e}" for e in errors)
            )
        return results

    def validate_scope(self, host: str, scope: TargetScope) -> bool:
        """
        Return ``True`` if *host* is within scope relative to the registered
        targets and the chosen *scope* policy.
        """
        for target in self._targets:
            if scope == TargetScope.STRICT and host == target.host:
                return True
            if scope == TargetScope.DOMAIN and (
                host == target.host or host.endswith(f".{target.host}")
            ):
                return True
            if scope == TargetScope.IP:
                try:
                    ipaddress.ip_address(host)
                    return host in target.resolved_ips
                except ValueError:
                    pass
            if scope == TargetScope.CIDR and target.kind == TargetType.CIDR:
                try:
                    net = ipaddress.ip_network(target.host, strict=False)
                    return ipaddress.ip_address(host) in net
                except ValueError:
                    pass
        return False

    @property
    def targets(self) -> list[Target]:
        return list(self._targets)

    def __iter__(self) -> Iterator[Target]:
        return iter(self._targets)

    def __len__(self) -> int:
        return len(self._targets)

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse(self, raw: str) -> Target:
        # --- URL ---
        if raw.startswith(("http://", "https://")):
            parsed = urlparse(raw)
            host = parsed.hostname or ""
            port = parsed.port
            if not host:
                raise TargetError(f"Cannot extract host from URL: {raw!r}")
            return Target(
                raw=raw,
                kind=TargetType.URL,
                host=host,
                port=port,
                scheme=parsed.scheme,
            )

        # --- CIDR ---
        if "/" in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
                return Target(raw=raw, kind=TargetType.CIDR, host=str(net))
            except ValueError:
                raise TargetError(f"Invalid CIDR notation: {raw!r}")

        # --- IP address ---
        try:
            ip = ipaddress.ip_address(raw)
            return Target(
                raw=raw,
                kind=TargetType.IP,
                host=str(ip),
                resolved_ips=[str(ip)],
            )
        except ValueError:
            pass

        # --- Wildcard / Domain ---
        if self._DOMAIN_RE.match(raw):
            kind = TargetType.WILDCARD if raw.startswith("*.") else TargetType.DOMAIN
            host = raw[2:] if raw.startswith("*.") else raw
            return Target(raw=raw, kind=kind, host=host)

        raise TargetError(
            f"Unrecognised target format: {raw!r}. "
            "Expected a domain, IP, CIDR, or URL."
        )

    @staticmethod
    def _resolve_host(host: str) -> list[str]:
        """Return resolved IP addresses for *host*, empty list on failure."""
        try:
            info = socket.getaddrinfo(host, None)
            return list({addr[4][0] for addr in info})
        except (socket.gaierror, OSError):
            return []
