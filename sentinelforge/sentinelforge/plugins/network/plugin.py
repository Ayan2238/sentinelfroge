"""Network Plugin — service identification and banner intelligence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sentinelforge.core.port_discovery import PortDiscovery, PortDiscoveryConfig
from sentinelforge.core.service_identifier import ServiceIdentifier
from sentinelforge.core.banner_grabber import BannerGrabber
from sentinelforge.core.version_identifier import VersionIdentifier
from sentinelforge.core.protocol_probe import ProtocolProbe
from sentinelforge.modules.base import Severity
from sentinelforge.plugins.base import BasePlugin, PluginResult

if TYPE_CHECKING:
    from sentinelforge.core.target import Target

def _build_ftp_composite_fingerprint(
    version: object,
    protocol: object,
) -> dict:
    """Combine existing FTP observations into one structured fingerprint."""

    data = getattr(protocol, "data", {}) or {}
    session = data.get("session") or {}

    capabilities = session.get("capabilities") or {}
    explicit_tls = session.get("explicit_tls") or {}
    passive_mode = session.get("passive_mode") or {}

    product = getattr(version, "product", "unknown")
    version_value = getattr(version, "version", "unknown")

    fingerprint = {
        "protocol": "ftp",
        "product": product,
        "version": version_value,
        "system_type": (
            (session.get("system") or {}).get("type")
        ),
        "greeting": {
            "code": (session.get("greeting") or {}).get("code"),
            "present": (session.get("greeting") or {}).get("present"),
        },
        "capabilities": {
            "advertised": list(
                capabilities.get("advertised") or []
            ),
            "groups": dict(
                capabilities.get("groups") or {}
            ),
        },
        "passive_mode": {
            "mode": passive_mode.get("mode"),
            "supported": passive_mode.get("supported"),
            "address": passive_mode.get("address"),
            "port": passive_mode.get("port"),
            "address_scope": passive_mode.get("address_scope"),
        },
        "tls": {
            "supported": explicit_tls.get("supported"),
            "handshake": explicit_tls.get("handshake"),
            "version": explicit_tls.get("version"),
            "cipher": explicit_tls.get("cipher"),
        },
        "confidence": {
            "protocol": getattr(protocol, "confidence", 0.0),
            "version": getattr(version, "confidence", 0.0),
        },
        "identification": {
            "protocol_method": getattr(
                protocol,
                "identification_method",
                None,
            ),
            "version_method": getattr(
                version,
                "identification_method",
                None,
            ),
        },
    }

    return fingerprint


def _ftp_security_findings(
    plugin: "NetworkPlugin",
    target: "Target",
    observation: object,
) -> list:
    """Derive conservative FTP security findings from observed probe data."""

    if getattr(observation, "protocol", "") != "ftp":
        return []

    data = getattr(observation, "data", {}) or {}
    session = data.get("session") or {}
    explicit_tls = session.get("explicit_tls") or {}

    findings = []

    tls_supported = explicit_tls.get("supported")
    tls_handshake = explicit_tls.get("handshake")

    if tls_supported is False:
        findings.append(
            plugin._finding(
                title="FTP Explicit TLS Not Accepted",
                severity=Severity.LOW,
                target=target,
                description=(
                    "The FTP server did not accept the AUTH TLS request. "
                    "The control channel therefore remained plaintext during "
                    "the protocol probe."
                ),
                evidence=[
                    evidence
                    for evidence in getattr(observation, "evidence", ())
                    if "AUTH TLS" in evidence or "TLS" in evidence
                ],
                recommendation=(
                    "If FTP must remain available, enable and enforce "
                    "explicit TLS where supported, and avoid transmitting "
                    "credentials or sensitive data over plaintext FTP."
                ),
                tags=[
                    "network",
                    "ftp",
                    "protocol-security",
                    "cleartext",
                ],
                confidence=0.99,
                raw_data={
                    "protocol": "ftp",
                    "security_condition": "explicit_tls_not_accepted",
                    "explicit_tls": explicit_tls,
                    "session": session,
                },
            )
        )

    elif tls_supported is True and tls_handshake is False:
        findings.append(
            plugin._finding(
                title="FTP Explicit TLS Handshake Failed",
                severity=Severity.LOW,
                target=target,
                description=(
                    "The FTP server accepted the AUTH TLS request, but the "
                    "subsequent TLS handshake did not complete successfully."
                ),
                evidence=[
                    evidence
                    for evidence in getattr(observation, "evidence", ())
                    if "AUTH TLS" in evidence
                    or "TLS handshake" in evidence
                    or "TLS negotiation" in evidence
                ],
                recommendation=(
                    "Verify the FTP server's TLS configuration and confirm "
                    "that explicit TLS negotiation completes successfully."
                ),
                tags=[
                    "network",
                    "ftp",
                    "protocol-security",
                    "tls",
                ],
                confidence=0.95,
                raw_data={
                    "protocol": "ftp",
                    "security_condition": "explicit_tls_handshake_failed",
                    "explicit_tls": explicit_tls,
                    "session": session,
                },
            )
        )

    return findings


def _smtp_security_findings(
    plugin: "NetworkPlugin",
    target: "Target",
    observation: object,
) -> list:
    """Derive conservative SMTP security findings from observed probe data."""

    if getattr(observation, "protocol", "") != "smtp":
        return []

    data = getattr(observation, "data", {}) or {}
    starttls = data.get("starttls") or {}
    auth = data.get("auth") or {}
    tls = data.get("tls") or {}
    fingerprint = data.get("fingerprint") or {}
    tls_capability_comparison = data.get("tls_capability_comparison") or {}
    findings = []

    certificate = starttls.get("certificate_analysis") or {}
    validity = certificate.get("validity") or {}
    security = certificate.get("security") or {}

    validity_state = (
        certificate.get("validity_state")
        or validity.get("state")
        or "unknown"
    )

    self_signed = certificate.get("self_signed")

    hostname_state = (
        certificate.get("hostname_state")
        or "unknown"
    )

    signature_algorithm = (
        security.get("signature_algorithm")
        or certificate.get("signature_algorithm")
        or ""
    )

    public_key_algorithm = (
        security.get("public_key_algorithm")
        or certificate.get("public_key_algorithm")
        or ""
    )

    public_key_bits = (
        security.get("public_key_bits")
        or certificate.get("public_key_bits")
    )

    certificate_raw_data = {
        "protocol": "smtp",
        "security_condition": None,
        "certificate_analysis": certificate,
        "starttls": starttls,
        "fingerprint": fingerprint,
    }

    if certificate:
        if validity_state == "expired":
            raw_data = dict(certificate_raw_data)
            raw_data["security_condition"] = "expired_certificate"
            findings.append(
                plugin._finding(
                    title="SMTP TLS Certificate Expired",
                    severity=Severity.HIGH,
                    target=target,
                    description=(
                        "The SMTP TLS certificate is expired and is no "
                        "longer within its validity period."
                    ),
                    evidence=[
                        "Certificate validity state: expired",
                        f"Certificate subject: "
                        f"{certificate.get('subject') or 'unknown'}",
                        f"Certificate expiry: "
                        f"{certificate.get('not_after') or validity.get('not_after') or 'unknown'}",
                    ],
                    recommendation=(
                        "Replace the expired certificate with a currently "
                        "valid certificate from a trusted certificate "
                        "authority."
                    ),
                    tags=[
                        "network",
                        "smtp",
                        "protocol-security",
                        "tls",
                        "certificate",
                        "expired",
                    ],
                    confidence=0.99,
                    raw_data=raw_data,
                )
            )

        elif validity_state == "not_yet_valid":
            raw_data = dict(certificate_raw_data)
            raw_data["security_condition"] = "not_yet_valid_certificate"
            findings.append(
                plugin._finding(
                    title="SMTP TLS Certificate Not Yet Valid",
                    severity=Severity.HIGH,
                    target=target,
                    description=(
                        "The SMTP TLS certificate is not yet within its "
                        "validity period."
                    ),
                    evidence=[
                        "Certificate validity state: not_yet_valid",
                        f"Certificate subject: "
                        f"{certificate.get('subject') or 'unknown'}",
                        f"Certificate valid from: "
                        f"{certificate.get('not_before') or validity.get('not_before') or 'unknown'}",
                    ],
                    recommendation=(
                        "Install a certificate whose validity period "
                        "includes the current time."
                    ),
                    tags=[
                        "network",
                        "smtp",
                        "protocol-security",
                        "tls",
                        "certificate",
                        "not-yet-valid",
                    ],
                    confidence=0.99,
                    raw_data=raw_data,
                )
            )

        if self_signed is True:
            raw_data = dict(certificate_raw_data)
            raw_data["security_condition"] = "self_signed_certificate"
            findings.append(
                plugin._finding(
                    title="SMTP TLS Certificate Self-Signed",
                    severity=Severity.MEDIUM,
                    target=target,
                    description=(
                        "The SMTP TLS certificate is self-signed rather "
                        "than issued by a separate certificate authority."
                    ),
                    evidence=[
                        "Certificate self-signed state: true",
                        f"Certificate subject: "
                        f"{certificate.get('subject') or 'unknown'}",
                        f"Certificate issuer: "
                        f"{certificate.get('issuer') or 'unknown'}",
                    ],
                    recommendation=(
                        "Use a certificate issued by a trusted certificate "
                        "authority unless a deliberately managed private "
                        "PKI is required."
                    ),
                    tags=[
                        "network",
                        "smtp",
                        "protocol-security",
                        "tls",
                        "certificate",
                        "self-signed",
                    ],
                    confidence=0.99,
                    raw_data=raw_data,
                )
            )

        if hostname_state == "mismatch":
            raw_data = dict(certificate_raw_data)
            raw_data["security_condition"] = "hostname_mismatch"
            findings.append(
                plugin._finding(
                    title="SMTP TLS Certificate Hostname Mismatch",
                    severity=Severity.HIGH,
                    target=target,
                    description=(
                        "The SMTP TLS certificate does not match the "
                        "assessed SMTP hostname."
                    ),
                    evidence=[
                        f"Assessed hostname: {target}",
                        "Certificate hostname state: mismatch",
                        f"Certificate SANs: "
                        f"{', '.join(map(str, certificate.get('san') or [])) or 'none'}",
                    ],
                    recommendation=(
                        "Install a certificate whose subject alternative "
                        "names cover the SMTP hostname used by clients."
                    ),
                    tags=[
                        "network",
                        "smtp",
                        "protocol-security",
                        "tls",
                        "certificate",
                        "hostname-mismatch",
                    ],
                    confidence=0.99,
                    raw_data=raw_data,
                )
            )

        if public_key_bits is not None:
            try:
                key_bits = int(public_key_bits)
            except (TypeError, ValueError):
                key_bits = None
        else:
            key_bits = None

        weak_key = False
        if key_bits is not None:
            algorithm = public_key_algorithm.upper()
            if algorithm in {"RSA", "DSA"} and key_bits < 2048:
                weak_key = True
            elif algorithm in {"EC", "ECDSA"} and key_bits < 256:
                weak_key = True

        if weak_key:
            raw_data = dict(certificate_raw_data)
            raw_data["security_condition"] = "weak_certificate_key"
            findings.append(
                plugin._finding(
                    title="SMTP TLS Certificate Weak Key",
                    severity=Severity.HIGH,
                    target=target,
                    description=(
                        f"The SMTP TLS certificate uses a {public_key_algorithm or 'unknown'} "
                        f"public key of only {key_bits} bits."
                    ),
                    evidence=[
                        f"Public key algorithm: "
                        f"{public_key_algorithm or 'unknown'}",
                        f"Public key size: {key_bits} bits",
                    ],
                    recommendation=(
                        "Replace the certificate with a sufficiently strong "
                        "public key; use at least RSA/DSA 2048-bit or an "
                        "appropriately sized modern elliptic-curve key."
                    ),
                    tags=[
                        "network",
                        "smtp",
                        "protocol-security",
                        "tls",
                        "certificate",
                        "weak-key",
                    ],
                    confidence=0.99,
                    raw_data=raw_data,
                )
            )

        signature_upper = signature_algorithm.upper()
        weak_signature = (
            "SHA1" in signature_upper
            or "SHA-1" in signature_upper
            or "MD5" in signature_upper
        )

        if weak_signature:
            raw_data = dict(certificate_raw_data)
            raw_data["security_condition"] = "weak_certificate_signature"
            findings.append(
                plugin._finding(
                    title="SMTP TLS Certificate Weak Signature",
                    severity=Severity.HIGH,
                    target=target,
                    description=(
                        f"The SMTP TLS certificate uses the weak signature "
                        f"algorithm {signature_algorithm}."
                    ),
                    evidence=[
                        f"Certificate signature algorithm: "
                        f"{signature_algorithm}"
                    ],
                    recommendation=(
                        "Replace the certificate with one signed using a "
                        "modern secure signature algorithm such as SHA-256 "
                        "or stronger."
                    ),
                    tags=[
                        "network",
                        "smtp",
                        "protocol-security",
                        "tls",
                        "certificate",
                        "weak-signature",
                    ],
                    confidence=0.99,
                    raw_data=raw_data,
                )
            )



    tls_security = starttls.get("tls_security") or {}
    tls_version_info = tls_security.get("version") or {}
    tls_cipher_info = tls_security.get("cipher") or {}

    tls_version_classification = tls_version_info.get("classification")
    tls_cipher_classification = tls_cipher_info.get("classification")

    if tls_version_classification == "obsolete":
        findings.append(
            plugin._finding(
                title="SMTP Obsolete TLS Version",
                severity=Severity.HIGH,
                target=target,
                description=(
                    f"The SMTP service negotiated obsolete TLS version "
                    f"{tls_version_info.get('value') or 'unknown'}."
                ),
                evidence=[
                    f"Negotiated TLS version: "
                    f"{tls_version_info.get('value') or 'unknown'}"
                ],
                recommendation=(
                    "Disable obsolete SSL/TLS protocol versions and require "
                    "TLS 1.2 or newer, preferably TLS 1.3."
                ),
                tags=[
                    "network",
                    "smtp",
                    "protocol-security",
                    "tls",
                    "obsolete",
                ],
                confidence=0.99,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "obsolete_tls_version",
                    "tls_security": tls_security,
                    "starttls": starttls,
                    "fingerprint": fingerprint,
                },
            )
        )

    elif tls_version_classification == "legacy":
        findings.append(
            plugin._finding(
                title="SMTP Legacy TLS Version",
                severity=Severity.MEDIUM,
                target=target,
                description=(
                    f"The SMTP service negotiated legacy TLS version "
                    f"{tls_version_info.get('value') or 'unknown'}."
                ),
                evidence=[
                    f"Negotiated TLS version: "
                    f"{tls_version_info.get('value') or 'unknown'}"
                ],
                recommendation=(
                    "Disable legacy TLS protocol versions and require "
                    "TLS 1.2 or newer."
                ),
                tags=[
                    "network",
                    "smtp",
                    "protocol-security",
                    "tls",
                    "legacy",
                ],
                confidence=0.99,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "legacy_tls_version",
                    "tls_security": tls_security,
                    "starttls": starttls,
                    "fingerprint": fingerprint,
                },
            )
        )

    if tls_cipher_classification == "weak":
        findings.append(
            plugin._finding(
                title="SMTP Weak TLS Cipher",
                severity=Severity.MEDIUM,
                target=target,
                description=(
                    f"The SMTP service negotiated weak TLS cipher "
                    f"{tls_cipher_info.get('name') or 'unknown'}."
                ),
                evidence=[
                    f"Negotiated TLS cipher: "
                    f"{tls_cipher_info.get('name') or 'unknown'}"
                ],
                recommendation=(
                    "Disable weak and legacy cipher suites and prefer "
                    "modern authenticated encryption such as AES-GCM or "
                    "ChaCha20-Poly1305."
                ),
                tags=[
                    "network",
                    "smtp",
                    "protocol-security",
                    "tls",
                    "weak-cipher",
                ],
                confidence=0.99,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "weak_tls_cipher",
                    "tls_security": tls_security,
                    "starttls": starttls,
                    "fingerprint": fingerprint,
                },
            )
        )

    capabilities = {
        str(item).upper()
        for item in data.get("capabilities", [])
    }

    auth_added_after_tls = list(
        tls_capability_comparison.get("auth_added_after_tls") or []
    )
    auth_removed_after_tls = list(
        tls_capability_comparison.get("auth_removed_after_tls") or []
    )

    if auth_removed_after_tls:
        findings.append(
            plugin._finding(
                title="SMTP AUTH Mechanisms Changed After TLS",
                severity=Severity.LOW,
                target=target,
                description=(
                    "The SMTP service advertised a different AUTH mechanism "
                    "set after TLS negotiation."
                ),
                evidence=[
                    f"AUTH mechanisms removed after TLS: "
                    f"{', '.join(auth_removed_after_tls)}",
                    (
                        "AUTH mechanisms added after TLS: "
                        f"{', '.join(auth_added_after_tls) or 'none'}"
                    ),
                ],
                recommendation=(
                    "Review the pre-TLS and post-TLS SMTP authentication "
                    "policies and ensure the change is intentional."
                ),
                tags=[
                    "network",
                    "smtp",
                    "authentication",
                    "tls",
                    "capability-change",
                ],
                confidence=0.95,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "auth_changed_after_tls",
                    "tls_capability_comparison": tls_capability_comparison,
                    "fingerprint": fingerprint,
                },
            )
        )

    advertised = bool(starttls.get("advertised"))
    accepted = starttls.get("accepted")
    handshake = starttls.get("handshake")
    tls_active = bool(
        data.get("implicit_tls")
        or tls.get("handshake")
        or handshake is True
    )

    if not advertised and not data.get("implicit_tls"):
        findings.append(
            plugin._finding(
                title="SMTP STARTTLS Not Advertised",
                severity=Severity.MEDIUM,
                target=target,
                description=(
                    "The SMTP service did not advertise STARTTLS and was "
                    "not identified as an implicit-TLS service. The SMTP "
                    "control channel therefore does not provide an observed "
                    "upgrade path to TLS."
                ),
                evidence=[
                    evidence
                    for evidence in getattr(observation, "evidence", ())
                    if "STARTTLS" in evidence.upper()
                    or "SMTP EHLO" in evidence
                ],
                recommendation=(
                    "Enable STARTTLS for SMTP services where encrypted "
                    "transport is required, and configure clients to require "
                    "TLS when transmitting credentials or sensitive mail."
                ),
                tags=[
                    "network",
                    "smtp",
                    "protocol-security",
                    "tls",
                ],
                confidence=0.95,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "starttls_not_advertised",
                    "capabilities": sorted(capabilities),
                    "starttls": starttls,
                    "tls": tls,
                    "fingerprint": fingerprint,
                },
            )
        )

    if advertised and accepted is False:
        findings.append(
            plugin._finding(
                title="SMTP STARTTLS Rejected",
                severity=Severity.MEDIUM,
                target=target,
                description=(
                    "The SMTP service advertised STARTTLS but rejected the "
                    "STARTTLS command during protocol negotiation."
                ),
                evidence=[
                    evidence
                    for evidence in getattr(observation, "evidence", ())
                    if "STARTTLS" in evidence.upper()
                ],
                recommendation=(
                    "Investigate the SMTP TLS configuration and ensure that "
                    "STARTTLS negotiation succeeds when TLS is advertised."
                ),
                tags=[
                    "network",
                    "smtp",
                    "protocol-security",
                    "tls",
                ],
                confidence=0.99,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "starttls_rejected",
                    "starttls": starttls,
                    "fingerprint": fingerprint,
                },
            )
        )

    if advertised and accepted is True and handshake is False:
        findings.append(
            plugin._finding(
                title="SMTP STARTTLS Handshake Failed",
                severity=Severity.MEDIUM,
                target=target,
                description=(
                    "The SMTP service accepted STARTTLS, but the subsequent "
                    "TLS handshake did not complete successfully."
                ),
                evidence=[
                    evidence
                    for evidence in getattr(observation, "evidence", ())
                    if "STARTTLS" in evidence.upper()
                    or "TLS handshake" in evidence
                    or "TLS negotiation" in evidence
                ],
                recommendation=(
                    "Verify the SMTP server certificate and TLS configuration "
                    "and confirm that STARTTLS negotiation completes "
                    "successfully."
                ),
                tags=[
                    "network",
                    "smtp",
                    "protocol-security",
                    "tls",
                ],
                confidence=0.98,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "starttls_handshake_failed",
                    "starttls": starttls,
                    "fingerprint": fingerprint,
                },
            )
        )

    mechanisms = [
        str(item).upper()
        for item in auth.get("mechanisms", [])
    ]
    mechanism_classes = auth.get("mechanism_classes") or {}
    cleartext = [
        mechanism
        for mechanism in mechanisms
        if mechanism in {"PLAIN", "LOGIN"}
    ]
    legacy = [
        mechanism
        for mechanism in mechanisms
        if mechanism in {"NTLM", "GSSAPI", "XOAUTH", "XOAUTH2"}
    ]

    if cleartext and not tls_active:
        findings.append(
            plugin._finding(
                title="SMTP Cleartext Authentication Advertised",
                severity=Severity.MEDIUM,
                target=target,
                description=(
                    "The SMTP service advertises authentication mechanisms "
                    "that can expose credentials without a protected TLS "
                    "session when used over plaintext transport."
                ),
                evidence=[
                    f"Advertised SMTP AUTH mechanisms: {', '.join(cleartext)}"
                ],
                recommendation=(
                    "Require TLS before authentication and avoid permitting "
                    "credential-based SMTP AUTH over plaintext connections."
                ),
                tags=[
                    "network",
                    "smtp",
                    "authentication",
                    "cleartext",
                ],
                confidence=0.95,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "cleartext_auth_advertised",
                    "mechanisms": mechanisms,
                    "mechanism_classes": mechanism_classes,
                    "tls_active": tls_active,
                },
            )
        )

    if legacy:
        findings.append(
            plugin._finding(
                title="SMTP Legacy Authentication Mechanism Advertised",
                severity=Severity.LOW,
                target=target,
                description=(
                    "The SMTP service advertises legacy or compatibility "
                    "authentication mechanisms that may increase the "
                    "authentication attack surface."
                ),
                evidence=[
                    f"Advertised SMTP AUTH mechanisms: {', '.join(legacy)}"
                ],
                recommendation=(
                    "Review whether the advertised legacy authentication "
                    "mechanisms are required and disable unnecessary methods."
                ),
                tags=[
                    "network",
                    "smtp",
                    "authentication",
                    "legacy",
                ],
                confidence=0.90,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "legacy_auth_advertised",
                    "mechanisms": mechanisms,
                    "mechanism_classes": mechanism_classes,
                },
            )
        )

    if (
        starttls.get("accepted") is True
        and starttls.get("handshake") is True
        and not starttls.get("tls_version")
    ):
        findings.append(
            plugin._finding(
                title="SMTP TLS Metadata Incomplete",
                severity=Severity.LOW,
                target=target,
                description=(
                    "The SMTP STARTTLS exchange was reported as successful, "
                    "but the resulting TLS version was not recorded."
                ),
                evidence=[
                    evidence
                    for evidence in getattr(observation, "evidence", ())
                    if "TLS" in evidence.upper()
                ],
                recommendation=(
                    "Verify TLS negotiation and ensure the scanner records "
                    "the negotiated TLS parameters for reliable assessment."
                ),
                tags=[
                    "network",
                    "smtp",
                    "tls",
                    "evidence-quality",
                ],
                confidence=0.90,
                raw_data={
                    "protocol": "smtp",
                    "security_condition": "tls_metadata_incomplete",
                    "starttls": starttls,
                    "tls": tls,
                },
            )
        )

    post_tls_identity = (
        data.get("post_tls_identity_consistency") or {}
    )
    post_tls_anomalies = post_tls_identity.get("anomalies") or []

    for anomaly in post_tls_anomalies:
        code = anomaly.get("code")

        if code == "smtp_post_tls_hostname_mismatch":
            findings.append(
                plugin._finding(
                    title="SMTP Post-TLS Hostname Mismatch",
                    severity=Severity.LOW,
                    target=target,
                    description=(
                        "The SMTP service presented a different hostname "
                        "after TLS negotiation than it presented before TLS."
                    ),
                    evidence=list(anomaly.get("evidence") or []),
                    recommendation=(
                        "Investigate the SMTP TLS termination and server "
                        "identity configuration to ensure the same expected "
                        "service identity is presented before and after TLS."
                    ),
                    tags=[
                        "network",
                        "smtp",
                        "protocol-security",
                        "tls",
                        "identity",
                    ],
                    confidence=float(anomaly.get("confidence", 0.90)),
                    raw_data={
                        "protocol": "smtp",
                        "security_condition": code,
                        "post_tls_identity_consistency": post_tls_identity,
                        "starttls": starttls,
                        "fingerprint": fingerprint,
                    },
                )
            )

        elif code == "smtp_post_tls_ehlo_rejected":
            findings.append(
                plugin._finding(
                    title="SMTP Post-TLS EHLO Rejected",
                    severity=Severity.LOW,
                    target=target,
                    description=(
                        "The SMTP service successfully negotiated TLS but "
                        "rejected the subsequent EHLO command."
                    ),
                    evidence=list(anomaly.get("evidence") or []),
                    recommendation=(
                        "Investigate the SMTP server's post-TLS protocol "
                        "state and configuration to ensure normal ESMTP "
                        "capability negotiation remains available after TLS."
                    ),
                    tags=[
                        "network",
                        "smtp",
                        "protocol-security",
                        "tls",
                        "protocol-anomaly",
                    ],
                    confidence=float(anomaly.get("confidence", 0.95)),
                    raw_data={
                        "protocol": "smtp",
                        "security_condition": code,
                        "post_tls_identity_consistency": post_tls_identity,
                        "starttls": starttls,
                        "fingerprint": fingerprint,
                    },
                )
            )

    return findings


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

        protocol_probe = ProtocolProbe(
            self._config,
            timeout=config.timeout,
        )
        protocol_observations = [
            protocol_probe.probe(
                target.host,
                service.address,
                service.address_family,
                service.port,
                service.service,
                service.transport,
            )
            for service in services
        ]
        protocol_by_key = {
            (observation.address, observation.port, observation.transport): observation
            for observation in protocol_observations
        }

        for service in services:
            key = (service.address, service.port, service.transport)
            banner = banner_by_key.get(key)
            version = version_by_key.get(key)
            protocol = protocol_by_key.get(key)

            ftp_fingerprint = None
            if (
                protocol is not None
                and getattr(protocol, "protocol", "") == "ftp"
                and version is not None
            ):
                ftp_fingerprint = _build_ftp_composite_fingerprint(
                    version,
                    protocol,
                )

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

            if protocol is not None:
                evidence.extend(protocol.evidence)

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
                        **(
                            {
                                "protocol": protocol.protocol,
                                "protocol_success": protocol.success,
                                "protocol_confidence": protocol.confidence,
                                "protocol_identification_method": (
                                    protocol.identification_method
                                ),
                                "protocol_data": protocol.data,
                                "protocol_error": protocol.error,
                            }
                            if protocol is not None
                            else {}
                        ),
                        **(
                            {
                                "ftp_fingerprint": ftp_fingerprint,
                            }
                            if ftp_fingerprint is not None
                            else {}
                        ),
                    },
                )
            )

            if protocol is not None:
                for security_finding in _ftp_security_findings(
                    self,
                    target,
                    protocol,
                ):
                    result.add_finding(security_finding)

                for security_finding in _smtp_security_findings(
                    self,
                    target,
                    protocol,
                ):
                    result.add_finding(security_finding)

        result.metadata["ports_scanned"] = discovery.ports_scanned
        result.metadata["open_ports"] = list(discovery.open_ports)
        result.metadata["services_identified"] = len(services)
        result.metadata["versions_identified"] = sum(
            1
            for version in versions
            if version.product != "unknown"
            and version.version != "unknown"
        )
        result.metadata["protocols_probed"] = sum(
            1
            for observation in protocol_observations
            if observation.success
        )

        result.status = "success"
        return result
