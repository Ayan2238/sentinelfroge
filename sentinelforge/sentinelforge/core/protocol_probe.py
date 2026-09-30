"""
Shared protocol probing.

Provides structured, bounded protocol observations for services discovered
by SentinelForge. This layer performs protocol identification and lightweight
handshakes; security-specific checks remain in their existing plugins.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from dataclasses import dataclass, field
from typing import Any

from sentinelforge.core.network import ssl_context


@dataclass(frozen=True)
class ProtocolObservation:
    """Structured result from a protocol probe."""

    target: str
    address: str
    address_family: str
    port: int
    transport: str
    protocol: str
    success: bool
    identification_method: str
    confidence: float
    timestamp: str
    data: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[str, ...] = ()
    error: str | None = None


class ProtocolProbe:
    """
    Lightweight protocol probe dispatcher.

    The probe is intentionally non-destructive. It performs only protocol
    handshakes and bounded metadata/body reads.
    """

    def __init__(
        self,
        config: object | None = None,
        *,
        timeout: float = 2.0,
        max_body_bytes: int = 8192,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")

        self._config = config
        self._timeout = float(timeout)
        self._max_body_bytes = int(max_body_bytes)

    def probe(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
        service: str,
        transport: str = "tcp",
    ) -> ProtocolObservation:
        """Probe a discovered service and return a structured observation."""

        if transport.lower() != "tcp":
            return self._unsupported(
                target,
                address,
                address_family,
                port,
                transport,
                "Only TCP protocol probes are currently implemented.",
            )

        service_name = (service or "unknown").lower()

        if service_name == "ssh" or port in {22, 2222}:
            return self._probe_ssh(
                target,
                address,
                address_family,
                port,
            )

        if service_name in {"http", "https"}:
            return self._probe_http(
                target,
                address,
                address_family,
                port,
                https=service_name == "https",
            )

        if port in {80, 8080, 8000, 8008, 8081, 8888}:
            return self._probe_http(
                target,
                address,
                address_family,
                port,
                https=False,
            )

        if port in {443, 8443, 9443}:
            return self._probe_http(
                target,
                address,
                address_family,
                port,
                https=True,
            )

        return self._unsupported(
            target,
            address,
            address_family,
            port,
            transport,
            f"No protocol probe is registered for service '{service}'.",
        )

    def _probe_http(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
        *,
        https: bool,
    ) -> ProtocolObservation:
        scheme = "https" if https else "http"
        url = f"{scheme}://{self._format_host(address, address_family)}:{port}/"

        request = urllib.request.Request(
            url,
            method="HEAD",
            headers={
                "User-Agent": "SentinelForge/1.0 ProtocolProbe",
                "Accept": "*/*",
                "Connection": "close",
            },
        )

        try:
            context = None
            if https and self._config is not None:
                context = ssl_context(self._config)

            if context is None:
                response = urllib.request.urlopen(
                    request,
                    timeout=self._timeout,
                )
            else:
                response = urllib.request.urlopen(
                    request,
                    timeout=self._timeout,
                    context=context,
                )

            try:
                headers = {
                    str(key).lower(): str(value)
                    for key, value in response.headers.items()
                }

                status = int(response.status)
                http_version = getattr(response, "version", None)

                data: dict[str, Any] = {
                    "scheme": scheme,
                    "status_code": status,
                    "http_version": self._http_version(http_version),
                    "server": headers.get("server"),
                    "content_type": headers.get("content-type"),
                    "content_length": headers.get("content-length"),
                    "location": headers.get("location"),
                    "headers": headers,
                }

                if https:
                    tls_info = self._tls_metadata(response)
                    data["tls"] = tls_info

                evidence = [
                    f"{scheme.upper()} responded with HTTP "
                    f"{status}"
                ]

                if data["server"]:
                    evidence.append(
                        f"Server header: {data['server']}"
                    )

                if data["content_type"]:
                    evidence.append(
                        f"Content-Type: {data['content_type']}"
                    )

                if data["location"]:
                    evidence.append(
                        f"Location: {data['location']}"
                    )

                if https:
                    evidence.append("Protocol confirmed as HTTPS/TLS")

                    tls_info = data.get("tls", {})
                    if tls_info.get("version"):
                        evidence.append(
                            f"TLS version: {tls_info['version']}"
                        )
                    if tls_info.get("cipher"):
                        evidence.append(
                            f"TLS cipher: {tls_info['cipher']}"
                        )
                    if tls_info.get("certificate_subject"):
                        evidence.append(
                            f"Certificate subject: "
                            f"{tls_info['certificate_subject']}"
                        )
                    if tls_info.get("certificate_issuer"):
                        evidence.append(
                            f"Certificate issuer: "
                            f"{tls_info['certificate_issuer']}"
                        )

                return ProtocolObservation(
                    target=target,
                    address=address,
                    address_family=address_family,
                    port=port,
                    transport="tcp",
                    protocol=scheme,
                    success=True,
                    identification_method="http_head",
                    confidence=0.99,
                    timestamp=self._timestamp(),
                    data=data,
                    evidence=tuple(evidence),
                )
            finally:
                response.close()

        except urllib.error.HTTPError as exc:
            headers = {
                str(key).lower(): str(value)
                for key, value in exc.headers.items()
            }

            data = {
                "scheme": scheme,
                "status_code": int(exc.code),
                "http_version": None,
                "server": headers.get("server"),
                "content_type": headers.get("content-type"),
                "content_length": headers.get("content-length"),
                "location": headers.get("location"),
                "headers": headers,
            }

            evidence = [
                f"{scheme.upper()} responded with HTTP {exc.code}"
            ]

            if headers.get("server"):
                evidence.append(
                    f"Server header: {headers['server']}"
                )

            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol=scheme,
                success=True,
                identification_method="http_head_error_response",
                confidence=0.99,
                timestamp=self._timestamp(),
                data=data,
                evidence=tuple(evidence),
            )

        except ssl.SSLError as exc:
            return self._error_observation(
                target,
                address,
                address_family,
                port,
                scheme,
                "tls_error",
                exc,
            )

        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            return self._error_observation(
                target,
                address,
                address_family,
                port,
                scheme,
                "connection_failed",
                exc,
            )

        except OSError as exc:
            return self._error_observation(
                target,
                address,
                address_family,
                port,
                scheme,
                "socket_error",
                exc,
            )

    def _probe_ssh(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
    ) -> ProtocolObservation:
        """Perform bounded SSH identification and algorithm negotiation."""

        family = (
            socket.AF_INET6
            if address_family.lower() in {"ipv6", "af_inet6"}
            else socket.AF_INET
        )

        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)

        try:
            sock.connect((address, port))

            banner = self._recv_ssh_banner(sock)
            if not banner:
                return ProtocolObservation(
                    target=target,
                    address=address,
                    address_family=address_family,
                    port=port,
                    transport="tcp",
                    protocol="unknown",
                    success=False,
                    identification_method="ssh_banner_missing",
                    confidence=0.0,
                    timestamp=self._timestamp(),
                    data={},
                    evidence=(
                        "TCP connection succeeded but no SSH "
                        "identification string was received.",
                    ),
                    error="Missing SSH identification string",
                )

            protocol_version, software = self._parse_ssh_banner(banner)

            data: dict[str, Any] = {
                "banner": banner,
                "protocol_version": protocol_version,
                "software": software,
                "algorithm_negotiation": None,
            }

            evidence = [
                "Protocol confirmed as SSH",
                f"SSH identification string: {banner}",
            ]

            if protocol_version:
                evidence.append(
                    f"SSH protocol version: {protocol_version}"
                )

            if software:
                evidence.append(
                    f"SSH software identification: {software}"
                )

            sock.sendall(b"SSH-2.0-SentinelForge_1.0\r\n")

            negotiation = self._ssh_algorithm_negotiation(sock)
            if negotiation is not None:
                data["algorithm_negotiation"] = negotiation

                for key, label in (
                    ("kex_algorithms", "KEX algorithms"),
                    ("server_host_key_algorithms", "server host-key algorithms"),
                    (
                        "encryption_algorithms_client_to_server",
                        "encryption algorithms client-to-server",
                    ),
                    (
                        "encryption_algorithms_server_to_client",
                        "encryption algorithms server-to-client",
                    ),
                    (
                        "mac_algorithms_client_to_server",
                        "MAC algorithms client-to-server",
                    ),
                    (
                        "mac_algorithms_server_to_client",
                        "MAC algorithms server-to-client",
                    ),
                    (
                        "compression_algorithms_client_to_server",
                        "compression algorithms client-to-server",
                    ),
                    (
                        "compression_algorithms_server_to_client",
                        "compression algorithms server-to-client",
                    ),
                ):
                    values = negotiation.get(key)
                    if values:
                        evidence.append(
                            f"{label}: {', '.join(values)}"
                        )

            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol="ssh",
                success=True,
                identification_method="ssh_banner_and_algorithm_negotiation",
                confidence=0.99,
                timestamp=self._timestamp(),
                data=data,
                evidence=tuple(evidence),
            )

        except (TimeoutError, ConnectionResetError, OSError, ValueError) as exc:
            return self._error_observation(
                target,
                address,
                address_family,
                port,
                "ssh",
                "connection_failed",
                exc,
            )
        finally:
            sock.close()

    def _recv_ssh_banner(self, sock: socket.socket) -> str | None:
        """Receive only the bounded SSH identification exchange."""

        data = bytearray()

        while len(data) < 1024:
            chunk = sock.recv(min(256, 1024 - len(data)))

            if not chunk:
                break

            data.extend(chunk)

            if b"\n" in data:
                break

        text = bytes(data).decode("utf-8", errors="replace")

        for line in text.splitlines():
            line = line.strip()
            if line.startswith("SSH-"):
                return line[:1024]

        return None

    @staticmethod
    def _parse_ssh_banner(
        banner: str,
    ) -> tuple[str | None, str | None]:
        parts = banner.split("-", 2)

        protocol_version = (
            parts[1]
            if len(parts) > 1 and parts[1]
            else None
        )

        software = (
            parts[2]
            if len(parts) > 2 and parts[2]
            else None
        )

        return protocol_version, software

    def _ssh_algorithm_negotiation(
        self,
        sock: socket.socket,
    ) -> dict[str, Any] | None:
        """
        Parse the server SSH_MSG_KEXINIT packet.

        The server sends SSH_MSG_KEXINIT immediately after the SSH version
        exchange. This probe only reads and parses that advertisement; it
        does not authenticate, execute commands, or attempt credentials.
        """

        import struct

        try:
            header = self._recv_exact(sock, 5)
            if header is None:
                return None

            packet_length, padding_length = struct.unpack(
                ">IB",
                header,
            )

            if packet_length < 16 or packet_length > 65536:
                return None

            if padding_length < 4 or padding_length >= packet_length:
                return None

            remaining = packet_length - 1
            packet_body = self._recv_exact(sock, remaining)

            if packet_body is None:
                return None

            payload_length = packet_length - padding_length - 1

            if payload_length < 1 or payload_length > len(packet_body):
                return None

            server_payload = packet_body[:payload_length]

            if not server_payload:
                return None

            message_type = server_payload[0]

            if message_type != 20:
                return {
                    "message_type": message_type,
                    "negotiation_complete": False,
                }

            if len(server_payload) < 17:
                return None

            offset = 1 + 16

            fields = [
                "kex_algorithms",
                "server_host_key_algorithms",
                "encryption_algorithms_client_to_server",
                "encryption_algorithms_server_to_client",
                "mac_algorithms_client_to_server",
                "mac_algorithms_server_to_client",
                "compression_algorithms_client_to_server",
                "compression_algorithms_server_to_client",
                "languages_client_to_server",
                "languages_server_to_client",
            ]

            result: dict[str, Any] = {
                "message_type": 20,
                "negotiation_complete": True,
            }

            for field_name in fields:
                if offset + 4 > len(server_payload):
                    return None

                length = struct.unpack(
                    ">I",
                    server_payload[offset:offset + 4],
                )[0]
                offset += 4

                if length > 65536:
                    return None

                if offset + length > len(server_payload):
                    return None

                value = server_payload[offset:offset + length]
                offset += length

                result[field_name] = (
                    value.decode(
                        "ascii",
                        errors="replace",
                    ).split(",")
                    if value
                    else []
                )

            if offset >= len(server_payload):
                return None

            result["first_kex_follows"] = bool(
                server_payload[offset]
            )
            offset += 1

            if offset + 4 > len(server_payload):
                return None

            result["reserved"] = struct.unpack(
                ">I",
                server_payload[offset:offset + 4],
            )[0]

            return result

        except (
            OSError,
            TimeoutError,
            ValueError,
            TypeError,
            struct.error,
        ):
            return None

    @staticmethod
    def _recv_exact(
        sock: socket.socket,
        size: int,
    ) -> bytes | None:
        data = bytearray()

        while len(data) < size:
            chunk = sock.recv(size - len(data))

            if not chunk:
                return None

            data.extend(chunk)

        return bytes(data)

    @staticmethod
    def _tls_metadata(response: Any) -> dict[str, Any]:
        """Extract TLS connection and peer-certificate metadata."""

        result: dict[str, Any] = {
            "version": None,
            "cipher": None,
            "certificate_sha256": None,
            "certificate_subject": None,
            "certificate_issuer": None,
            "certificate_serial": None,
            "certificate_not_before": None,
            "certificate_not_after": None,
            "certificate_sans": [],
            "public_key_type": None,
            "public_key_size": None,
            "signature_hash": None,
        }

        try:
            sock = getattr(response, "fp", None)
            sock = getattr(sock, "raw", None)
            sock = getattr(sock, "_sock", None)

            if sock is None:
                return result

            result["version"] = sock.version()

            cipher = sock.cipher()
            if cipher:
                result["cipher"] = cipher[0]

            der_cert = sock.getpeercert(binary_form=True)
            if not der_cert:
                return result

            result["certificate_sha256"] = (
                __import__("hashlib")
                .sha256(der_cert)
                .hexdigest()
            )

            cert = x509.load_der_x509_certificate(der_cert)

            result["certificate_subject"] = cert.subject.rfc4514_string()
            result["certificate_issuer"] = cert.issuer.rfc4514_string()
            result["certificate_serial"] = str(cert.serial_number)
            result["certificate_not_before"] = (
                cert.not_valid_before_utc.isoformat()
            )
            result["certificate_not_after"] = (
                cert.not_valid_after_utc.isoformat()
            )

            try:
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
                result["certificate_sans"] = san.get_values_for_type(
                    x509.DNSName
                ) + san.get_values_for_type(x509.IPAddress).__str__().split()
            except x509.ExtensionNotFound:
                pass

            public_key = cert.public_key()
            result["public_key_type"] = type(public_key).__name__
            result["public_key_size"] = getattr(
                public_key, "key_size", None
            )

            signature_hash = cert.signature_hash_algorithm
            if signature_hash is not None:
                result["signature_hash"] = signature_hash.name

        except (AttributeError, OSError, ValueError, TypeError):
            return result

        return result

    @staticmethod
    def _certificate_name(value: Any) -> str | None:
        parts: list[str] = []

        for group in value or ():
            for key, item in group:
                parts.append(f"{key}={item}")

        return ", ".join(parts) if parts else None

    @staticmethod
    def _format_host(address: str, address_family: str) -> str:
        if address_family.lower() in {"ipv6", "af_inet6"} and ":" in address:
            return f"[{address}]"
        return address

    @staticmethod
    def _http_version(value: Any) -> str | None:
        if value is None:
            return None

        versions = {
            10: "HTTP/1.0",
            11: "HTTP/1.1",
            20: "HTTP/2",
        }
        return versions.get(value, str(value))

    @staticmethod
    def _timestamp() -> str:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat()

    def _error_observation(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
        protocol: str,
        category: str,
        exc: BaseException,
    ) -> ProtocolObservation:
        return ProtocolObservation(
            target=target,
            address=address,
            address_family=address_family,
            port=port,
            transport="tcp",
            protocol=protocol,
            success=False,
            identification_method=category,
            confidence=0.0,
            timestamp=self._timestamp(),
            evidence=(
                f"{protocol.upper()} probe failed: "
                f"{type(exc).__name__}: {exc}",
            ),
            error=f"{category}: {type(exc).__name__}: {exc}",
        )

    def _unsupported(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
        transport: str,
        message: str,
    ) -> ProtocolObservation:
        return ProtocolObservation(
            target=target,
            address=address,
            address_family=address_family,
            port=port,
            transport=transport,
            protocol="unknown",
            success=False,
            identification_method="unsupported",
            confidence=0.0,
            timestamp=self._timestamp(),
            evidence=(message,),
            error=message,
        )
