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

        if service_name == "ftp" or port == 21:
            return self._probe_ftp(
                target,
                address,
                address_family,
                port,
            )

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

    def _probe_ftp(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
    ) -> ProtocolObservation:
        """Probe FTP protocol capabilities without authentication or file I/O."""

        family = (
            socket.AF_INET6
            if address_family.lower() in {"ipv6", "af_inet6"}
            else socket.AF_INET
        )

        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        response_buffer = bytearray()

        try:
            sock.connect((address, port))

            greeting = self._ftp_read_response(sock, response_buffer)

            if greeting is None:
                return ProtocolObservation(
                    target=target,
                    address=address,
                    address_family=address_family,
                    port=port,
                    transport="tcp",
                    protocol="ftp",
                    success=False,
                    identification_method="ftp_greeting_missing",
                    confidence=0.0,
                    timestamp=self._timestamp(),
                    evidence=("FTP server did not provide a valid greeting.",),
                    error="ftp_greeting_missing",
                )

            greeting_code, greeting_lines = greeting

            data: dict[str, Any] = {
                "greeting_code": greeting_code,
                "greeting_lines": greeting_lines,
                "banner": "\n".join(greeting_lines),
                "commands": {},
                "features": [],
                "feature_details": [],
                "system_type": None,
                "working_directory": None,
                "passive_mode": None,
                "explicit_tls": None,
            }

            evidence = [
                "FTP protocol confirmed by server greeting.",
                f"FTP greeting response code: {greeting_code}",
            ]

            if greeting_lines:
                evidence.append(
                    f"FTP server greeting: {greeting_lines[0]}"
                )

            commands = ("FEAT", "SYST", "PWD", "AUTH TLS")

            for command in commands:
                response = self._ftp_command(
                    sock,
                    command,
                    response_buffer,
                )

                command_key = command.lower().replace(" ", "_")

                if response is None:
                    data["commands"][command_key] = {
                        "code": None,
                        "lines": [],
                        "status": "no_response",
                    }
                    evidence.append(
                        f"FTP {command} produced no valid response."
                    )
                    continue

                code, lines = response

                data["commands"][command_key] = {
                    "code": code,
                    "lines": lines,
                    "status": self._classify_ftp_response(code),
                }

                evidence.append(
                    f"FTP {command} response code: {code}"
                )

                if command == "FEAT":
                    features = []
                    feature_details = []

                    for line in lines:
                        stripped = line.strip()

                        if not stripped:
                            continue

                        if stripped[:3].isdigit():
                            continue

                        parts = stripped.split(None, 1)
                        feature = parts[0].upper()

                        if feature in {"EXTENSIONS", "END"}:
                            continue

                        arguments = parts[1].strip() if len(parts) > 1 else None

                        features.append(feature)
                        feature_details.append(
                            {
                                "name": feature,
                                "arguments": arguments,
                                "raw": stripped,
                            }
                        )

                    data["features"] = list(dict.fromkeys(features))
                    data["feature_details"] = feature_details

                    if features:
                        evidence.append(
                            "FTP advertised features: "
                            + ", ".join(data["features"])
                        )

                    if feature_details:
                        evidence.append(
                            "FTP FEAT advertisement details captured."
                        )

                    passive_command = (
                        "EPSV" if "EPSV" in data["features"] else "PASV"
                    )
                    passive_response = self._ftp_command(
                        sock,
                        passive_command,
                        response_buffer,
                    )

                    passive_key = passive_command.lower()

                    if passive_response is None:
                        data["commands"][passive_key] = {
                            "code": None,
                            "lines": [],
                            "status": "no_response",
                        }
                        evidence.append(
                            f"FTP {passive_command} produced no valid response."
                        )
                    else:
                        passive_code, passive_lines = passive_response

                        data["commands"][passive_key] = {
                            "code": passive_code,
                            "lines": passive_lines,
                            "status": self._classify_ftp_response(passive_code),
                        }

                        if passive_command == "EPSV":
                            passive = self._parse_ftp_epsv(passive_lines)

                            data["passive_mode"] = {
                                "mode": "EPSV",
                                "supported": passive["supported"],
                                "port": passive["port"],
                                "raw": passive["raw"],
                            }
                        else:
                            passive = self._parse_ftp_pasv(passive_lines)

                            data["passive_mode"] = {
                                "mode": "PASV",
                                "supported": passive["supported"],
                                "address": passive["address"],
                                "port": passive["port"],
                                "raw": passive["raw"],
                            }

                        evidence.append(
                            f"FTP {passive_command} response code: "
                            f"{passive_code}"
                        )

                        if passive["supported"]:
                            if passive_command == "EPSV":
                                evidence.append(
                                    f"FTP EPSV passive mode accepted on port "
                                    f"{passive['port']}."
                                )
                            else:
                                evidence.append(
                                    f"FTP PASV passive mode accepted at "
                                    f"{passive['address']}:{passive['port']}."
                                )
                        else:
                            evidence.append(
                                f"FTP {passive_command} response did not contain "
                                "a valid passive endpoint."
                            )

                elif command == "SYST":
                    payload = [
                        line.strip()
                        for line in lines
                        if line[:3].isdigit() and len(line) > 4
                    ]

                    if payload:
                        data["system_type"] = payload[0][4:].strip()

                    if data["system_type"]:
                        evidence.append(
                            f"FTP system type: {data['system_type']}"
                        )

                elif command == "PWD":
                    payload = [
                        line.strip()
                        for line in lines
                        if line[:3].isdigit() and len(line) > 4
                    ]

                    if payload:
                        data["working_directory"] = payload[0][4:].strip()

                    if data["working_directory"]:
                        evidence.append(
                            "FTP server reported initial working-directory state."
                        )

                elif command == "AUTH TLS":
                    data["explicit_tls"] = 200 <= code < 400
                    data["tls_handshake"] = None
                    data["tls"] = None

                    if data["explicit_tls"]:
                        evidence.append(
                            "FTP server accepted the AUTH TLS capability request."
                        )

                        try:
                            context = (
                                ssl_context(self._config)
                                if self._config is not None
                                else ssl.create_default_context()
                            )

                            server_hostname = None
                            if ":" not in address and not address.replace(
                                ".", ""
                            ).isdigit():
                                server_hostname = target

                            tls_sock = context.wrap_socket(
                                sock,
                                server_hostname=server_hostname,
                            )
                            sock = tls_sock

                            data["tls_handshake"] = True
                            data["tls"] = self._tls_socket_metadata(tls_sock)

                            evidence.append(
                                "FTP AUTH TLS handshake completed successfully."
                            )

                            tls_version = data["tls"].get("version")
                            tls_cipher = data["tls"].get("cipher")

                            if tls_version:
                                evidence.append(
                                    f"FTP TLS version: {tls_version}"
                                )

                            if tls_cipher:
                                evidence.append(
                                    f"FTP TLS cipher: {tls_cipher}"
                                )

                        except (
                            ssl.SSLError,
                            TimeoutError,
                            ConnectionResetError,
                            OSError,
                            ValueError,
                        ) as exc:
                            data["tls_handshake"] = False
                            data["tls"] = self._empty_tls_metadata()
                            data["tls_error"] = str(exc)

                            evidence.append(
                                "FTP AUTH TLS was accepted, but the TLS "
                                "handshake failed."
                            )
                    else:
                        evidence.append(
                            "FTP server did not accept the AUTH TLS request."
                        )

            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol="ftp",
                success=True,
                identification_method="ftp_greeting_and_capability_probe",
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
                "ftp",
                "connection_failed",
                exc,
            )
        finally:
            sock.close()

    @staticmethod
    def _parse_ftp_epsv(
        lines: list[str],
    ) -> dict[str, Any]:
        """Parse an FTP EPSV response without contacting the data port."""

        result: dict[str, Any] = {
            "supported": False,
            "port": None,
            "raw": None,
        }

        for line in lines:
            stripped = line.strip()

            if not stripped:
                continue

            if stripped[:3].isdigit() and len(stripped) > 4:
                payload = stripped[4:].strip()
            else:
                payload = stripped

            result["raw"] = payload

            if not payload.startswith("Entering Extended Passive Mode"):
                continue

            start = payload.find("(")
            end = payload.rfind(")")

            if start == -1 or end <= start + 1:
                continue

            value = payload[start + 1:end]

            if len(value) < 5:
                continue

            delimiter = value[0]
            fields = value.split(delimiter)

            if len(fields) != 5:
                continue

            if fields[1] or fields[2] or not fields[3] or fields[4]:
                continue

            try:
                port = int(fields[3] if fields[3] else fields[4])
            except ValueError:
                continue

            if not 1 <= port <= 65535:
                continue

            result["supported"] = True
            result["port"] = port
            return result

        return result

    @staticmethod
    def _classify_ftp_response(code: int) -> str:
        """Classify an FTP reply code into its standard response class."""

        if 100 <= code < 200:
            return "preliminary"
        if 200 <= code < 300:
            return "success"
        if 300 <= code < 400:
            return "continuation"
        if 400 <= code < 500:
            return "transient_error"
        if 500 <= code < 600:
            return "permanent_error"
        return "unknown"

    @staticmethod
    def _parse_ftp_pasv(
        lines: list[str],
    ) -> dict[str, Any]:
        """Parse an FTP PASV response without contacting the data port."""

        result: dict[str, Any] = {
            "supported": False,
            "address": None,
            "port": None,
            "raw": None,
        }

        for line in lines:
            stripped = line.strip()

            if not stripped:
                continue

            if stripped[:3].isdigit() and len(stripped) > 4:
                payload = stripped[4:].strip()
            else:
                payload = stripped

            result["raw"] = payload

            if not payload.lower().startswith("entering passive mode"):
                continue

            start = payload.find("(")
            end = payload.rfind(")")

            if start == -1 or end <= start + 1:
                continue

            value = payload[start + 1:end]
            parts = [part.strip() for part in value.split(",")]

            if len(parts) != 6:
                continue

            try:
                octets = [int(part) for part in parts[:4]]
                high = int(parts[4])
                low = int(parts[5])
            except ValueError:
                continue

            if any(not 0 <= octet <= 255 for octet in octets):
                continue

            if not 0 <= high <= 255 or not 0 <= low <= 255:
                continue

            port = (high * 256) + low

            if not 1 <= port <= 65535:
                continue

            result["supported"] = True
            result["address"] = ".".join(str(octet) for octet in octets)
            result["port"] = port
            return result

        return result

    def _ftp_command(
        self,
        sock: socket.socket,
        command: str,
        response_buffer: bytearray,
    ) -> tuple[int, list[str]] | None:
        """Send one bounded, non-authenticating FTP command."""

        if not command or "\r" in command or "\n" in command:
            raise ValueError("invalid FTP command")

        encoded = (command + "\r\n").encode("ascii")

        if len(encoded) > 1024:
            raise ValueError("FTP command exceeds maximum length")

        sock.sendall(encoded)

        return self._ftp_read_response(sock, response_buffer)

    def _ftp_read_response(
        self,
        sock: socket.socket,
        response_buffer: bytearray,
    ) -> tuple[int, list[str]] | None:
        """Read exactly one bounded FTP response from a connection buffer."""

        max_bytes = min(self._max_body_bytes, 65536)

        while True:
            newline = response_buffer.find(b"\n")

            if newline == -1:
                if len(response_buffer) >= max_bytes:
                    return None

                chunk = sock.recv(
                    min(1024, max_bytes - len(response_buffer))
                )

                if not chunk:
                    return None

                response_buffer.extend(chunk)
                continue

            first = bytes(
                response_buffer[:newline + 1]
            ).decode(
                "utf-8",
                errors="replace",
            ).rstrip("\r\n")

            if len(first) < 3 or not first[:3].isdigit():
                return None

            code = int(first[:3])
            multiline = len(first) >= 4 and first[3] == "-"

            if not multiline:
                del response_buffer[:newline + 1]
                return code, [first]

            terminator = f"{code} "
            search_from = newline + 1

            while True:
                next_newline = response_buffer.find(
                    b"\n",
                    search_from,
                )

                if next_newline == -1:
                    if len(response_buffer) >= max_bytes:
                        return None

                    chunk = sock.recv(
                        min(1024, max_bytes - len(response_buffer))
                    )

                    if not chunk:
                        return None

                    response_buffer.extend(chunk)
                    continue

                line = bytes(
                    response_buffer[
                        search_from:next_newline + 1
                    ]
                ).decode(
                    "utf-8",
                    errors="replace",
                ).rstrip("\r\n")

                if line.startswith(terminator):
                    consumed = next_newline + 1
                    raw_response = bytes(
                        response_buffer[:consumed]
                    )
                    del response_buffer[:consumed]

                    return (
                        code,
                        raw_response.decode(
                            "utf-8",
                            errors="replace",
                        ).splitlines(),
                    )

                search_from = next_newline + 1

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
    def _empty_tls_metadata() -> dict[str, Any]:
        """Return the shared empty TLS metadata structure."""

        return {
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

    @staticmethod
    def _tls_socket_metadata(sock: ssl.SSLSocket) -> dict[str, Any]:
        """Extract TLS metadata directly from a negotiated TLS socket."""

        result = ProtocolProbe._empty_tls_metadata()

        try:
            result["version"] = sock.version()

            cipher = sock.cipher()
            if cipher:
                result["cipher"] = cipher[0]

            der_cert = sock.getpeercert(binary_form=True)
            if not der_cert:
                return result

            import hashlib

            result["certificate_sha256"] = hashlib.sha256(
                der_cert
            ).hexdigest()

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

                result["certificate_sans"] = [
                    str(value)
                    for value in san.get_values_for_type(x509.DNSName)
                ] + [
                    str(value)
                    for value in san.get_values_for_type(x509.IPAddress)
                ]
            except x509.ExtensionNotFound:
                pass

            public_key = cert.public_key()
            result["public_key_type"] = type(public_key).__name__
            result["public_key_size"] = getattr(
                public_key,
                "key_size",
                None,
            )

            signature_hash = cert.signature_hash_algorithm
            if signature_hash is not None:
                result["signature_hash"] = signature_hash.name

        except (AttributeError, OSError, ValueError, TypeError):
            return result

        return result

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
