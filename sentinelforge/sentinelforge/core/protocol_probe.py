"""Shared protocol probing.

Provides structured, bounded protocol observations for services discovered
by SentinelForge. This layer performs protocol identification and lightweight
handshakes; security-specific checks remain in their existing plugins.
"""

from __future__ import annotations

import re
import time
import hashlib

import ipaddress
import socket
import struct
import sys
import ssl
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from dataclasses import dataclass, field
from typing import Any

from sentinelforge.core.network import ssl_context
from sentinelforge.core.dns_probe import DnsProbe


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

        transport_name = transport.lower()
        service_name = (service or "unknown").lower()

        if service_name == "dns" or port == 53:
            return self._probe_dns(
                target,
                address,
                address_family,
                port,
                transport_name,
            )

        if transport_name != "tcp":
            return self._unsupported(
                target,
                address,
                address_family,
                port,
                transport_name,
                "Only TCP protocol probes are currently implemented.",
            )

        if service_name == "ftp" or port == 21:
            return self._probe_ftp(
                target,
                address,
                address_family,
                port,
            )

        if service_name in {
            "oracle", "oracle-db", "oracle database", "oracle-database", "tns"
        } or port == 1521:
            return self._probe_oracle(
                target,
                address,
                address_family,
                port,
            )

        if service_name in {"mssql", "sqlserver", "microsoft sql server", "tds"} or port == 1433:
            return self._probe_mssql(
                target,
                address,
                address_family,
                port,
            )

        if service_name in {"postgresql", "postgres", "pgsql"} or port == 5432:
            return self._probe_postgresql(
                target,
                address,
                address_family,
                port,
            )

        if service_name in {"mongodb", "mongo"} or port == 27017:
            return self._probe_mongodb(
                target,
                address,
                address_family,
                port,
            )

        if service_name in {"mysql", "mariadb"} or port == 3306:
            return self._probe_mysql(
                target,
                address,
                address_family,
                port,
            )

        if service_name in {"redis", "redis-server", "resp"} or port == 6379:
            return self._probe_redis(
                target,
                address,
                address_family,
                port,
            )

        if service_name == "smtp" or port in {25, 465, 587, 2525}:
            return self._probe_smtp(
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

    def _probe_postgresql(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
    ) -> ProtocolObservation:
        """Perform bounded PostgreSQL SSL negotiation and startup identification."""

        family = (
            socket.AF_INET6
            if address_family.lower() in {"ipv6", "af_inet6"}
            else socket.AF_INET
        )
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        ssl_accepted = False
        tls_established = False

        try:
            sock.connect((address, port))

            # PostgreSQL SSLRequest: length 8, request code 80877103.
            sock.sendall(struct.pack("!II", 8, 80877103))
            ssl_reply = self._recv_exact(sock, 1)

            if ssl_reply == b"S":
                ssl_accepted = True
                context = (
                    ssl_context(self._config)
                    if self._config is not None
                    else ssl.create_default_context()
                )
                sock = context.wrap_socket(sock, server_hostname=target)
                sock.settimeout(self._timeout)
                tls_established = True
            elif ssl_reply != b"N":
                raise ValueError(
                    "Invalid or incomplete PostgreSQL SSL negotiation response"
                )

            # StartupMessage protocol 3.0. No password or SQL is sent.
            parameters = (
                b"user\x00sentinelforge_probe\x00"
                b"database\x00postgres\x00"
                b"application_name\x00SentinelForge\x00"
                b"client_encoding\x00UTF8\x00"
                b"\x00"
            )
            startup_body = struct.pack("!I", 196608) + parameters
            startup_packet = struct.pack(
                "!I", len(startup_body) + 4
            ) + startup_body
            if len(startup_packet) > 4096:
                raise ValueError("PostgreSQL startup packet exceeds limit")
            sock.sendall(startup_packet)

            header = self._recv_exact(sock, 5)
            if header is None:
                raise ValueError("Incomplete PostgreSQL startup response")

            message_type = chr(header[0])
            message_length = struct.unpack("!I", header[1:])[0]
            if message_length < 4 or message_length > 65536:
                raise ValueError(
                    f"Invalid PostgreSQL response length: {message_length}"
                )

            payload = self._recv_exact(sock, message_length - 4)
            if payload is None:
                raise ValueError("Truncated PostgreSQL startup response")

            response_names = {
                "E": "error",
                "R": "authentication",
                "S": "parameter_status",
                "K": "backend_key_data",
                "Z": "ready_for_query",
                "N": "notice",
                "A": "notification",
                "v": "negotiate_protocol_version",
                "T": "row_description",
                "C": "command_complete",
                "I": "empty_query",
            }
            response_name = response_names.get(message_type)
            if response_name is None:
                raise ValueError(
                    f"Unexpected PostgreSQL response type: {message_type!r}"
                )

            data = {
                "ssl_supported": ssl_accepted and tls_established,
                "ssl_negotiation_accepted": ssl_accepted,
                "tls_established": tls_established,
                "server_response_type": response_name,
                "server_message_length": message_length,
                "credentials_sent": False,
                "sql_sent": False,
                "startup_parameters": [
                    "user", "database", "application_name", "client_encoding"
                ],
            }

            evidence = [
                "Valid PostgreSQL startup response received",
                f"PostgreSQL response type: {response_name}",
                f"TLS established: {tls_established}",
                "No password or SQL was sent",
            ]

            if message_type == "K":
                # BackendKeyData: exactly two 32-bit integers.
                if len(payload) != 8:
                    raise ValueError(
                        "Malformed PostgreSQL BackendKeyData payload"
                    )
                backend_process_id, _ = struct.unpack("!II", payload)
                if backend_process_id == 0:
                    raise ValueError(
                        "Invalid PostgreSQL backend process ID"
                    )
                data["backend_process_id"] = backend_process_id
                data["backend_secret_key_present"] = True
                # Do not expose or retain the server's secret key.
                evidence.append("Valid PostgreSQL BackendKeyData received")

            if message_type == "S":
                # ParameterStatus: name\0value\0, with no trailing bytes.
                if (
                    len(payload) < 3
                    or not payload.endswith(b"\x00")
                    or payload.count(b"\x00") != 2
                ):
                    raise ValueError(
                        "Malformed PostgreSQL ParameterStatus payload"
                    )
                parameter_name, parameter_value, terminator = payload.split(b"\x00")
                if not parameter_name or terminator != b"":
                    raise ValueError(
                        "Invalid PostgreSQL ParameterStatus fields"
                    )
                try:
                    decoded_parameter_name = parameter_name.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError(
                        "Invalid PostgreSQL ParameterStatus name encoding"
                    ) from exc

                data["parameter_status"] = {
                    "name": decoded_parameter_name,
                    "value": parameter_value.decode("utf-8", errors="replace"),
                }
                evidence.append(
                    "PostgreSQL parameter status received: "
                    + data["parameter_status"]["name"]
                )

            elif message_type == "Z":
                # ReadyForQuery has exactly one status byte: I, T, or E.
                if len(payload) != 1 or payload not in {b"I", b"T", b"E"}:
                    raise ValueError(
                        "Malformed PostgreSQL ReadyForQuery payload"
                    )
                data["transaction_status"] = payload.decode("ascii")
                evidence.append(
                    "PostgreSQL transaction status: "
                    + data["transaction_status"]
                )

            if message_type == "R":
                if len(payload) < 4:
                    raise ValueError(
                        "Truncated PostgreSQL authentication request"
                    )

                auth_code = struct.unpack("!I", payload[:4])[0]
                auth_methods = {
                    0: "OK",
                    2: "KERBEROS_V5",
                    3: "CLEAR_TEXT_PASSWORD",
                    5: "MD5_PASSWORD",
                    6: "SCM_CREDENTIAL",
                    7: "GSS",
                    8: "GSS_CONTINUE",
                    9: "SSPI",
                    10: "SASL",
                    11: "SASL_CONTINUE",
                    12: "SASL_FINAL",
                }
                auth_name = auth_methods.get(auth_code)
                if auth_name is None:
                    raise ValueError(
                        f"Unknown PostgreSQL authentication code: {auth_code}"
                    )

                expected_auth_payload_lengths = {
                    0: {4},       # AuthenticationOk
                    2: {4},       # Kerberos V5
                    3: {4},       # Cleartext password request
                    5: {8},       # MD5 request: code + four-byte salt
                    6: {4},       # SCM credentials
                    7: {4},       # GSS
                    8: None,      # GSS continuation data is variable
                    9: {4},       # SSPI
                    10: None,     # SASL mechanism list is variable
                    11: None,     # SASL continuation data is variable
                    12: None,     # SASL final data is variable
                }
                expected_length = expected_auth_payload_lengths[auth_code]
                if auth_code in {11, 12} and len(payload) <= 4:
                    raise ValueError(
                        f"Empty PostgreSQL {auth_name} data"
                    )
                if (
                    expected_length is not None
                    and len(payload) not in expected_length
                ):
                    raise ValueError(
                        f"Invalid PostgreSQL {auth_name} payload length: "
                        f"{len(payload)}"
                    )

                data["authentication_method"] = auth_name

                if auth_code == 10:
                    mechanisms = payload[4:]
                    if not mechanisms or not mechanisms.endswith(b"\x00\x00"):
                        raise ValueError(
                            "Malformed PostgreSQL SASL mechanism list"
                        )
                    names = [
                        item.decode("ascii")
                        for item in mechanisms.split(b"\x00")
                        if item
                    ]
                    if not names:
                        raise ValueError(
                            "Empty PostgreSQL SASL mechanism list"
                        )
                    if len(names) != len(set(names)):
                        raise ValueError(
                            "Duplicate PostgreSQL SASL mechanisms"
                        )
                    data["authentication_mechanisms"] = names
                    evidence.append(
                        "PostgreSQL authentication method: SASL"
                    )
                    evidence.append(
                        "Advertised SASL mechanisms: " + ", ".join(names)
                    )
                else:
                    evidence.append(
                        f"PostgreSQL authentication method: {auth_name}"
                    )

            if message_type in {"E", "N"}:
                fields = {}
                offset = 0
                terminated = False
                while offset < len(payload):
                    field_code = payload[offset]
                    offset += 1
                    if field_code == 0:
                        terminated = True
                        if offset != len(payload):
                            raise ValueError(
                                "Unexpected bytes after PostgreSQL error terminator"
                            )
                        break

                    field_end = payload.find(b"\x00", offset)
                    if field_end < 0:
                        raise ValueError(
                            "Unterminated PostgreSQL error field"
                        )
                    if chr(field_code) in fields:
                        raise ValueError(
                            "Duplicate PostgreSQL error response field"
                        )
                    value = payload[offset:field_end]
                    offset = field_end + 1
                    try:
                        decoded = value.decode("utf-8")
                    except UnicodeDecodeError:
                        decoded = value.decode("utf-8", errors="replace")
                    fields[chr(field_code)] = decoded

                if not terminated:
                    raise ValueError(
                        "PostgreSQL ErrorResponse lacks field terminator"
                    )

                parsed_fields = {
                    "severity": fields.get("V") or fields.get("S"),
                    "sqlstate": fields.get("C"),
                    "message": fields.get("M"),
                }
                data[
                    "startup_error" if message_type == "E"
                    else "startup_notice"
                ] = parsed_fields
                if fields.get("C"):
                    evidence.append(
                        f"PostgreSQL SQLSTATE: {fields['C']}"
                    )
                if fields.get("M"):
                    evidence.append(
                        f"PostgreSQL startup response: {fields['M']}"
                    )

            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol="postgresql",
                success=True,
                identification_method="postgresql_startup_response",
                confidence=0.99,
                timestamp=self._timestamp(),
                data=data,
                evidence=tuple(evidence),
            )

        except (
            TimeoutError,
            ConnectionResetError,
            OSError,
            ValueError,
            struct.error,
            ssl.SSLError,
        ) as exc:
            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol="postgresql",
                success=False,
                identification_method="postgresql_handshake_invalid",
                confidence=0.0,
                timestamp=self._timestamp(),
                data={
                    "ssl_negotiation_accepted": ssl_accepted,
                    "tls_established": tls_established,
                    "credentials_sent": False,
                    "sql_sent": False,
                },
                evidence=(
                    f"PostgreSQL probe failed: {type(exc).__name__}: {exc}",
                ),
                error=(
                    f"postgresql_handshake_invalid: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )
        finally:
            sock.close()

    def _probe_mongodb(
        self,
        target,
        address,
        address_family,
        port,
    ):
        """Identify MongoDB using a bounded OP_MSG hello handshake."""
        import socket
        import struct
        import time

        try:
            from bson import BSON
        except ImportError as exc:
            return self._error_observation(
                target, address, address_family, port,
                "mongodb", "mongodb_optional_dependency_missing", exc,
            )

        op_msg = 2013
        max_frame = min(max(int(self._max_body_bytes), 1024), 1024 * 1024)
        timeout = float(self._timeout)
        request_id = int(time.monotonic_ns() & 0x7fffffff)
        sock = None

        def crc32c(data):
            crc = 0xffffffff
            for byte in data:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ (
                        0x82f63b78 if crc & 1 else 0
                    )
            return crc ^ 0xffffffff

        def receive_exact(connection, size, deadline):
            chunks = []
            remaining = size
            while remaining:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("MongoDB response deadline exceeded")
                connection.settimeout(left)
                chunk = connection.recv(remaining)
                if not chunk:
                    raise ValueError("Truncated MongoDB wire response")
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)

        try:
            deadline = time.monotonic() + timeout

            document = BSON.encode({
                "hello": 1,
                "helloOk": True,
                "$db": "admin",
            })
            body = struct.pack("<I", 0) + b"\x00" + document
            packet = struct.pack(
                "<iiii", 16 + len(body), request_id, 0, op_msg
            ) + body

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("MongoDB request deadline exceeded")

            sock = socket.socket(address_family, socket.SOCK_STREAM)
            sock.settimeout(remaining)
            sock.connect(address)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("MongoDB request deadline exceeded")
            sock.settimeout(remaining)
            sock.sendall(packet)

            header = receive_exact(sock, 16, deadline)
            length, _response_id, response_to, opcode = struct.unpack(
                "<iiii", header
            )

            if length < 26 or length > max_frame:
                raise ValueError(f"Invalid MongoDB frame length: {length}")
            if response_to != request_id:
                raise ValueError("MongoDB response-to ID does not match request")
            if opcode != op_msg:
                raise ValueError(f"Expected OP_MSG; received opcode {opcode}")

            body = receive_exact(sock, length - 16, deadline)
            if len(body) < 10:
                raise ValueError("MongoDB OP_MSG body is too short")

            flags = struct.unpack_from("<I", body)[0]
            # This probe supports checksumPresent only.
            if flags & ~0x00000001:
                raise ValueError("Unsupported MongoDB OP_MSG flags")

            checksum_size = 4 if flags & 1 else 0
            if len(body) < 10 + checksum_size:
                raise ValueError("MongoDB OP_MSG document is truncated")

            if checksum_size:
                supplied = struct.unpack_from("<I", body, len(body) - 4)[0]
                if crc32c(header + body[:-4]) != supplied:
                    raise ValueError("MongoDB OP_MSG CRC-32C checksum mismatch")

            section = body[4:len(body) - checksum_size]
            if not section or section[0] != 0:
                raise ValueError("MongoDB hello response lacks kind-0 BSON section")

            bson_bytes = section[1:]
            if len(bson_bytes) < 5:
                raise ValueError("MongoDB BSON document is truncated")
            declared = struct.unpack_from("<i", bson_bytes)[0]
            if declared != len(bson_bytes):
                raise ValueError("MongoDB BSON length does not match section")

            try:
                response = BSON(bson_bytes).decode()
            except Exception as exc:
                raise ValueError(f"Invalid MongoDB hello BSON: {exc}") from exc

            if not isinstance(response, dict):
                raise ValueError("MongoDB hello response is not a document")
            ok = response.get("ok")
            if isinstance(ok, bool) or not isinstance(ok, (int, float)) or ok != 1:
                raise ValueError("MongoDB hello command was not successful")

            evidence = [
                "MongoDB OP_MSG hello response received",
                "Response-to ID matched request",
                "BSON decoded and hello returned ok=1",
            ]
            if isinstance(response.get("version"), str):
                evidence.append(f"Server version: {response['version']}")
            if isinstance(response.get("maxWireVersion"), int):
                evidence.append(
                    f"Maximum wire version: {response['maxWireVersion']}"
                )

            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol="mongodb",
                success=True,
                identification_method="mongodb_op_msg_hello",
                confidence=0.99,
                timestamp=self._timestamp(),
                data={
                    key: response[key]
                    for key in (
                        "version", "maxWireVersion", "minWireVersion",
                        "maxBsonObjectSize", "logicalSessionTimeoutMinutes",
                    )
                    if key in response
                },
                evidence=tuple(evidence),
                error=None,
            )

        except Exception as exc:
            # Prevent ordinary probe failures from aborting the overall scan.
            return self._error_observation(
                target, address, address_family, port,
                "mongodb", "mongodb_handshake_error", exc,
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _probe_oracle(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
    ) -> ProtocolObservation:
        """Identify an Oracle listener using a bounded TNS CONNECT handshake."""

        protocol = "oracle"
        try:
            family = (
                socket.AF_INET6
                if address_family.lower() in {"ipv6", "af_inet6"}
                else socket.AF_INET
            )

            connect_data = (
                f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={address})"
                f"(PORT={port}))(CONNECT_DATA=(SERVICE_NAME=ORCL)))"
            ).encode("ascii")
            if len(connect_data) > 1024:
                raise ValueError("TNS CONNECT descriptor exceeds size limit")

            # TNS 3.19 CONNECT layout: descriptor begins at packet offset 74.
            # Keep each field at its protocol-defined offset.
            prefix = bytearray(66)
            struct.pack_into(
                "!HHHHHHHHHH",
                prefix,
                0,
                0x013F,  # Desired TNS version 319
                0x012C,  # Lowest compatible version 300
                0x0C01,  # Don't care; receive attention; no attention processing
                8192,    # Session data unit
                32767,   # Transport data unit
                0x7F08,  # Protocol characteristics
                0,       # Line turnaround
                1,       # Required fixed field
                len(connect_data),
                74,      # CONNECT descriptor offset from packet start
            )
            prefix[14:16] = (1).to_bytes(2, byteorder=sys.byteorder)
            struct.pack_into("!I", prefix, 20, 512)  # 32-bit maximum CONNECT data
            struct.pack_into("!II", prefix, 50, 8192, 32767)
            body = bytes(prefix) + connect_data
            packet = struct.pack("!HHBBH", len(body) + 8, 0, 1, 0, 0) + body

            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self._timeout)
                sock.connect((address, port))
                sock.sendall(packet)

                deadline = time.monotonic() + self._timeout

                def recv_exact(size: int) -> bytes:
                    data = bytearray()
                    while len(data) < size:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("TNS response deadline exceeded")
                        sock.settimeout(remaining)
                        try:
                            chunk = sock.recv(size - len(data))
                        except socket.timeout as exc:
                            raise TimeoutError(
                                "TNS response deadline exceeded"
                            ) from exc
                        if not chunk:
                            raise ValueError("Truncated TNS response")
                        data.extend(chunk)
                    return bytes(data)

                header = recv_exact(8)
                packet_length, checksum, packet_type, flags, header_checksum = (
                    struct.unpack("!HHBBH", header)
                )

                if packet_length < 8:
                    raise ValueError("Invalid TNS packet length")
                if packet_length > min(self._max_body_bytes, 4096):
                    raise ValueError("TNS response exceeds configured size limit")
                if packet_type not in {2, 4, 5}:
                    raise ValueError(
                        f"Unexpected TNS response packet type: {packet_type}"
                    )

                payload_length = packet_length - 8
                payload = recv_exact(payload_length) if payload_length else b""
                response = header + payload

            if packet_type == 2:  # ACCEPT
                if len(response) < 32:
                    raise ValueError("TNS ACCEPT packet is too short")

                version, options, sdu, tdu = struct.unpack(
                    "!HHHH", response[8:16]
                )
                value_one_bytes = response[16:18]
                data_length, data_offset = struct.unpack(
                    "!HH", response[18:22]
                )
                if version < 0x012C or value_one_bytes not in (
                    bytes((0, 1)), bytes((1, 0))
                ):
                    raise ValueError("Invalid TNS ACCEPT version or fixed field")
                if sdu == 0 or tdu == 0:
                    raise ValueError("Invalid TNS ACCEPT SDU/TDU")

                if data_length:
                    if (
                        data_offset < 32
                        or data_offset > len(response)
                        or data_length > len(response) - data_offset
                    ):
                        raise ValueError("Invalid TNS ACCEPT connect-data bounds")
                elif data_offset and not 32 <= data_offset <= len(response):
                    raise ValueError("Invalid TNS ACCEPT connect-data offset")

                if version >= 0x013B:
                    if len(response) < 41:
                        raise ValueError("Truncated extended TNS ACCEPT packet")
                    large_sdu, large_tdu = struct.unpack("!II", response[32:40])
                    if large_sdu and large_sdu < 512:
                        raise ValueError("Invalid extended TNS ACCEPT SDU")
                    if large_tdu and large_tdu < 255:
                        raise ValueError("Invalid extended TNS ACCEPT TDU")

                if version >= 0x013E and len(response) < 45:
                    raise ValueError("Truncated TNS ACCEPT flags field")

                result_name = "oracle_tns_accept"
                confidence = 0.99
                classification = "accept"
            elif packet_type == 4:  # REFUSE
                if len(response) < 12:
                    raise ValueError("TNS REFUSE packet is too short")
                refusal_length = int.from_bytes(response[10:12], "big")
                if refusal_length != len(response) - 12:
                    raise ValueError("Invalid TNS REFUSE data length")
                result_name = "oracle_tns_refuse"
                confidence = 0.98
                classification = "refuse"
            else:  # REDIRECT
                if len(response) < 10:
                    raise ValueError("TNS REDIRECT packet is too short")
                redirect_length = int.from_bytes(response[8:10], "big")
                if redirect_length == 0 or redirect_length != len(response) - 10:
                    raise ValueError("Invalid TNS REDIRECT data length")
                redirect_data = response[10:]
                if b"(" not in redirect_data or b"ADDRESS" not in redirect_data.upper():
                    raise ValueError("TNS REDIRECT data lacks an address descriptor")
                result_name = "oracle_tns_redirect"
                confidence = 0.98
                classification = "redirect"

            data = {
                "tns_packet_type": packet_type,
                "tns_packet_type_name": classification.upper(),
                "response_length": len(response),
                "credentials_sent": False,
                "sql_executed": False,
            }
            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol=protocol,
                success=True,
                identification_method=result_name,
                confidence=confidence,
                timestamp=self._timestamp(),
                data=data,
                evidence=(
                    f"Received a structurally valid Oracle TNS {classification.upper()} response; "
                    "no credentials or SQL were sent.",
                ),
            )
        except (OSError, ValueError, struct.error) as exc:
            return self._error_observation(
                target, address, address_family, port, protocol,
                "oracle_tns_failed", exc,
            )

    def _probe_mssql(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
    ) -> ProtocolObservation:
        """Identify Microsoft SQL Server using TDS PRELOGIN only."""

        protocol = "mssql"
        try:
            family = (
                socket.AF_INET6
                if address_family.lower() in {"ipv6", "af_inet6"}
                else socket.AF_INET
            )
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(self._timeout)
                sock.connect((address, port))
                # TDS PRELOGIN option table: VERSION and ENCRYPTION, then terminator.
                version_offset = 11
                encryption_offset = 17
                payload = (
                    b"\\x00" + struct.pack("!HH", version_offset, 6)
                    + b"\\x01" + struct.pack("!HH", encryption_offset, 1)
                    + b"\\xff"
                    + b"\\x00\\x00\\x00\\x00\\x00\\x00"
                    + b"\\x02"
                )
                packet = struct.pack("!BBHHBB", 0x12, 0x01, len(payload) + 8, 0, 1, 0) + payload
                sock.sendall(packet)

                response_buffer = bytearray()
                response_deadline = time.monotonic() + self._timeout

                def recv_tds_exact(size: int) -> bytes | None:
                    data = bytearray()
                    while len(data) < size:
                        remaining = response_deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError(
                                "TDS PRELOGIN response deadline exceeded"
                            )
                        sock.settimeout(remaining)
                        try:
                            chunk = sock.recv(size - len(data))
                        except socket.timeout as exc:
                            raise TimeoutError(
                                "TDS PRELOGIN response deadline exceeded"
                            ) from exc
                        if not chunk:
                            return None
                        data.extend(chunk)
                    return bytes(data)

                while True:
                    header = recv_tds_exact(8)
                    if header is None:
                        raise ValueError("Truncated TDS response header")

                    packet_type, status, packet_length = struct.unpack(
                        "!BBH", header[:4]
                    )
                    if packet_type != 0x04:
                        raise ValueError(
                            f"Unexpected TDS response packet type: 0x{packet_type:02x}"
                        )
                    if packet_length < 9:
                        raise ValueError(
                            f"Invalid TDS response length: {packet_length}"
                        )

                    packet_payload_length = packet_length - 8
                    if (
                        len(response_buffer) + packet_payload_length
                        > self._max_body_bytes
                    ):
                        raise ValueError(
                            "TDS PRELOGIN response exceeds configured size limit"
                        )

                    packet_payload = recv_tds_exact(packet_payload_length)
                    if packet_payload is None:
                        raise ValueError("Truncated TDS PRELOGIN response")

                    response_buffer.extend(packet_payload)
                    if status & 0x01:
                        break

                response = bytes(response_buffer)

            options = {}
            cursor = 0
            table_end = None
            while cursor < len(response):
                token = response[cursor]
                cursor += 1
                if token == 0xFF:
                    table_end = cursor
                    break
                if cursor + 4 > len(response):
                    raise ValueError("Malformed TDS PRELOGIN option table")
                offset, length = struct.unpack("!HH", response[cursor:cursor + 4])
                cursor += 4
                if token in options:
                    raise ValueError("Duplicate TDS PRELOGIN option")
                options[token] = (offset, length)

            if table_end is None:
                raise ValueError("Missing TDS PRELOGIN option terminator")

            parsed = {}
            ranges = []
            for token, (offset, length) in options.items():
                end = offset + length
                if offset < table_end or end > len(response):
                    raise ValueError("TDS PRELOGIN option offset is out of bounds")

                if length:
                    for existing_start, existing_end in ranges:
                        if offset < existing_end and end > existing_start:
                            raise ValueError("overlapping TDS PRELOGIN option ranges")
                    ranges.append((offset, end))

                parsed[token] = response[offset:end]

            version = parsed.get(0x00)
            encryption = parsed.get(0x01)
            encryption_names = {
                0: "ENCRYPT_OFF",
                1: "ENCRYPT_ON",
                2: "ENCRYPT_NOT_SUP",
                3: "ENCRYPT_REQ",
            }
            encryption_value = encryption[0] if encryption and len(encryption) == 1 else None
            if encryption is not None and encryption_value is None:
                raise ValueError("Invalid TDS encryption option length")
            if encryption_value is not None and encryption_value not in encryption_names:
                raise ValueError("Unknown TDS encryption option value")

            data = {
                "prelogin_received": True,
                "tds_packet_type": packet_type,
                "tds_version_hex": version.hex() if version else None,
                "encryption_option": encryption_value,
                "encryption_option_name": encryption_names.get(encryption_value),
                "options_present": sorted(options),
            }
            return ProtocolObservation(
                target=target, address=address, address_family=address_family,
                port=port, transport="tcp", protocol=protocol, success=True,
                identification_method="mssql_tds_prelogin", confidence=0.98,
                timestamp=self._timestamp(), data=data,
                evidence=("Received a valid TDS PRELOGIN response; no credentials or SQL were sent.",),
            )
        except (OSError, ValueError, struct.error) as exc:
            return self._error_observation(
                target, address, address_family, port, protocol,
                "mssql_prelogin_failed", exc,
            )

    def _probe_mysql(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
    ) -> ProtocolObservation:
        """Read and classify a bounded MySQL/MariaDB initial handshake."""

        import struct

        family = (
            socket.AF_INET6
            if address_family.lower() in {"ipv6", "af_inet6"}
            else socket.AF_INET
        )

        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)

        try:
            sock.connect((address, port))

            header = self._recv_exact(sock, 4)
            if header is None:
                raise ValueError("Incomplete MySQL packet header")

            packet_length = int.from_bytes(header[:3], "little")
            sequence_id = header[3]

            if packet_length < 1 or packet_length > 65536:
                raise ValueError(
                    f"Invalid MySQL handshake packet length: {packet_length}"
                )

            if sequence_id != 0:
                raise ValueError(
                    f"Unexpected MySQL greeting sequence ID: {sequence_id}"
                )

            payload = self._recv_exact(sock, packet_length)
            if payload is None:
                raise ValueError("Truncated MySQL handshake payload")

            if len(payload) < 1 or payload[0] != 10:
                raise ValueError("Invalid MySQL protocol-10 greeting")

            offset = 1
            version_end = payload.find(bytes([0]), offset)
            if version_end < 0:
                raise ValueError("MySQL greeting has no terminated server version")

            try:
                server_version = payload[offset:version_end].decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    "Invalid non-ASCII MySQL server-version string"
                ) from exc
            if not server_version or not server_version.isprintable():
                raise ValueError("Invalid MySQL server-version string")
            version_lower = server_version.lower()
            if "mariadb" in version_lower:
                server_family = "mariadb"
            elif "mysql" in version_lower:
                server_family = "mysql"
            else:
                server_family = "mysql_compatible"
            offset = version_end + 1

            if offset + 4 + 8 + 1 + 2 > len(payload):
                raise ValueError("Truncated MySQL greeting fields")

            connection_id = struct.unpack_from("<I", payload, offset)[0]
            if connection_id == 0:
                raise ValueError("Invalid MySQL connection ID: zero is reserved")
            offset += 4
            salt_part_one = payload[offset:offset + 8]
            offset += 8

            if payload[offset] != 0:
                raise ValueError("Invalid MySQL greeting filler byte")
            offset += 1

            lower_capabilities = struct.unpack_from("<H", payload, offset)[0]
            offset += 2

            data = {
                "protocol_version": 10,
                "server_version": server_version,
                "server_family": server_family,
                "connection_id": connection_id,
                "capability_flags": lower_capabilities,
                "capabilities": [],
                "character_set": None,
                "status_flags": None,
                "authentication_plugin": None,
                "authentication_salt_length": len(salt_part_one),
                "handshake_complete": False,
            }

            capability_names = {
                0x000001: "long_password",
                0x000002: "found_rows",
                0x000004: "long_flag",
                0x000008: "connect_with_database",
                0x000010: "no_schema",
                0x000020: "compress",
                0x000040: "odbc",
                0x000080: "local_files",
                0x000100: "ignore_space",
                0x000200: "protocol_41",
                0x000400: "interactive",
                0x000800: "ssl",
                0x001000: "ignore_sigpipe",
                0x002000: "transactions",
                0x008000: "secure_connection",
                0x010000: "multi_statements",
                0x020000: "multi_results",
                0x040000: "ps_multi_results",
                0x080000: "plugin_auth",
                0x100000: "connect_attrs",
                0x200000: "plugin_auth_lenenc_client_data",
                0x400000: "can_handle_expired_passwords",
                0x800000: "session_track",
                0x1000000: "deprecate_eof",
            }

            capabilities = lower_capabilities
            for bit, name in capability_names.items():
                if lower_capabilities & bit:
                    data["capabilities"].append(name)

            if offset < len(payload):
                if offset + 5 > len(payload):
                    raise ValueError("Truncated MySQL capability metadata")

                data["character_set"] = payload[offset]
                offset += 1

                data["status_flags"] = struct.unpack_from(
                    "<H", payload, offset
                )[0]
                offset += 2

                upper_capabilities = struct.unpack_from(
                    "<H", payload, offset
                )[0]
                offset += 2
                capabilities |= upper_capabilities << 16
                data["capability_flags"] = capabilities

                auth_length = payload[offset] if offset < len(payload) else 0
                if offset < len(payload):
                    offset += 1

                reserved_end = offset + 10
                if reserved_end > len(payload):
                    raise ValueError("Truncated MySQL reserved handshake fields")
                if any(payload[offset:reserved_end]):
                    raise ValueError("Nonzero MySQL reserved handshake bytes")
                offset = reserved_end

                if capabilities & 0x00008000:
                    auth_data_length = max(13, auth_length - 8)
                    remaining = payload[offset:]
                    if len(remaining) < auth_data_length:
                        raise ValueError(
                            "Truncated MySQL authentication data"
                        )

                    salt_part_two = remaining[:auth_data_length]
                    offset += auth_data_length
                    salt = (salt_part_one + salt_part_two).rstrip(bytes([0]))
                    data["authentication_salt_length"] = len(salt)

                    if capabilities & 0x00080000:
                        if offset >= len(payload):
                            raise ValueError(
                                "Missing MySQL authentication plugin name"
                            )
                        plugin_end = payload.find(bytes([0]), offset)
                        if plugin_end < 0:
                            raise ValueError(
                                "Unterminated MySQL authentication plugin name"
                            )
                        plugin_bytes = payload[offset:plugin_end]
                        try:
                            plugin = plugin_bytes.decode("ascii")
                        except UnicodeDecodeError as exc:
                            raise ValueError(
                                "Invalid MySQL authentication plugin name"
                            ) from exc
                        if not plugin or not all(
                            char.isalnum() or char in "_-."
                            for char in plugin
                        ):
                            raise ValueError(
                                "Invalid MySQL authentication plugin name"
                            )
                        data["authentication_plugin"] = plugin
                        offset = plugin_end + 1

                elif not (capabilities & 0x00080000):
                    # Without plugin_auth, no authentication-plugin field
                    # is advertised; don't consume arbitrary trailing bytes.

                    pass

                if offset != len(payload):
                    raise ValueError("Unexpected trailing MySQL handshake bytes")

                data["capabilities"] = [
                    name
                    for bit, name in capability_names.items()
                    if capabilities & bit
                ]

            data["handshake_complete"] = True
            data["fingerprint"] = {
                "protocol": "mysql",
                "server_family": server_family,
                "server_version": server_version,
                "capability_flags": capabilities,
                "authentication_plugin": data["authentication_plugin"],
                "confidence": 0.98,
            }

            evidence = [
                "MySQL protocol-10 initial handshake parsed successfully",
                f"MySQL server version: {server_version}",
                f"MySQL connection ID: {connection_id}",
                f"MySQL capability flags: 0x{capabilities:08x}",
            ]
            if data["authentication_plugin"]:
                evidence.append(
                    "Server-advertised authentication plugin: "
                    + data["authentication_plugin"]
                )

            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol="mysql",
                success=True,
                identification_method="mysql_initial_handshake",
                confidence=0.98,
                timestamp=self._timestamp(),
                data=data,
                evidence=tuple(evidence),
            )

        except (TimeoutError, ConnectionResetError, OSError, ValueError, struct.error) as exc:
            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol="mysql",
                success=False,
                identification_method="mysql_handshake_invalid",
                confidence=0.0,
                timestamp=self._timestamp(),
                evidence=(
                    f"MySQL handshake failed: {type(exc).__name__}: {exc}",
                ),
                error=f"mysql_handshake_invalid: {type(exc).__name__}: {exc}",
            )
        finally:
            sock.close()

    def _probe_redis(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
    ) -> ProtocolObservation:
        """Identify Redis with a bounded, unauthenticated RESP PING."""

        deadline = time.monotonic() + self._timeout
        sock = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Redis connection deadline exceeded')
            sock = socket.create_connection((address, port), timeout=remaining)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Redis connection deadline exceeded')
            sock.settimeout(remaining)

            # RESP array encoding avoids ambiguity in inline-command parsing.
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")

            # Read one bounded RESP line, accepting a line exactly at the limit.
            limit = min(self._max_body_bytes, 4096)
            response = bytearray()
            while True:
                line_end = response.find(b"\r\n")
                if line_end >= 0:
                    if line_end + 2 != len(response):
                        raise ValueError(
                            "Unexpected trailing bytes after Redis RESP line"
                        )
                    break

                if len(response) >= limit:
                    raise ValueError(
                        "Redis RESP response line exceeded size limit"
                    )

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Redis response deadline exceeded")
                sock.settimeout(remaining)
                chunk = sock.recv(min(512, limit - len(response)))
                if not chunk:
                    raise ValueError(
                        "Connection closed before a complete RESP line"
                    )
                response.extend(chunk)

                if b"\n" in response and b"\r\n" not in response:
                    raise ValueError("Malformed RESP line ending")
                if (
                    b"\r" in response
                    and not response.endswith(b"\r")
                    and b"\r\n" not in response
                ):
                    raise ValueError("Malformed RESP line ending")
            if not response.endswith(b"\r\n"):
                raise ValueError("Malformed or truncated RESP line")

            try:
                line = bytes(response[:-2]).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("Redis RESP response is not valid UTF-8") from exc

            if "\r" in line or "\n" in line:
                raise ValueError("Malformed control characters in Redis RESP line")

            data = {
                "response_type": line[:1],
                "response": line[1:] if line else "",
                "command": "PING",
                "authentication_attempted": False,
            }

            if line == "+PONG":
                return ProtocolObservation(
                    target=target,
                    address=address,
                    address_family=address_family,
                    port=port,
                    transport="tcp",
                    protocol="redis",
                    success=True,
                    identification_method="redis_resp_ping",
                    confidence=0.99,
                    timestamp=self._timestamp(),
                    data=data,
                    evidence=(
                        "Server returned the exact RESP simple-string PONG "
                        "reply to a Redis-compatible PING command.",
                        "No credentials or data-access commands were sent.",
                    ),
                )

            # These are Redis-specific server error prefixes. Generic RESP
            # errors such as -ERR are deliberately insufficient for proof.
            redis_errors = ("NOAUTH ", "NOPERM ", "DENIED ", "LOADING ", "MASTERDOWN ")
            if line.startswith("-") and line[1:].startswith(redis_errors):
                data["server_error_code"] = line[1:].split(" ", 1)[0]
                return ProtocolObservation(
                    target=target,
                    address=address,
                    address_family=address_family,
                    port=port,
                    transport="tcp",
                    protocol="redis",
                    success=True,
                    identification_method="redis_resp_error_reply",
                    confidence=0.90,
                    timestamp=self._timestamp(),
                    data=data,
                    evidence=(
                        "Server returned a Redis-recognized error code in a "
                        "RESP error reply to PING; authentication was not attempted.",
                    ),
                )

            raise ValueError(
                "Response was not a recognized Redis PING reply"
            )

        except (TimeoutError, ConnectionResetError, OSError, ValueError) as exc:
            return self._error_observation(
                target,
                address,
                address_family,
                port,
                "redis",
                "redis_resp_invalid",
                exc,
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    # Cleanup errors must not override the probe observation.
                    pass

    def _probe_dns(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
        transport: str,
    ) -> ProtocolObservation:
        """Probe DNS over UDP or TCP and preserve structured DNS intelligence."""

        from dataclasses import asdict

        dns_probe = DnsProbe(timeout=self._timeout)

        observation = dns_probe.probe(
            target,
            address,
            address_family,
            port,
            transport=transport,
        )

        data = asdict(observation)

        return ProtocolObservation(
            target=target,
            address=address,
            address_family=address_family,
            port=port,
            transport=transport,
            protocol="dns",
            success=observation.success,
            identification_method=observation.identification_method,
            confidence=observation.confidence,
            timestamp=observation.timestamp,
            data=data,
            evidence=observation.evidence,
            error=observation.error,
        )

    def _probe_smtp(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int,
    ) -> ProtocolObservation:
        """Probe SMTP greeting and capabilities without authentication or mail I/O."""

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

            implicit_tls = port == 465

            data: dict[str, Any] = {
                "implicit_tls": implicit_tls,
                "greeting_code": None,
                "greeting_lines": [],
                "banner": "",
                "commands": {},
                "capabilities": [],
                "capability_details": [],
                "capability_groups": self._group_smtp_capabilities([]),
                "auth": {
                    "advertised": False,
                    "mechanisms": [],
                    "mechanism_classes": {},
                },
                "ehlo": None,
                "helo": None,
                "starttls": {
                    "advertised": False,
                    "response_code": None,
                    "accepted": False,
                    "handshake": implicit_tls,
                    "tls_version": None,
                    "cipher": None,
                    "peer_certificate": None,
                    "post_tls_ehlo": None,
                    "post_tls_capabilities": [],
                    "error": None,
                },
            }

            evidence = []

            if implicit_tls:
                if self._config is None:
                    return ProtocolObservation(
                        target=target,
                        address=address,
                        address_family=address_family,
                        port=port,
                        transport="tcp",
                        protocol="smtp",
                        success=False,
                        identification_method="implicit_tls_configuration_missing",
                        confidence=0.0,
                        timestamp=self._timestamp(),
                        evidence=(
                            "SMTPS requires TLS configuration.",
                        ),
                        error="implicit_tls_configuration_missing",
                    )

                try:
                    context = ssl_context(self._config)

                    server_hostname = (
                        target
                        if not ProtocolProbe._is_ip_address(target)
                        else None
                    )

                    sock = context.wrap_socket(
                        sock,
                        server_hostname=server_hostname,
                    )
                    sock.settimeout(self._timeout)

                    data["starttls"]["tls_version"] = sock.version()
                    data["starttls"]["cipher"] = sock.cipher()
                    data["starttls"]["tls_security"] = (
                        self._classify_smtp_tls_security(
                            data["starttls"]["tls_version"],
                            data["starttls"]["cipher"],
                        )
                    )

                    certificate = sock.getpeercert()
                    data["starttls"]["peer_certificate"] = {
                        "subject": certificate.get("subject"),
                        "issuer": certificate.get("issuer"),
                        "serial_number": certificate.get("serialNumber"),
                        "not_before": certificate.get("notBefore"),
                        "not_after": certificate.get("notAfter"),
                        "subjectAltName": certificate.get(
                            "subjectAltName"
                        ),
                    }
                    data["starttls"]["certificate_analysis"] = (
                        self._analyze_smtp_certificate(
                            certificate,
                            target,
                        )
                    )

                    evidence.append(
                        "SMTP implicit TLS handshake completed successfully."
                    )

                except (
                    ssl.SSLError,
                    TimeoutError,
                    ConnectionResetError,
                    OSError,
                    ValueError,
                ) as exc:
                    data["starttls"]["handshake"] = False
                    data["starttls"]["error"] = (
                        f"{type(exc).__name__}: {exc}"
                    )

                    return ProtocolObservation(
                        target=target,
                        address=address,
                        address_family=address_family,
                        port=port,
                        transport="tcp",
                        protocol="smtp",
                        success=False,
                        identification_method="implicit_tls_failed",
                        confidence=0.0,
                        timestamp=self._timestamp(),
                        data=data,
                        evidence=(
                            "SMTP implicit TLS handshake failed: "
                            f"{type(exc).__name__}: {exc}",
                        ),
                        error=(
                            f"implicit_tls_failed: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                    )

            greeting = self._smtp_read_response(
                sock,
                response_buffer,
            )

            if greeting is None:
                return ProtocolObservation(
                    target=target,
                    address=address,
                    address_family=address_family,
                    port=port,
                    transport="tcp",
                    protocol="smtp",
                    success=False,
                    identification_method="smtp_greeting_missing",
                    confidence=0.0,
                    timestamp=self._timestamp(),
                    evidence=(
                        "SMTP server did not provide a valid greeting.",
                    ),
                    error="smtp_greeting_missing",
                )

            greeting_code, greeting_lines = greeting

            data["greeting_code"] = greeting_code
            data["greeting_lines"] = greeting_lines
            data["banner"] = "\n".join(greeting_lines)
            data["status_analysis"] = {
                "greeting": self._analyze_smtp_response_status(
                    greeting_code,
                    greeting_lines,
                )
            }
            data["greeting_identity"] = self._analyze_smtp_greeting(
                greeting_code,
                greeting_lines,
            )

            evidence.extend([
                "SMTP protocol confirmed by server greeting.",
                f"SMTP greeting response code: {greeting_code}",
            ])

            if greeting_lines:
                evidence.append(
                    f"SMTP server greeting: {greeting_lines[0]}"
                )

            if implicit_tls:
                evidence.append(
                    "SMTP service identified as implicit-TLS/SMTPS on port 465."
                )

            ehlo_response = self._smtp_command(
                sock,
                "EHLO SentinelForge",
                response_buffer,
            )

            if ehlo_response is not None:
                ehlo_code, ehlo_lines = ehlo_response

                data["commands"]["ehlo"] = {
                    "code": ehlo_code,
                    "lines": ehlo_lines,
                    "status": self._classify_smtp_response(ehlo_code),
                    "status_analysis": self._analyze_smtp_response_status(
                        ehlo_code, ehlo_lines
                    ),
                }

                starttls_detail = next(
                    (
                        item
                        for item in data["capability_details"]
                        if item.get("name") == "STARTTLS"
                    ),
                    None,
                )

                previous_tls = data.get("starttls", {})

                data["starttls"] = {
                    "advertised": starttls_detail is not None,
                    "response_code": None,
                    "accepted": False,
                    "handshake": bool(previous_tls.get("handshake")),
                    "tls_version": previous_tls.get("tls_version"),
                    "cipher": previous_tls.get("cipher"),
                    "peer_certificate": previous_tls.get("peer_certificate"),
                    "certificate_analysis": previous_tls.get(
                        "certificate_analysis"
                    ),
                    "post_tls_ehlo": None,
                    "post_tls_capabilities": [],
                    "post_tls_capability_details": [],
                    "error": previous_tls.get("error"),
                }

                data["ehlo"] = {
                    "accepted": 200 <= ehlo_code < 300,
                    "code": ehlo_code,
                    "lines": ehlo_lines,
                }

                evidence.append(
                    f"SMTP EHLO response code: {ehlo_code}"
                )

                if 200 <= ehlo_code < 300:
                    capabilities = []
                    capability_details = []

                    for line in ehlo_lines:
                        stripped = line.strip()

                        if not stripped:
                            continue

                        if stripped[:3].isdigit():
                            if len(stripped) <= 4:
                                continue
                            payload = stripped[4:].strip()
                        else:
                            payload = stripped

                        if not payload:
                            continue

                        parts = payload.split(None, 1)
                        name = parts[0].upper()
                        arguments = (
                            parts[1].strip()
                            if len(parts) > 1
                            else None
                        )

                        capabilities.append(name)
                        capability_details.append(
                            {
                                "name": name,
                                "arguments": arguments,
                                "raw": payload,
                            }
                        )

                    data["capabilities"] = list(
                        dict.fromkeys(capabilities)
                    )
                    data["capability_details"] = capability_details
                    data["capability_groups"] = (
                        self._group_smtp_capabilities(
                            data["capability_details"]
                        )
                    )
                    data["auth"] = self._analyze_smtp_auth(
                        data["capability_details"]
                    )
                    data["auth"]["status_analysis"] = (
                        self._analyze_smtp_auth_status(
                            data["auth"],
                            tls_active=bool(
                                data.get("starttls", {}).get("handshake")
                            ),
                        )
                    )
                    data["capability_parameters"] = (
                        self._analyze_smtp_capability_parameters(
                            data["capability_details"]
                        )
                    )
                    data["extension_relationships"] = (
                        self._analyze_smtp_extension_relationships(
                            data["capabilities"],
                            data["capability_details"],
                        )
                    )

                    if capabilities:
                        evidence.append(
                            "SMTP advertised capabilities: "
                            + ", ".join(data["capabilities"])
                        )

                        for group, values in data[
                            "capability_groups"
                        ].items():
                            if values:
                                evidence.append(
                                    f"SMTP {group} capabilities: "
                                    + ", ".join(values)
                                )

                    if (
                        data["starttls"]["advertised"]
                        and self._config is not None
                    ):
                        starttls_response = self._smtp_command(
                            sock,
                            "STARTTLS",
                            response_buffer,
                        )

                        if starttls_response is None:
                            data["starttls"]["error"] = (
                                "STARTTLS produced no valid response."
                            )
                            evidence.append(
                                "SMTP STARTTLS was advertised but produced "
                                "no valid response."
                            )
                        else:
                            tls_code, tls_lines = starttls_response
                            data["starttls"]["response_code"] = tls_code
                            data["commands"]["starttls"] = {
                                "code": tls_code,
                                "lines": tls_lines,
                                "status": self._classify_smtp_response(
                                    tls_code
                                ),
                                "status_analysis": (
                                    self._analyze_smtp_response_status(
                                        tls_code, tls_lines
                                    )
                                ),
                            }

                            if 200 <= tls_code < 300:
                                data["starttls"]["accepted"] = True
                                evidence.append(
                                    f"SMTP STARTTLS accepted with code "
                                    f"{tls_code}."
                                )

                                try:
                                    context = ssl_context(self._config)

                                    server_hostname = (
                                        target
                                        if not ProtocolProbe._is_ip_address(target)
                                        else None
                                    )

                                    tls_sock = context.wrap_socket(
                                        sock,
                                        server_hostname=server_hostname,
                                    )
                                    sock = tls_sock
                                    sock.settimeout(self._timeout)

                                    data["starttls"]["handshake"] = True
                                    data["starttls"]["tls_version"] = (
                                        sock.version()
                                    )
                                    data["starttls"]["cipher"] = (
                                        sock.cipher()
                                    )
                                    data["starttls"]["tls_security"] = (
                                        self._classify_smtp_tls_security(
                                            data["starttls"]["tls_version"],
                                            data["starttls"]["cipher"],
                                        )
                                    )

                                    certificate_der = (
                                        sock.getpeercert(
                                            binary_form=True
                                        )
                                    )
                                    certificate = sock.getpeercert()

                                    if certificate_der:
                                        data["starttls"][
                                            "certificate_analysis"
                                        ] = (
                                            self._analyze_smtp_certificate(
                                                certificate_der,
                                                target,
                                            )
                                        )

                                    data["starttls"]["peer_certificate"] = {
                                        "subject": certificate.get(
                                            "subject"
                                        ),
                                        "issuer": certificate.get(
                                            "issuer"
                                        ),
                                        "serial_number": certificate.get(
                                            "serialNumber"
                                        ),
                                        "not_before": certificate.get(
                                            "notBefore"
                                        ),
                                        "not_after": certificate.get(
                                            "notAfter"
                                        ),
                                        "subjectAltName": certificate.get(
                                            "subjectAltName"
                                        ),
                                    }

                                    data["starttls"]["certificate_analysis"] = (
                                        self._analyze_smtp_certificate(
                                            certificate,
                                            target,
                                        )
                                    )

                                    evidence.append(
                                        "SMTP STARTTLS TLS handshake "
                                        "completed successfully."
                                    )

                                    post_tls_buffer = bytearray()

                                    post_tls_ehlo = self._smtp_command(
                                        sock,
                                        "EHLO SentinelForge",
                                        post_tls_buffer,
                                    )

                                    if post_tls_ehlo is not None:
                                        post_code, post_lines = (
                                            post_tls_ehlo
                                        )

                                        post_capabilities = []
                                        post_details = []

                                        if 200 <= post_code < 300:
                                            for line in post_lines:
                                                stripped = line.strip()

                                                if not stripped:
                                                    continue

                                                if (
                                                    stripped[:3].isdigit()
                                                    and len(stripped) > 4
                                                ):
                                                    payload = stripped[
                                                        4:
                                                    ].strip()
                                                else:
                                                    payload = stripped

                                                if not payload:
                                                    continue

                                                parts = payload.split(
                                                    None,
                                                    1,
                                                )
                                                name = parts[0].upper()
                                                arguments = (
                                                    parts[1].strip()
                                                    if len(parts) > 1
                                                    else None
                                                )

                                                post_capabilities.append(
                                                    name
                                                )
                                                post_details.append(
                                                    {
                                                        "name": name,
                                                        "arguments": arguments,
                                                        "raw": payload,
                                                    }
                                                )

                                        post_capabilities = list(
                                            dict.fromkeys(
                                                post_capabilities
                                            )
                                        )

                                        data["starttls"][
                                            "post_tls_ehlo"
                                        ] = {
                                            "code": post_code,
                                            "lines": post_lines,
                                            "accepted": (
                                                200
                                                <= post_code
                                                < 300
                                            ),
                                        }

                                        data["starttls"][
                                            "post_tls_capabilities"
                                        ] = post_capabilities

                                        data["starttls"][
                                            "post_tls_capability_details"
                                        ] = post_details

                                        data["starttls"][
                                            "post_tls_capability_parameters"
                                        ] = (
                                            self._analyze_smtp_capability_parameters(
                                                post_details
                                            )
                                        )
                                        data["starttls"][
                                            "post_tls_extension_relationships"
                                        ] = (
                                            self._analyze_smtp_extension_relationships(
                                                post_capabilities,
                                                post_details,
                                            )
                                        )

                                        post_tls_auth = self._analyze_smtp_auth(
                                            post_details
                                        )
                                        data["starttls"][
                                            "post_tls_auth_status_analysis"
                                        ] = self._analyze_smtp_auth_status(
                                            post_tls_auth,
                                            tls_active=True,
                                        )

                                        if post_capabilities:
                                            evidence.append(
                                                "SMTP post-TLS capabilities: "
                                                + ", ".join(
                                                    post_capabilities
                                                )
                                            )
                                    else:
                                        data["starttls"][
                                            "error"
                                        ] = (
                                            "Post-TLS EHLO produced no "
                                            "valid response."
                                        )

                                except (
                                    ssl.SSLError,
                                    TimeoutError,
                                    ConnectionResetError,
                                    OSError,
                                    ValueError,
                                ) as exc:
                                    data["starttls"]["error"] = (
                                        f"{type(exc).__name__}: {exc}"
                                    )
                                    evidence.append(
                                        "SMTP STARTTLS TLS handshake "
                                        f"failed: {type(exc).__name__}: "
                                        f"{exc}"
                                    )
                            else:
                                data["starttls"]["error"] = (
                                    f"STARTTLS rejected with code "
                                    f"{tls_code}."
                                )
                                evidence.append(
                                    f"SMTP STARTTLS rejected with code "
                                    f"{tls_code}."
                                )
                else:
                    helo_response = self._smtp_command(
                        sock,
                        "HELO SentinelForge",
                        response_buffer,
                    )

                    if helo_response is not None:
                        helo_code, helo_lines = helo_response

                        data["commands"]["helo"] = {
                            "code": helo_code,
                            "lines": helo_lines,
                            "status": self._classify_smtp_response(
                                helo_code
                            ),
                            "status_analysis": (
                                self._analyze_smtp_response_status(
                                    helo_code, helo_lines
                                )
                            ),
                        }

                        data["helo"] = {
                            "accepted": 200 <= helo_code < 300,
                            "code": helo_code,
                            "lines": helo_lines,
                        }

                        evidence.append(
                            f"SMTP HELO response code: {helo_code}"
                        )
                    else:
                        data["commands"]["helo"] = {
                            "code": None,
                            "lines": [],
                            "status": "no_response",
                        }

                        evidence.append(
                            "SMTP HELO produced no valid response."
                        )
            else:
                data["commands"]["ehlo"] = {
                    "code": None,
                    "lines": [],
                    "status": "no_response",
                }

                evidence.append(
                    "SMTP EHLO produced no valid response."
                )

            data["tls_capability_comparison"] = (
                self._compare_smtp_tls_capabilities(data)
            )

            data["session_probe"] = self._probe_smtp_session_commands(
                sock=sock,
                response_buffer=response_buffer,
            )

            data["session_state_analysis"] = (
                self._analyze_smtp_session_state(
                    data["session_probe"]
                )
            )

            for command_name, details in data["session_probe"].items():
                status = details.get("status")
                code = details.get("code")
                evidence.append(
                    f"SMTP {command_name.upper()} response: "
                    f"{code if code is not None else status}"
                )

            data["fingerprint"] = self._build_smtp_fingerprint(
                target=target,
                address=address,
                port=port,
                data=data,
            )

            data["identity_consistency"] = (
                self._analyze_smtp_identity_consistency(
                    greeting_identity=data.get("greeting_identity"),
                    ehlo=data.get("ehlo"),
                    helo=data.get("helo"),
                    software=data["fingerprint"].get("software", []),
                    capabilities=data.get("capabilities", []),
                )
            )

            data["post_tls_identity_consistency"] = (
                self._analyze_smtp_post_tls_identity(
                    identity_consistency=data["identity_consistency"],
                    post_tls_ehlo=data.get("starttls", {}).get(
                        "post_tls_ehlo"
                    ),
                )
            )

            data["fingerprint"]["identity"]["consistency"] = (
                dict(data["identity_consistency"])
            )

            data["fingerprint"]["identity"]["post_tls_consistency"] = (
                dict(data["post_tls_identity_consistency"])
            )

            data["session"] = {
                "protocol": "smtp",
                "greeting": {
                    "code": greeting_code,
                    "present": bool(greeting_lines),
                },
                "capabilities": {
                    "advertised": list(data["capabilities"]),
                    "details": list(data["capability_details"]),
                    "groups": dict(data["capability_groups"]),
                },
                "command_status": {
                    name: details.get("status")
                    for name, details in data["commands"].items()
                },
                "starttls": dict(data["starttls"]),
                "auth": dict(data["auth"]),
            }

            return ProtocolObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport="tcp",
                protocol="smtp",
                success=True,
                identification_method="smtp_greeting_and_ehlo_probe",
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
                "smtp",
                "connection_failed",
                exc,
            )
        finally:
            sock.close()

    @staticmethod
    def _analyze_smtp_session_state(
        results: dict[str, dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Interpret harmless SMTP session-command behavior."""

        results = results or {}

        expected_codes = {
            "noop": {200, 250},
            "rset": {200, 250},
            "help": {200, 214, 250},
            "quit": {221},
        }

        command_analysis: dict[str, Any] = {}
        anomalies: list[dict[str, Any]] = []

        for command_name, details in results.items():
            code = details.get("code")
            status = details.get("status", "unknown")
            expected = expected_codes.get(command_name, set())

            if code is None:
                semantic = "no_response"
            elif code in expected:
                if command_name == "noop":
                    semantic = "session_alive"
                elif command_name == "rset":
                    semantic = "session_reset_accepted"
                elif command_name == "help":
                    semantic = "help_available"
                elif command_name == "quit":
                    semantic = "session_closed"
                else:
                    semantic = "expected_response"
            elif 400 <= code < 500:
                semantic = "temporary_rejection"
            elif 500 <= code < 600:
                semantic = "permanent_rejection"
            else:
                semantic = "unexpected_response"

            command_analysis[command_name] = {
                "code": code,
                "status": status,
                "expected_codes": sorted(expected),
                "semantic": semantic,
                "status_analysis": details.get("status_analysis"),
                "enhanced_status": details.get("enhanced_status"),
            }

            if code is not None and expected and code not in expected:
                anomalies.append(
                    {
                        "code": f"{command_name}_unexpected_response",
                        "severity": "low",
                        "confidence": 0.90,
                        "description": (
                            f"SMTP {command_name.upper()} returned "
                            f"unexpected response code {code}."
                        ),
                        "evidence": details.get("lines", []),
                    }
                )

            if status == "error":
                anomalies.append(
                    {
                        "code": f"{command_name}_session_error",
                        "severity": "low",
                        "confidence": 0.95,
                        "description": (
                            f"SMTP {command_name.upper()} encountered "
                            "a session-level transport or protocol error."
                        ),
                        "evidence": [str(details.get("error", "unknown error"))],
                    }
                )

        if "quit" in results:
            quit_code = results["quit"].get("code")
            if quit_code is not None and quit_code != 221:
                anomalies.append(
                    {
                        "code": "quit_did_not_close_cleanly",
                        "severity": "low",
                        "confidence": 0.95,
                        "description": (
                            "SMTP QUIT did not return the expected 221 "
                            "service-closing response."
                        ),
                        "evidence": results["quit"].get("lines", []),
                    }
                )

        return {
            "commands": command_analysis,
            "anomalies": anomalies,
            "command_count": len(command_analysis),
            "anomaly_count": len(anomalies),
        }

    def _probe_smtp_session_commands(
        self,
        *,
        sock: socket.socket,
        response_buffer: bytearray,
    ) -> dict[str, dict[str, Any]]:
        """Probe harmless SMTP session commands without mail or authentication."""

        results: dict[str, dict[str, Any]] = {}

        for command_name, command in (
            ("noop", "NOOP"),
            ("rset", "RSET"),
            ("help", "HELP"),
            ("quit", "QUIT"),
        ):
            try:
                response = self._smtp_command(
                    sock,
                    command,
                    response_buffer,
                )

                if response is None:
                    results[command_name] = {
                        "code": None,
                        "lines": [],
                        "status": "no_response",
                        "status_analysis": self._analyze_smtp_response_status(
                            None,
                            [],
                        ),
                    }
                    continue

                code, lines = response

                results[command_name] = {
                    "code": code,
                    "lines": lines,
                    "status": self._classify_smtp_response(code),
                    "enhanced_status": self._parse_smtp_enhanced_status(
                        lines
                    ),
                    "status_analysis": self._analyze_smtp_response_status(
                        code,
                        lines,
                    ),
                }

                if command_name == "quit":
                    break

            except (
                TimeoutError,
                ConnectionResetError,
                BrokenPipeError,
                OSError,
                ValueError,
            ) as exc:
                results[command_name] = {
                    "code": None,
                    "lines": [],
                    "status": "error",
                    "status_analysis": self._analyze_smtp_response_status(
                        None,
                        [],
                    ),
                    "error": f"{type(exc).__name__}: {exc}",
                }

                if command_name == "quit":
                    break

        anomalies: list[dict[str, Any]] = []

        expected_codes = {
            "noop": {200, 250},
            "rset": {200, 250},
            "help": {200, 214, 250},
            "quit": {221},
        }

        for command_name, details in results.items():
            code = details.get("code")

            if code is None:
                continue

            if code not in expected_codes[command_name]:
                anomalies.append(
                    {
                        "code": "unexpected_response",
                        "severity": "low",
                        "confidence": 0.90,
                        "command": command_name.upper(),
                        "description": (
                            f"SMTP {command_name.upper()} returned "
                            f"unexpected response code {code}."
                        ),
                        "evidence": list(details.get("lines", [])),
                    }
                )

        quit_result = results.get("quit")

        if quit_result is not None:
            quit_code = quit_result.get("code")

            if quit_code is not None and quit_code != 221:
                anomalies.append(
                    {
                        "code": "quit_semantics",
                        "severity": "low",
                        "confidence": 0.95,
                        "command": "QUIT",
                        "description": (
                            "SMTP QUIT did not return the expected "
                            "221 closing response."
                        ),
                        "evidence": list(quit_result.get("lines", [])),
                    }
                )

        results["_analysis"] = {
            "commands_attempted": [
                name.upper()
                for name in results
                if name != "_analysis"
            ],
            "quit_observed": "quit" in results,
            "connection_close_expected": "quit" in results,
            "anomalies": anomalies,
        }

        return results

    @staticmethod
    def _classify_smtp_tls_security(
        tls_version: str | None,
        cipher: tuple | None,
    ) -> dict[str, Any]:
        """Classify negotiated SMTP TLS version and cipher security."""
        version_value = str(tls_version) if tls_version else None

        if version_value in {"TLSv1.3", "TLSv1.2"}:
            version_classification = "modern"
        elif version_value in {"TLSv1.1", "TLSv1.0"}:
            version_classification = "legacy"
        elif version_value in {"SSLv3", "SSLv2"}:
            version_classification = "obsolete"
        else:
            version_classification = "unknown"

        cipher_name = None
        cipher_protocol = None
        cipher_bits = None

        if cipher:
            if len(cipher) >= 1:
                cipher_name = cipher[0]
            if len(cipher) >= 2:
                cipher_protocol = cipher[1]
            if len(cipher) >= 3:
                cipher_bits = cipher[2]

        cipher_name_upper = str(cipher_name or "").upper()

        weak_cipher_markers = (
            "RC4",
            "3DES",
            "DES-CBC",
            "DES40",
            "EXPORT",
            "NULL",
            "ANON",
            "MD5",
            "RC2",
            "AES128-SHA",
            "AES256-SHA",
        )

        if not cipher_name:
            cipher_classification = "unknown"
        elif any(marker in cipher_name_upper for marker in weak_cipher_markers):
            cipher_classification = "weak"
        elif cipher_bits is not None and cipher_bits < 128:
            cipher_classification = "weak"
        elif (
            "AES" in cipher_name_upper
            or "CHACHA20" in cipher_name_upper
            or "ARIA" in cipher_name_upper
            or "CAMELLIA" in cipher_name_upper
        ) and (
            cipher_bits is None or cipher_bits >= 128
        ):
            cipher_classification = "strong"
        else:
            cipher_classification = "unknown"

        issues = []

        if version_classification == "legacy":
            issues.append("legacy_tls_version")
        elif version_classification == "obsolete":
            issues.append("obsolete_tls_version")

        if cipher_classification == "weak":
            issues.append("weak_cipher")

        if version_classification == "unknown" or cipher_classification == "unknown":
            issues.append("missing_tls_metadata")

        if (
            version_classification in {"legacy", "obsolete"}
            or cipher_classification == "weak"
        ):
            overall = "weak"
        elif version_classification == "modern" and cipher_classification == "strong":
            overall = "strong"
        else:
            overall = "unknown"

        return {
            "version": {
                "value": version_value,
                "classification": version_classification,
            },
            "cipher": {
                "name": cipher_name,
                "protocol": cipher_protocol,
                "bits": cipher_bits,
                "classification": cipher_classification,
            },
            "classification": overall,
            "issues": issues,
        }

    @staticmethod
    def _smtp_dns_name_matches(hostname: str, pattern: str) -> bool:
        """Match a hostname against a certificate DNS name.

        Wildcards are restricted to a complete leftmost label and match
        exactly one DNS label.
        """
        if not isinstance(hostname, str) or not isinstance(pattern, str):
            return False

        hostname = hostname.strip().rstrip(".").lower()
        pattern = pattern.strip().rstrip(".").lower()

        if not hostname or not pattern:
            return False

        if "*" not in pattern:
            return hostname == pattern

        labels = pattern.split(".")

        if labels[0] != "*":
            return False

        if any("*" in label for label in labels[1:]):
            return False

        hostname_labels = hostname.split(".")

        if len(hostname_labels) != len(labels):
            return False

        return hostname_labels[1:] == labels[1:]

    @staticmethod
    def _analyze_smtp_certificate(
        certificate: dict[str, Any] | bytes,
        target: str | None = None,
    ) -> dict[str, Any]:
        """Analyze SMTP TLS certificate identity, validity, and security metadata."""
        if not certificate:
            return {
                "present": False,
                "subject": None,
                "issuer": None,
                "serial_number": None,
                "not_before": None,
                "not_after": None,
                "san": [],
                "hostname_state": "unknown",
                "self_signed": False,
                "validity": {
                    "state": "unknown",
                    "not_before": None,
                    "not_after": None,
                },
                "security": {
                    "version": None,
                    "signature_algorithm": None,
                    "public_key_algorithm": None,
                    "public_key_bits": None,
                },
            }

        from email.utils import parsedate_to_datetime

        if isinstance(certificate, bytes):
            from cryptography import x509

            parsed_certificate = x509.load_der_x509_certificate(certificate)

            san = []
            try:
                san_extension = (
                    parsed_certificate.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                )
                for name in san_extension.value:
                    if isinstance(name, x509.DNSName):
                        san.append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        san.append(str(name.value))
            except x509.ExtensionNotFound:
                pass

            public_key = parsed_certificate.public_key()
            public_key_algorithm = type(public_key).__name__.replace(
                "PublicKey", ""
            )
            public_key_bits = getattr(public_key, "key_size", None)

            signature_algorithm = (
                parsed_certificate.signature_hash_algorithm.name
                if parsed_certificate.signature_hash_algorithm is not None
                else None
            )

            from datetime import datetime, timezone

            now = datetime.now(timezone.utc)

            if now < parsed_certificate.not_valid_before_utc:
                validity_state = "not_yet_valid"
            elif now > parsed_certificate.not_valid_after_utc:
                validity_state = "expired"
            else:
                validity_state = "currently_valid"

            return {
                "present": True,
                "subject": parsed_certificate.subject.rfc4514_string(),
                "issuer": parsed_certificate.issuer.rfc4514_string(),
                "serial_number": str(parsed_certificate.serial_number),
                "not_before": parsed_certificate.not_valid_before_utc.isoformat(),
                "not_after": parsed_certificate.not_valid_after_utc.isoformat(),
                "san": san,
                "hostname_state": "unknown",
                "self_signed": (
                    parsed_certificate.subject
                    == parsed_certificate.issuer
                ),
                "validity": {
                    "state": validity_state,
                    "not_before": parsed_certificate.not_valid_before_utc.isoformat(),
                    "not_after": parsed_certificate.not_valid_after_utc.isoformat(),
                },
                "security": {
                    "version": parsed_certificate.version.value + 1,
                    "signature_algorithm": signature_algorithm,
                    "public_key_algorithm": public_key_algorithm,
                    "public_key_bits": public_key_bits,
                },
                "fingerprint_sha256": (
                    parsed_certificate.fingerprint(
                        hashes.SHA256()
                    ).hex()
                ),
            }

        san = []
        for entry in certificate.get("subjectAltName") or ():
            if len(entry) >= 2 and entry[0] in {"DNS", "IP Address"}:
                san.append(str(entry[1]))

        subject = certificate.get("subject")
        issuer = certificate.get("issuer")

        validity_state = "unknown"
        not_before = certificate.get("notBefore")
        not_after = certificate.get("notAfter")

        try:
            now = __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            )

            before = parsedate_to_datetime(not_before) if not_before else None
            after = parsedate_to_datetime(not_after) if not_after else None

            if before is not None and after is not None:
                if before.tzinfo is None:
                    before = before.replace(
                        tzinfo=__import__("datetime").timezone.utc
                    )
                if after.tzinfo is None:
                    after = after.replace(
                        tzinfo=__import__("datetime").timezone.utc
                    )

                if now < before:
                    validity_state = "not_yet_valid"
                elif now > after:
                    validity_state = "expired"
                else:
                    validity_state = "currently_valid"
        except (TypeError, ValueError, OverflowError):
            validity_state = "unknown"

        return {
            "present": True,
            "subject": subject,
            "issuer": issuer,
            "serial_number": certificate.get("serialNumber"),
            "not_before": not_before,
            "not_after": not_after,
            "san": san,
            "hostname_state": (
                "unknown"
                if not target or not san
                else (
                    "verified"
                    if any(
                        (
                            ProtocolProbe._smtp_dns_name_matches(target, str(name))
                            if str(name).strip()
                            else False
                        )
                        for name in san
                        if not ProtocolProbe._is_ip_address(target)
                        and not ProtocolProbe._is_ip_address(str(name))
                    )
                    or any(
                        str(name).strip() == target.strip()
                        for name in san
                        if ProtocolProbe._is_ip_address(target)
                        and ProtocolProbe._is_ip_address(str(name))
                    )
                    else "mismatch"
                )
            ),
            "self_signed": bool(subject and issuer and subject == issuer),
            "validity": {
                "state": validity_state,
                "not_before": not_before,
                "not_after": not_after,
            },
            "security": {
                "version": certificate.get("version"),
                "signature_algorithm": certificate.get("signatureAlgorithm"),
                "public_key_algorithm": certificate.get("publicKeyAlgorithm"),
                "public_key_bits": certificate.get("publicKeyBits"),
            },
        }

    @staticmethod
    def _compare_smtp_tls_capabilities(
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare SMTP capabilities and AUTH mechanisms before and after TLS."""

        pre_tls = {
            str(item).upper()
            for item in data.get("capabilities", [])
            if item
        }

        starttls = data.get("starttls", {})
        post_tls = {
            str(item).upper()
            for item in starttls.get(
                "post_tls_capabilities",
                [],
            )
            if item
        }

        pre_auth = data.get("auth", {})
        pre_mechanisms = {
            str(item).upper()
            for item in pre_auth.get("mechanisms", [])
            if item
        }

        post_mechanisms: set[str] = set()

        for item in starttls.get(
            "post_tls_capability_details",
            [],
        ):
            if not isinstance(item, dict):
                continue

            name = str(item.get("name", "")).upper()
            arguments = str(item.get("arguments") or "")

            if name == "AUTH":
                post_mechanisms.update(
                    part.upper()
                    for part in arguments.split()
                    if part
                )

        added = sorted(post_tls - pre_tls)
        removed = sorted(pre_tls - post_tls)
        auth_added = sorted(post_mechanisms - pre_mechanisms)
        auth_removed = sorted(pre_mechanisms - post_mechanisms)

        anomalies: list[dict[str, Any]] = []

        if starttls.get("handshake") and not post_tls:
            anomalies.append(
                {
                    "code": "missing_post_tls_capabilities",
                    "severity": "low",
                    "confidence": 0.90,
                    "description": (
                        "SMTP STARTTLS completed but no post-TLS "
                        "capabilities were observed."
                    ),
                }
            )

        if auth_added:
            anomalies.append(
                {
                    "code": "auth_enabled_after_tls",
                    "severity": "info",
                    "confidence": 0.95,
                    "description": (
                        "SMTP AUTH mechanisms became available "
                        "after TLS negotiation."
                    ),
                    "mechanisms": auth_added,
                }
            )

        if auth_removed:
            anomalies.append(
                {
                    "code": "auth_changed_after_tls",
                    "severity": "low",
                    "confidence": 0.95,
                    "description": (
                        "SMTP AUTH mechanisms changed after TLS negotiation."
                    ),
                    "removed": auth_removed,
                }
            )

        return {
            "pre_tls_capabilities": sorted(pre_tls),
            "post_tls_capabilities": sorted(post_tls),
            "capabilities_added_after_tls": added,
            "capabilities_removed_after_tls": removed,
            "pre_tls_auth_mechanisms": sorted(pre_mechanisms),
            "post_tls_auth_mechanisms": sorted(post_mechanisms),
            "auth_added_after_tls": auth_added,
            "auth_removed_after_tls": auth_removed,
            "changed": bool(
                added
                or removed
                or auth_added
                or auth_removed
            ),
            "anomalies": anomalies,
        }

    @staticmethod
    def _analyze_smtp_identity_consistency(
        *,
        greeting_identity: dict[str, Any] | None,
        ehlo: dict[str, Any] | None,
        helo: dict[str, Any] | None,
        software: list[dict[str, str]] | None = None,
        capabilities: list[str] | None = None,
    ) -> dict[str, Any]:
        """Correlate SMTP server identity across greeting and EHLO/HELO."""

        greeting_identity = greeting_identity or {}
        ehlo = ehlo or {}
        helo = helo or {}
        software = list(software or [])
        capabilities = [
            str(item).upper()
            for item in (capabilities or [])
        ]

        greeting_hostname = greeting_identity.get("hostname")

        def response_hostname(response: dict[str, Any]) -> str | None:
            for line in response.get("lines", []) or []:
                match = re.match(
                    r"^\s*\d{3}[ -]+([^\s]+)",
                    str(line),
                )
                if match:
                    candidate = match.group(1).strip().rstrip(".")
                    if (
                        "." in candidate
                        or candidate.lower() == "localhost"
                    ):
                        return candidate
            return None

        ehlo_hostname = response_hostname(ehlo)
        helo_hostname = response_hostname(helo)

        accepted_ehlo = bool(ehlo.get("accepted"))
        accepted_helo = bool(helo.get("accepted"))

        if accepted_ehlo:
            dialect = "esmtp"
        elif accepted_helo:
            dialect = "smtp"
        else:
            dialect = "unknown"

        anomalies: list[dict[str, Any]] = []

        if (
            greeting_hostname
            and ehlo_hostname
            and greeting_hostname.lower() != ehlo_hostname.lower()
        ):
            anomalies.append(
                {
                    "code": "greeting_ehlo_hostname_mismatch",
                    "severity": "low",
                    "confidence": 0.85,
                    "description": (
                        "SMTP greeting hostname differs from the hostname "
                        "presented in the EHLO response."
                    ),
                    "evidence": [
                        f"Greeting hostname: {greeting_hostname}",
                        f"EHLO hostname: {ehlo_hostname}",
                    ],
                }
            )

        if accepted_ehlo and not capabilities:
            anomalies.append(
                {
                    "code": "esmtp_without_capabilities",
                    "severity": "low",
                    "confidence": 0.80,
                    "description": (
                        "EHLO was accepted but no SMTP extensions were "
                        "observed in the response."
                    ),
                    "evidence": [],
                }
            )

        product_clues = {
            str(item).lower()
            for item in greeting_identity.get("product_clues", [])
        }

        detected_products = {
            str(item.get("product", "")).lower()
            for item in software
            if item.get("product")
        }

        product_matches = bool(
            product_clues.intersection(detected_products)
        )

        if product_clues and detected_products and not product_matches:
            anomalies.append(
                {
                    "code": "greeting_software_identity_mismatch",
                    "severity": "low",
                    "confidence": 0.75,
                    "description": (
                        "Software clues in the SMTP greeting do not match "
                        "the detected SMTP software fingerprint."
                    ),
                    "evidence": [
                        f"Greeting clues: {sorted(product_clues)}",
                        f"Detected software: {sorted(detected_products)}",
                    ],
                }
            )

        return {
            "dialect": dialect,
            "greeting_hostname": greeting_hostname,
            "ehlo_hostname": ehlo_hostname,
            "helo_hostname": helo_hostname,
            "ehlo_accepted": accepted_ehlo,
            "helo_accepted": accepted_helo,
            "product_clues": sorted(product_clues),
            "detected_products": sorted(detected_products),
            "product_identity_consistent": (
                product_matches
                if product_clues and detected_products
                else None
            ),
            "hostname_identity_consistent": (
                greeting_hostname.lower() == (
                    ehlo_hostname if accepted_ehlo else helo_hostname
                ).lower()
                if greeting_hostname
                and (ehlo_hostname if accepted_ehlo else helo_hostname)
                else None
            ),
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
        }

    @staticmethod
    def _analyze_smtp_post_tls_identity(
        *,
        identity_consistency: dict[str, Any] | None,
        post_tls_ehlo: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Correlate SMTP identity before and after STARTTLS."""

        identity_consistency = identity_consistency or {}
        post_tls_ehlo = post_tls_ehlo or {}

        pre_tls_hostname = (
            identity_consistency.get("ehlo_hostname")
            or identity_consistency.get("helo_hostname")
        )

        post_tls_hostname = None

        for line in post_tls_ehlo.get("lines", []) or []:
            match = re.match(
                r"^\s*\d{3}[ -]+([^\s]+)",
                str(line),
            )
            if match:
                candidate = match.group(1).strip().rstrip(".")
                if (
                    "." in candidate
                    or candidate.lower() == "localhost"
                ):
                    post_tls_hostname = candidate
                    break

        post_tls_accepted = bool(post_tls_ehlo.get("accepted"))

        anomalies: list[dict[str, Any]] = []

        if (
            pre_tls_hostname
            and post_tls_hostname
            and pre_tls_hostname.lower() != post_tls_hostname.lower()
        ):
            anomalies.append(
                {
                    "code": "smtp_post_tls_hostname_mismatch",
                    "severity": "low",
                    "confidence": 0.90,
                    "description": (
                        "SMTP server presented a different hostname "
                        "after STARTTLS than before TLS negotiation."
                    ),
                    "evidence": [
                        f"Pre-TLS hostname: {pre_tls_hostname}",
                        f"Post-TLS hostname: {post_tls_hostname}",
                    ],
                }
            )

        if post_tls_ehlo and not post_tls_accepted:
            anomalies.append(
                {
                    "code": "smtp_post_tls_ehlo_rejected",
                    "severity": "low",
                    "confidence": 0.95,
                    "description": (
                        "SMTP server rejected the EHLO command after "
                        "successful TLS negotiation."
                    ),
                    "evidence": list(
                        post_tls_ehlo.get("lines", []) or []
                    ),
                }
            )

        return {
            "pre_tls_hostname": pre_tls_hostname,
            "post_tls_hostname": post_tls_hostname,
            "post_tls_ehlo_accepted": post_tls_accepted,
            "hostname_identity_consistent": (
                pre_tls_hostname.lower() == post_tls_hostname.lower()
                if pre_tls_hostname and post_tls_hostname
                else None
            ),
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
        }

    @staticmethod
    def _build_smtp_fingerprint(
        *,
        target: str,
        address: str,
        port: int,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a composite SMTP fingerprint strictly from observed evidence."""

        capabilities = [
            str(item).upper()
            for item in data.get("capabilities", [])
        ]

        capability_details = data.get("capability_details", [])
        auth = data.get("auth", {})
        starttls = data.get("starttls", {})

        greeting_lines = data.get("greeting_lines", [])
        banner = data.get("banner", "")

        products: list[dict[str, str]] = []

        version_patterns = {
            "Postfix": re.compile(
                r"\bPostfix(?:\s+SMTP)?\b.*?\b([0-9]+(?:\.[0-9]+)+)\b",
                re.IGNORECASE,
            ),
            "Exim": re.compile(
                r"\bExim\s+(?:ESMTP\s+)?([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
            "Sendmail": re.compile(
                r"\bSendmail(?:\s+version)?\s+([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
            "OpenSMTPD": re.compile(
                r"\bOpenSMTPD(?:\s+ESMTP)?\s+([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
            "Haraka": re.compile(
                r"\bHaraka(?:\s+ESMTP)?\s+([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
            "qmail": re.compile(
                r"\bqmail(?:-smtpd)?[^0-9]*([0-9]+(?:\.[0-9]+)+)",
                re.IGNORECASE,
            ),
        }

        for product, pattern in version_patterns.items():
            match = pattern.search(banner)
            if match:
                products.append(
                    {
                        "product": product,
                        "version": match.group(1),
                        "source": "smtp_banner",
                    }
                )

        tls_state = "not_advertised"

        if starttls.get("advertised"):
            if starttls.get("handshake"):
                tls_state = "starttls_success"
            elif starttls.get("accepted"):
                tls_state = "starttls_accepted_handshake_failed"
            elif starttls.get("response_code") is not None:
                tls_state = "starttls_rejected"
            else:
                tls_state = "starttls_advertised"

        if data.get("implicit_tls"):
            tls_state = (
                "implicit_tls_success"
                if starttls.get("handshake")
                else "implicit_tls_failed"
            )

        capability_set = set(capabilities)

        transport_features = [
            name
            for name in (
                "PIPELINING",
                "CHUNKING",
                "BINARYMIME",
                "8BITMIME",
            )
            if name in capability_set
        ]

        delivery_features = [
            name
            for name in (
                "DSN",
                "ETRN",
                "ATRN",
                "VERP",
                "XVERP",
                "XEXPS",
            )
            if name in capability_set
        ]

        internationalization = [
            name
            for name in (
                "SMTPUTF8",
                "8BITMIME",
            )
            if name in capability_set
        ]

        post_tls_capabilities = [
            str(item).upper()
            for item in starttls.get("post_tls_capabilities", [])
        ]

        fingerprint = {
            "protocol": "smtp",
            "target": target,
            "address": address,
            "port": port,
            "implicit_tls": bool(data.get("implicit_tls")),
            "software": products,
            "greeting": {
                "code": data.get("greeting_code"),
                "lines": list(greeting_lines),
                "banner_present": bool(banner),
            },
            "ehlo": {
                "accepted": bool(
                    data.get("ehlo", {}).get("accepted")
                ),
                "code": data.get("ehlo", {}).get("code"),
            },
            "capabilities": {
                "count": len(capabilities),
                "names": capabilities,
                "groups": dict(data.get("capability_groups", {})),
            },
            "authentication": {
                "advertised": bool(auth.get("advertised")),
                "mechanisms": list(auth.get("mechanisms", [])),
                "classes": dict(auth.get("mechanism_classes", {})),
            },
            "tls": {
                "state": tls_state,
                "starttls_advertised": bool(
                    starttls.get("advertised")
                ),
                "handshake": bool(starttls.get("handshake")),
                "version": starttls.get("tls_version"),
                "cipher": starttls.get("cipher"),
                "post_tls_capabilities": post_tls_capabilities,
            },
            "features": {
                "transport": transport_features,
                "delivery": delivery_features,
                "internationalization": internationalization,
                "size": "SIZE" in capability_set,
                "pipelining": "PIPELINING" in capability_set,
            },
            "identity": {
                "software_identified": bool(products),
                "capability_count": len(capabilities),
                "auth_mechanism_count": len(
                    auth.get("mechanisms", [])
                ),
                "tls_state": tls_state,
            },
            "confidence": (
                0.95
                if products
                else 0.85
                if capabilities
                else 0.70
            ),
            "evidence": [
                "Composite SMTP fingerprint derived from observed "
                "greeting, EHLO capabilities, authentication metadata, "
                "and TLS state."
            ],
        }

        if capability_details:
            fingerprint["evidence"].append(
                f"Observed {len(capability_details)} SMTP capability entries."
            )

        if auth.get("mechanisms"):
            fingerprint["evidence"].append(
                "Observed advertised SMTP AUTH mechanisms: "
                + ", ".join(auth["mechanisms"])
            )

        if tls_state != "not_advertised":
            fingerprint["evidence"].append(
                f"Observed SMTP TLS state: {tls_state}."
            )

        fingerprint["anomalies"] = ProtocolProbe._detect_smtp_anomalies(
                data=data,
                fingerprint=fingerprint,
            )

        return fingerprint


    @staticmethod
    def _detect_smtp_anomalies(
        *,
        data: dict[str, Any],
        fingerprint: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Detect evidence-backed SMTP protocol inconsistencies."""

        anomalies: list[dict[str, Any]] = []

        def add(
            code: str,
            severity: str,
            confidence: float,
            description: str,
            evidence: list[str],
        ) -> None:
            anomalies.append(
                {
                    "code": code,
                    "severity": severity,
                    "confidence": confidence,
                    "description": description,
                    "evidence": evidence,
                }
            )

        greeting_code = data.get("greeting_code")
        if greeting_code is not None and not 200 <= greeting_code < 400:
            add(
                "unexpected_greeting_code",
                "medium",
                0.90,
                "SMTP greeting used an unexpected response class.",
                [f"Observed greeting response code: {greeting_code}"],
            )

        ehlo = data.get("ehlo") or {}
        helo = data.get("helo") or {}
        commands = data.get("commands") or {}
        starttls = data.get("starttls") or {}
        auth = data.get("auth") or {}

        if not ehlo.get("accepted") and helo.get("accepted"):
            add(
                "ehlo_rejected_helo_accepted",
                "low",
                0.95,
                "Server rejected EHLO but accepted HELO.",
                [
                    f"EHLO response: {ehlo.get('code')}",
                    f"HELO response: {helo.get('code')}",
                ],
            )

        if (
            starttls.get("advertised")
            and starttls.get("response_code") is not None
            and not starttls.get("accepted")
        ):
            add(
                "starttls_advertised_but_rejected",
                "medium",
                0.95,
                "Server advertised STARTTLS but rejected the STARTTLS command.",
                [
                    f"STARTTLS response code: "
                    f"{starttls.get('response_code')}",
                    f"STARTTLS error: {starttls.get('error')}",
                ],
            )

        if starttls.get("accepted") and not starttls.get("handshake"):
            add(
                "starttls_handshake_failed",
                "high",
                0.95,
                "Server accepted STARTTLS but the TLS handshake failed.",
                [
                    f"STARTTLS response code: "
                    f"{starttls.get('response_code')}",
                    f"TLS error: {starttls.get('error')}",
                ],
            )

        if (
            starttls.get("handshake")
            and not starttls.get("tls_version")
        ):
            add(
                "tls_handshake_missing_metadata",
                "medium",
                0.90,
                "TLS handshake was reported successful but TLS version metadata was unavailable.",
                ["STARTTLS handshake was marked successful."],
            )

        if auth.get("advertised") and not auth.get("mechanisms"):
            add(
                "auth_without_mechanisms",
                "medium",
                0.95,
                "SMTP advertised AUTH but no authentication mechanism was parsed.",
                ["AUTH capability was present without usable mechanism data."],
            )

        cleartext_auth = set(
            (auth.get("mechanism_classes") or {}).get(
                "cleartext",
                [],
            )
        )

        if cleartext_auth and not starttls.get("handshake") and not data.get(
            "implicit_tls"
        ):
            add(
                "cleartext_auth_without_tls",
                "medium",
                0.90,
                "Cleartext-capable SMTP AUTH mechanisms were advertised without an observed TLS session.",
                [
                    "Advertised mechanisms: "
                    + ", ".join(sorted(cleartext_auth)),
                    "No successful STARTTLS or implicit TLS handshake was observed.",
                ],
            )

        capabilities = set(
            str(item).upper()
            for item in data.get("capabilities", [])
        )

        if "CHUNKING" in capabilities and "PIPELINING" not in capabilities:
            add(
                "chunking_without_pipelining",
                "low",
                0.80,
                "CHUNKING was advertised without PIPELINING.",
                ["Observed CHUNKING capability."],
            )

        post_tls = set(
            str(item).upper()
            for item in starttls.get("post_tls_capabilities", [])
        )

        if starttls.get("handshake") and not post_tls:
            add(
                "post_tls_capabilities_missing",
                "low",
                0.85,
                "TLS handshake succeeded but the server did not provide post-TLS EHLO capabilities.",
                ["Post-TLS EHLO produced no parsed capabilities."],
            )

        if starttls.get("handshake"):
            pre_tls_auth = set(
                auth.get("mechanisms", [])
            )
            post_tls_auth = {
                part.strip().upper()
                for item in post_tls
                if item.startswith("AUTH ")
                for part in item[5:].split()
            }

            if pre_tls_auth and post_tls_auth and not post_tls_auth.issuperset(
                pre_tls_auth
            ):
                add(
                    "auth_capabilities_changed_after_tls",
                    "low",
                    0.85,
                    "Advertised AUTH mechanisms changed after TLS negotiation.",
                    [
                        "Pre-TLS AUTH: "
                        + ", ".join(sorted(pre_tls_auth)),
                        "Post-TLS AUTH: "
                        + ", ".join(sorted(post_tls_auth)),
                    ],
                )

        if data.get("implicit_tls") and starttls.get("advertised"):
            add(
                "implicit_tls_also_advertises_starttls",
                "low",
                0.80,
                "An implicit-TLS SMTP service also advertised STARTTLS.",
                [
                    "Service was probed as implicit TLS.",
                    "STARTTLS appeared in advertised capabilities.",
                ],
            )

        return anomalies


    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """Return whether a value is an IPv4 or IPv6 address."""

        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


    @staticmethod
    def _analyze_smtp_extension_relationships(
        capabilities: list[str] | None,
        capability_details: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Interpret relationships and consistency between SMTP extensions."""

        capability_set = {
            str(item).strip().upper()
            for item in (capabilities or [])
            if str(item).strip()
        }

        details = capability_details or []
        detail_map = {
            str(item.get("name", "")).strip().upper(): item
            for item in details
            if str(item.get("name", "")).strip()
        }

        relationships: list[dict[str, Any]] = []
        anomalies: list[dict[str, Any]] = []

        def add_relationship(
            name: str,
            extensions: list[str],
            interpretation: str,
        ) -> None:
            present = [
                extension
                for extension in extensions
                if extension in capability_set
            ]
            if present:
                relationships.append(
                    {
                        "name": name,
                        "extensions": present,
                        "interpretation": interpretation,
                    }
                )

        add_relationship(
            "message_chunking",
            ["CHUNKING", "BINARYMIME"],
            "Server supports BDAT-style message transfer and binary MIME data.",
        )

        add_relationship(
            "eight_bit_transport",
            ["8BITMIME"],
            "Server advertises transport support for 8-bit MIME content.",
        )

        add_relationship(
            "delivery_status",
            ["DSN"],
            "Server advertises delivery-status notification support.",
        )

        add_relationship(
            "internationalized_smtp",
            ["SMTPUTF8"],
            "Server advertises internationalized SMTP support.",
        )

        add_relationship(
            "transport_pipelining",
            ["PIPELINING"],
            "Server permits SMTP command pipelining.",
        )

        add_relationship(
            "transport_security",
            ["STARTTLS", "REQUIRETLS"],
            "Server advertises TLS negotiation and/or TLS-required message handling.",
        )

        add_relationship(
            "message_size_control",
            ["SIZE"],
            "Server advertises a maximum message-size policy.",
        )

        add_relationship(
            "queue_management",
            ["ETRN", "ATRN"],
            "Server advertises remote queue-management or retrieval extensions.",
        )

        add_relationship(
            "delivery_timing",
            ["DELIVERBY"],
            "Server advertises delivery-time constraints.",
        )

        add_relationship(
            "message_priority",
            ["MT-PRIORITY"],
            "Server advertises message-priority handling.",
        )

        # Consistency checks.
        if "BINARYMIME" in capability_set and "CHUNKING" not in capability_set:
            anomalies.append(
                {
                    "code": "binarymime_without_chunking",
                    "severity": "low",
                    "confidence": 0.85,
                    "description": (
                        "BINARYMIME is advertised without CHUNKING; "
                        "the advertised extension set is unusual."
                    ),
                    "evidence": ["BINARYMIME"],
                }
            )

        if "REQUIRETLS" in capability_set and "STARTTLS" not in capability_set:
            anomalies.append(
                {
                    "code": "requiretls_without_starttls",
                    "severity": "medium",
                    "confidence": 0.90,
                    "description": (
                        "REQUIRETLS is advertised without STARTTLS; "
                        "TLS-required message handling may depend on "
                        "an already-secured transport or downstream handling."
                    ),
                    "evidence": ["REQUIRETLS"],
                }
            )

        if "SMTPUTF8" in capability_set and "8BITMIME" not in capability_set:
            anomalies.append(
                {
                    "code": "smtputf8_without_8bitmime",
                    "severity": "low",
                    "confidence": 0.80,
                    "description": (
                        "SMTPUTF8 is advertised without 8BITMIME; "
                        "the combination is unusual and should be preserved "
                        "for protocol-level review."
                    ),
                    "evidence": ["SMTPUTF8"],
                }
            )

        size_detail = detail_map.get("SIZE")
        if "SIZE" in capability_set:
            raw = size_detail.get("argument") if size_detail else None
            if raw is not None:
                try:
                    maximum = int(str(raw).strip())
                    if maximum < 0:
                        raise ValueError
                except (TypeError, ValueError):
                    anomalies.append(
                        {
                            "code": "invalid_size_parameter",
                            "severity": "medium",
                            "confidence": 0.95,
                            "description": (
                                "SMTP SIZE capability contains an invalid "
                                "numeric parameter."
                            ),
                            "evidence": [str(raw)],
                        }
                    )

        return {
            "capabilities": sorted(capability_set),
            "relationships": relationships,
            "anomalies": anomalies,
            "relationship_count": len(relationships),
            "anomaly_count": len(anomalies),
        }

    @staticmethod
    def _analyze_smtp_auth_status(
        auth: dict[str, Any] | None,
        *,
        tls_active: bool = False,
    ) -> dict[str, Any]:
        """Interpret advertised SMTP AUTH mechanisms without authenticating."""

        auth = auth or {}
        mechanisms = [
            str(item).upper()
            for item in auth.get("mechanisms", [])
            if str(item).strip()
        ]

        cleartext = {"PLAIN", "LOGIN"}
        challenge_response = {
            "CRAM-MD5",
            "DIGEST-MD5",
            "SCRAM-SHA-1",
            "SCRAM-SHA-256",
            "SCRAM-SHA-512",
        }
        strong = {
            "SCRAM-SHA-256",
            "SCRAM-SHA-512",
        }
        legacy = {
            "NTLM",
            "GSSAPI",
            "XOAUTH",
            "XOAUTH2",
        }

        cleartext_mechanisms = sorted(set(mechanisms) & cleartext)
        challenge_mechanisms = sorted(set(mechanisms) & challenge_response)
        strong_mechanisms = sorted(set(mechanisms) & strong)
        legacy_mechanisms = sorted(set(mechanisms) & legacy)

        if not mechanisms:
            semantic = "not_advertised"
        elif cleartext_mechanisms and not tls_active:
            semantic = "cleartext_auth_without_tls"
        elif strong_mechanisms:
            semantic = "strong_auth_available"
        elif challenge_mechanisms:
            semantic = "challenge_response_auth_available"
        elif legacy_mechanisms:
            semantic = "legacy_auth_available"
        else:
            semantic = "auth_available"

        return {
            "advertised": bool(mechanisms),
            "mechanisms": mechanisms,
            "cleartext_mechanisms": cleartext_mechanisms,
            "challenge_response_mechanisms": challenge_mechanisms,
            "strong_mechanisms": strong_mechanisms,
            "legacy_mechanisms": legacy_mechanisms,
            "tls_active": bool(tls_active),
            "semantics": semantic,
        }

    @staticmethod
    def _analyze_smtp_capability_parameters(
        capability_details: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Normalize structured parameters from advertised SMTP extensions."""

        result: dict[str, Any] = {
            "size": {
                "advertised": False,
                "maximum": None,
                "valid": False,
                "raw": None,
            },
            "auth": {
                "advertised": False,
                "mechanisms": [],
                "raw": None,
            },
            "extensions_with_arguments": [],
            "known": {},
            "unknown_parameters": [],
        }

        known_parameter_extensions = {
            "DSN",
            "ETRN",
            "ATRN",
            "DELIVERBY",
            "MT-PRIORITY",
            "REQUIRETLS",
        }

        for detail in capability_details:
            name = str(detail.get("name") or "").upper()
            arguments = detail.get("arguments")

            if not name:
                continue

            raw_entry = {
                "name": name,
                "arguments": str(arguments) if arguments is not None else None,
                "raw": detail.get("raw"),
            }

            if arguments:
                result["extensions_with_arguments"].append(raw_entry)

            if name == "SIZE":
                result["size"]["advertised"] = True
                result["size"]["raw"] = arguments

                if arguments is not None:
                    value = str(arguments).strip()
                    if value.isdigit():
                        try:
                            maximum = int(value)
                        except (TypeError, ValueError, OverflowError):
                            maximum = None
                        else:
                            if maximum >= 0:
                                result["size"]["maximum"] = maximum
                                result["size"]["valid"] = True

                continue

            if name == "AUTH":
                result["auth"]["advertised"] = True
                result["auth"]["raw"] = arguments

                if arguments:
                    result["auth"]["mechanisms"] = list(
                        dict.fromkeys(
                            token.upper()
                            for token in str(arguments).split()
                            if token.strip()
                        )
                    )

                continue

            if name in known_parameter_extensions:
                result["known"][name] = {
                    "advertised": True,
                    "arguments": (
                        str(arguments)
                        if arguments is not None
                        else None
                    ),
                    "raw": detail.get("raw"),
                }
                continue

            if arguments:
                result["unknown_parameters"].append(raw_entry)

        return result

    @staticmethod
    def _analyze_smtp_auth(
        capability_details: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze advertised SMTP AUTH mechanisms without authenticating."""

        auth_items = [
            item
            for item in capability_details
            if str(item.get("name", "")).upper() in {"AUTH", "AUTH="}
        ]

        mechanisms: list[str] = []

        for item in auth_items:
            arguments = item.get("arguments") or ""
            for mechanism in str(arguments).split():
                normalized = mechanism.strip().upper()
                if normalized and normalized not in mechanisms:
                    mechanisms.append(normalized)

        classes: dict[str, list[str]] = {
            "strong": [],
            "challenge_response": [],
            "cleartext": [],
            "legacy": [],
            "unknown": [],
        }

        challenge_response = {
            "CRAM-MD5",
            "DIGEST-MD5",
            "SCRAM-SHA-1",
            "SCRAM-SHA-256",
            "SCRAM-SHA-512",
        }

        cleartext = {
            "PLAIN",
            "LOGIN",
        }

        legacy = {
            "NTLM",
            "GSSAPI",
            "XOAUTH",
            "XOAUTH2",
        }

        strong = {
            "SCRAM-SHA-256",
            "SCRAM-SHA-512",
        }

        for mechanism in mechanisms:
            if mechanism in strong:
                classes["strong"].append(mechanism)
            elif mechanism in challenge_response:
                classes["challenge_response"].append(mechanism)
            elif mechanism in cleartext:
                classes["cleartext"].append(mechanism)
            elif mechanism in legacy:
                classes["legacy"].append(mechanism)
            else:
                classes["unknown"].append(mechanism)

        return {
            "advertised": bool(auth_items),
            "mechanisms": mechanisms,
            "mechanism_classes": classes,
        }


    @staticmethod
    def _group_smtp_capabilities(
        capability_details: list[dict[str, Any]],
    ) -> dict[str, list[str]]:
        """Group advertised SMTP extensions by protocol function."""

        groups: dict[str, list[str]] = {
            "security": [],
            "authentication": [],
            "transport": [],
            "message_submission": [],
            "encoding": [],
            "delivery": [],
            "size": [],
            "session": [],
            "internationalization": [],
            "other": [],
        }

        security = {
            "STARTTLS",
            "AUTH",
            "AUTH=",
            "TLS",
            "REQUIRETLS",
        }

        authentication = {
            "AUTH",
            "AUTH=",
        }

        transport = {
            "PIPELINING",
            "CHUNKING",
            "BINARYMIME",
            "8BITMIME",
            "DSN",
            "SMTPUTF8",
        }

        message_submission = {
            "SIZE",
            "BDAT",
            "BURL",
            "DELIVERBY",
            "MT-PRIORITY",
        }

        encoding = {
            "8BITMIME",
            "BINARYMIME",
            "CHUNKING",
        }

        delivery = {
            "DSN",
            "ETRN",
            "ATRN",
            "VERP",
            "XVERP",
            "XEXPS",
        }

        size = {
            "SIZE",
            "CHUNKING",
            "BDAT",
        }

        session = {
            "PIPELINING",
            "ENHANCEDSTATUSCODES",
            "HELP",
            "NOOP",
            "RSET",
        }

        internationalization = {
            "SMTPUTF8",
            "8BITMIME",
        }

        for detail in capability_details:
            name = str(detail.get("name", "")).upper()

            if not name:
                continue

            assigned: set[str] = set()

            if name in security:
                assigned.add("security")

            if name in authentication:
                assigned.add("authentication")

            if name in transport:
                assigned.add("transport")

            if name in message_submission:
                assigned.add("message_submission")

            if name in encoding:
                assigned.add("encoding")

            if name in delivery:
                assigned.add("delivery")

            if name in size:
                assigned.add("size")

            if name in session:
                assigned.add("session")

            if name in internationalization:
                assigned.add("internationalization")

            if not assigned:
                assigned.add("other")

            for group in assigned:
                if name not in groups[group]:
                    groups[group].append(name)

        return groups


    @staticmethod
    def _parse_smtp_enhanced_status(
        lines: list[str],
    ) -> dict[str, Any]:
        """Extract RFC-style enhanced SMTP status information from reply lines."""

        import re

        pattern = re.compile(
            r"\b([245]\.[0-9]\.[0-9]+)\b"
        )

        matches: list[str] = []

        for line in lines:
            match = pattern.search(str(line))
            if match:
                matches.append(match.group(1))

        matches = list(dict.fromkeys(matches))

        if not matches:
            return {
                "present": False,
                "codes": [],
                "primary": None,
                "class": None,
                "subject": None,
                "detail": None,
            }

        primary = matches[0]
        parts = primary.split(".")

        status_class = {
            "2": "success",
            "4": "transient_failure",
            "5": "permanent_failure",
        }.get(parts[0])

        return {
            "present": True,
            "codes": matches,
            "primary": primary,
            "class": status_class,
            "subject": int(parts[1]),
            "detail": int(parts[2]),
        }

    @staticmethod
    def _analyze_smtp_greeting(
        code: int | None,
        lines: list[str] | None,
    ) -> dict[str, Any]:
        """Interpret SMTP greeting identity and structure."""

        lines = list(lines or [])
        first_line = lines[0].strip() if lines else ""

        hostname = None
        product_clues: list[str] = []
        anomalies: list[dict[str, Any]] = []

        if first_line:
            match = re.match(r"^\s*\d{3}[ -]+([^\s]+)", first_line)
            if match:
                candidate = match.group(1).strip().rstrip(".")
                hostname_valid = (
                    bool(
                        re.fullmatch(
                            r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?",
                            candidate,
                        )
                    )
                    and (
                        "." in candidate
                        or candidate.lower() == "localhost"
                    )
                )

                try:
                    ipaddress.ip_address(candidate)
                    hostname_valid = True
                except ValueError:
                    pass

                if hostname_valid:
                    hostname = candidate

            lowered = first_line.lower()
            product_patterns = {
                "postfix": "Postfix",
                "exim": "Exim",
                "sendmail": "Sendmail",
                "opensmtpd": "OpenSMTPD",
                "haraka": "Haraka",
                "qmail": "qmail",
                "microsoft": "Microsoft SMTP",
                "exchange": "Microsoft Exchange",
            }

            for marker_text, product in product_patterns.items():
                if marker_text in lowered and product not in product_clues:
                    product_clues.append(product)

        if code == 220:
            semantic = "service_ready"
        elif code == 421:
            semantic = "service_unavailable"
        elif code is None:
            semantic = "no_response"
        elif 400 <= code < 500:
            semantic = "temporary_failure"
        elif 500 <= code < 600:
            semantic = "permanent_failure"
        else:
            semantic = "unexpected_greeting"

        if not lines:
            anomalies.append(
                {
                    "code": "empty_greeting",
                    "severity": "medium",
                    "confidence": 0.95,
                    "description": "SMTP server returned an empty greeting.",
                    "evidence": [],
                }
            )

        if code is not None and code != 220:
            anomalies.append(
                {
                    "code": "unexpected_greeting_code",
                    "severity": "low",
                    "confidence": 0.95,
                    "description": (
                        f"SMTP greeting returned response code {code} "
                        "instead of the expected 220 service-ready code."
                    ),
                    "evidence": lines,
                }
            )

        if len(lines) > 1:
            separators = [
                line[3:4]
                for line in lines
                if len(line) >= 4 and line[:3].isdigit()
            ]
            if separators and separators[-1] == "-":
                anomalies.append(
                    {
                        "code": "unterminated_multiline_greeting",
                        "severity": "low",
                        "confidence": 0.90,
                        "description": (
                            "SMTP greeting appears to remain in multiline "
                            "continuation state."
                        ),
                        "evidence": lines,
                    }
                )

        return {
            "code": code,
            "semantic": semantic,
            "hostname": hostname,
            "product_clues": product_clues,
            "line_count": len(lines),
            "multiline": len(lines) > 1,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
        }

    @staticmethod
    def _analyze_smtp_response_status(
        code: int | None,
        lines: list[str] | None = None,
    ) -> dict[str, Any]:
        """Combine SMTP numeric and enhanced status into semantic intelligence."""

        lines = lines or []
        numeric_status = (
            ProtocolProbe._classify_smtp_response(code)
            if code is not None
            else "no_response"
        )
        enhanced = ProtocolProbe._parse_smtp_enhanced_status(lines)

        semantics = "unknown"

        if code is None:
            semantics = "no_response"
        elif 100 <= code < 200:
            semantics = "preliminary"
        elif 200 <= code < 300:
            semantics = "accepted"
        elif 300 <= code < 400:
            semantics = "continuation_required"
        elif 400 <= code < 500:
            semantics = "temporary_failure"
        elif 500 <= code < 600:
            semantics = "permanent_failure"

        if enhanced["present"]:
            primary = enhanced["primary"]
            enhanced_class = enhanced["class"]

            if enhanced_class == "success":
                if primary.startswith("2.0."):
                    semantics = "success"
                elif primary.startswith("2.1."):
                    semantics = "mailbox_success"
                elif primary.startswith("2.5."):
                    semantics = "mail_system_success"
            elif enhanced_class == "transient_failure":
                if primary.startswith("4.4."):
                    semantics = "temporary_network_failure"
                elif primary.startswith("4.7."):
                    semantics = "temporary_security_or_policy_failure"
                else:
                    semantics = "temporary_failure"
            elif enhanced_class == "permanent_failure":
                if primary.startswith("5.1."):
                    semantics = "mailbox_or_address_failure"
                elif primary.startswith("5.5."):
                    semantics = "command_or_protocol_failure"
                elif primary.startswith("5.7."):
                    semantics = "security_or_policy_rejection"
                else:
                    semantics = "permanent_failure"

        return {
            "code": code,
            "numeric_status": numeric_status,
            "enhanced_status": enhanced,
            "semantics": semantics,
            "lines": list(lines),
        }

    @staticmethod
    def _classify_smtp_response(code: int) -> str:
        """Classify an SMTP response code by its first digit."""

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

    def _smtp_command(
        self,
        sock: socket.socket,
        command: str,
        response_buffer: bytearray,
    ) -> tuple[int, list[str]] | None:
        """Send one bounded, non-authenticating SMTP command."""

        if not command or "\r" in command or "\n" in command:
            raise ValueError("invalid SMTP command")

        encoded = (command + "\r\n").encode("ascii")

        if len(encoded) > 1024:
            raise ValueError("SMTP command exceeds maximum length")

        sock.sendall(encoded)

        return self._smtp_read_response(
            sock,
            response_buffer,
        )

    def _smtp_read_response(
        self,
        sock: socket.socket,
        response_buffer: bytearray,
    ) -> tuple[int, list[str]] | None:
        """Read exactly one bounded SMTP response from a connection buffer."""

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

            raw_line = bytes(response_buffer[:newline + 1])
            del response_buffer[:newline + 1]

            line = raw_line.rstrip(b"\r\n").decode(
                "utf-8",
                errors="replace",
            )

            if len(line) < 3 or not line[:3].isdigit():
                return None

            code = int(line[:3])

            if len(line) == 3:
                return code, [line]

            separator = line[3]

            if separator == "-":
                lines = [line]
                while True:
                    next_newline = response_buffer.find(b"\n")

                    if next_newline == -1:
                        if len(response_buffer) >= max_bytes:
                            return None

                        chunk = sock.recv(
                            min(
                                1024,
                                max_bytes - len(response_buffer),
                            )
                        )

                        if not chunk:
                            return None

                        response_buffer.extend(chunk)
                        continue

                    raw_next = bytes(
                        response_buffer[:next_newline + 1]
                    )
                    del response_buffer[:next_newline + 1]

                    next_line = raw_next.rstrip(
                        b"\r\n"
                    ).decode(
                        "utf-8",
                        errors="replace",
                    )

                    if (
                        len(next_line) < 4
                        or not next_line[:3].isdigit()
                    ):
                        return None

                    if int(next_line[:3]) != code:
                        lines.append(next_line)
                        continue

                    lines.append(next_line)

                    if len(next_line) == 3 or next_line[3] == " ":
                        return code, lines

                    if next_line[3] == "-":
                        continue

                    return None

            if separator == " ":
                return code, [line]

            return None


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

                    capability_groups = {
                        "security": [],
                        "transport": [],
                        "transfer": [],
                        "encoding": [],
                        "metadata": [],
                        "other": [],
                    }

                    security_features = {
                        "AUTH", "PBSZ", "PROT", "TLS", "SSL"
                    }
                    transport_features = {
                        "EPSV", "PASV"
                    }
                    transfer_features = {
                        "APPE", "ESTA", "ESTP", "LIST", "MDTM",
                        "MLSD", "MLST", "NLST", "REST", "RETR",
                        "SIZE", "STOR", "STOU", "STRU", "THMB"
                    }
                    encoding_features = {
                        "UTF8", "UTF-8"
                    }
                    metadata_features = {
                        "CLNT", "FEAT", "HELP", "LANG", "MFF",
                        "MFCT", "OPTS", "SITE", "TVFS"
                    }

                    for feature in data["features"]:
                        if feature in security_features:
                            group = "security"
                        elif feature in transport_features:
                            group = "transport"
                        elif feature in transfer_features:
                            group = "transfer"
                        elif feature in encoding_features:
                            group = "encoding"
                        elif feature in metadata_features:
                            group = "metadata"
                        else:
                            group = "other"

                        capability_groups[group].append(feature)

                    data["capability_groups"] = capability_groups

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
                                "address": address,
                                "port": passive["port"],
                                "address_source": "control_connection",
                                "raw": passive["raw"],
                            }

                            if passive["supported"]:
                                data["passive_mode"]["address_scope"] = (
                                    self._classify_ftp_passive_address(
                                        address
                                    )
                                )
                        else:
                            passive = self._parse_ftp_pasv(passive_lines)

                            passive_address = passive["address"]

                            data["passive_mode"] = {
                                "mode": "PASV",
                                "supported": passive["supported"],
                                "address": passive_address,
                                "port": passive["port"],
                                "raw": passive["raw"],
                            }

                            if passive["supported"] and passive_address:
                                data["passive_mode"]["address_scope"] = (
                                    self._classify_ftp_passive_address(
                                        passive_address
                                    )
                                )
                                data["passive_mode"][
                                    "address_matches_control"
                                ] = (
                                    self._ftp_passive_address_matches_control(
                                        passive_address,
                                        address,
                                    )
                                )

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

                            pbsz_response = self._ftp_command(
                                sock,
                                "PBSZ 0",
                                response_buffer,
                            )

                            if pbsz_response is None:
                                data["commands"]["pbsz"] = {
                                    "code": None,
                                    "lines": [],
                                    "status": "no_response",
                                }
                            else:
                                pbsz_code, pbsz_lines = pbsz_response
                                data["commands"]["pbsz"] = {
                                    "code": pbsz_code,
                                    "lines": pbsz_lines,
                                    "status": self._classify_ftp_response(
                                        pbsz_code
                                    ),
                                }

                            prot_response = self._ftp_command(
                                sock,
                                "PROT P",
                                response_buffer,
                            )

                            if prot_response is None:
                                data["commands"]["prot_p"] = {
                                    "code": None,
                                    "lines": [],
                                    "status": "no_response",
                                }
                            else:
                                prot_code, prot_lines = prot_response
                                data["commands"]["prot_p"] = {
                                    "code": prot_code,
                                    "lines": prot_lines,
                                    "status": self._classify_ftp_response(
                                        prot_code
                                    ),
                                }

                            data["tls_protection"] = {
                                "control_channel": {
                                    "supported": True,
                                    "handshake": True,
                                },
                                "data_channel": {
                                    "pbsz": data["commands"]["pbsz"],
                                    "prot_p": data["commands"]["prot_p"],
                                    "private_requested": (
                                        data["commands"]["prot_p"].get(
                                            "status"
                                        ) == "success"
                                    ),
                                },
                            }

                            evidence.append(
                                "FTP TLS data-channel protection state "
                                "was inspected with PBSZ 0 and PROT P."
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

            data["anomalies"] = self._detect_ftp_anomalies(data)
            data["session"] = self._build_ftp_session_profile(data)

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
    def _classify_ftp_passive_address(address: str) -> str:
        """Classify a passive FTP endpoint address without contacting it."""

        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return "invalid"

        if parsed.is_loopback:
            return "loopback"
        if parsed.is_private:
            return "private"
        if parsed.is_link_local:
            return "link_local"
        if parsed.is_multicast:
            return "multicast"
        if parsed.is_unspecified:
            return "unspecified"
        if parsed.is_reserved:
            return "reserved"

        return "global"

    @staticmethod
    def _ftp_passive_address_matches_control(
        passive_address: str,
        control_address: str,
    ) -> bool | None:
        """Compare PASV endpoint and control addresses when both are valid."""

        try:
            return (
                ipaddress.ip_address(passive_address)
                == ipaddress.ip_address(control_address)
            )
        except ValueError:
            return None

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
    def _detect_ftp_anomalies(
        data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Detect safe, observation-only FTP protocol inconsistencies."""

        anomalies: list[dict[str, Any]] = []

        commands = data.get("commands") or {}
        features = set(data.get("features") or [])
        passive_mode = data.get("passive_mode") or {}
        tls_protection = data.get("tls_protection") or {}

        def add(code: str, description: str, severity: str = "info") -> None:
            anomalies.append(
                {
                    "code": code,
                    "severity": severity,
                    "description": description,
                }
            )

        greeting_code = data.get("greeting_code")
        if not isinstance(greeting_code, int) or not (
            100 <= greeting_code < 600
        ):
            add(
                "invalid_greeting_code",
                "FTP greeting did not contain a standard response code.",
                "low",
            )

        for command_name, details in commands.items():
            if details.get("status") == "no_response":
                add(
                    "command_no_response",
                    f"FTP {command_name.upper()} produced no valid response.",
                    "low",
                )

        if "EPSV" in features:
            epsv = commands.get("epsv")
            if epsv is not None:
                if epsv.get("status") == "no_response":
                    add(
                        "epsv_advertised_no_response",
                        "FTP advertised EPSV but produced no valid EPSV response.",
                        "low",
                    )
                elif (
                    epsv.get("status") == "success"
                    and not passive_mode.get("supported")
                ):
                    add(
                        "epsv_response_invalid",
                        "FTP returned a successful EPSV response without a valid passive endpoint.",
                        "low",
                    )

        if passive_mode:
            if passive_mode.get("supported"):
                port = passive_mode.get("port")
                if not isinstance(port, int) or not 1 <= port <= 65535:
                    add(
                        "passive_invalid_port",
                        "FTP passive mode reported an invalid data port.",
                        "low",
                    )

                address_scope = passive_mode.get("address_scope")
                if address_scope in {
                    "invalid",
                    "unspecified",
                    "multicast",
                    "reserved",
                }:
                    add(
                        "passive_unusual_address",
                        "FTP passive mode reported an unusual endpoint address scope.",
                        "low",
                    )

                if (
                    passive_mode.get("mode") == "PASV"
                    and passive_mode.get("address_matches_control") is False
                ):
                    add(
                        "pasv_address_differs",
                        "FTP PASV reported an address different from the control connection.",
                        "info",
                    )

        explicit_tls = data.get("explicit_tls")
        tls_handshake = data.get("tls_handshake")

        if explicit_tls is True and tls_handshake is False:
            add(
                "tls_handshake_failed",
                "FTP accepted AUTH TLS but the TLS handshake failed.",
                "low",
            )

        if "AUTH" in features or "TLS" in features or "SSL" in features:
            auth_tls = commands.get("auth_tls")
            if (
                auth_tls is not None
                and auth_tls.get("status") == "permanent_error"
                and explicit_tls is True
            ):
                add(
                    "tls_capability_inconsistent",
                    "FTP capability data indicated TLS support but AUTH TLS returned a permanent error.",
                    "low",
                )

        if tls_protection:
            data_channel = tls_protection.get("data_channel") or {}
            prot_p = data_channel.get("prot_p") or {}

            if (
                tls_handshake is True
                and prot_p.get("status") == "no_response"
            ):
                add(
                    "tls_protection_no_response",
                    "FTP completed the TLS handshake but PROT P produced no valid response.",
                    "low",
                )

        return anomalies


    @staticmethod
    def _build_ftp_session_profile(
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Build structured FTP session intelligence from probe results."""

        commands = data.get("commands", {})
        passive_mode = data.get("passive_mode") or {}
        tls = data.get("tls") or {}

        command_status = {
            name: details.get("status")
            for name, details in commands.items()
        }

        return {
            "protocol": "ftp",
            "greeting": {
                "code": data.get("greeting_code"),
                "present": bool(data.get("greeting_lines")),
            },
            "capabilities": {
                "advertised": list(data.get("features") or []),
                "details": list(data.get("feature_details") or []),
                "groups": {
                    name: list(values)
                    for name, values in (
                        data.get("capability_groups") or {}
                    ).items()
                },
            },
            "system": {
                "type": data.get("system_type"),
            },
            "working_directory": {
                "reported": data.get("working_directory") is not None,
            },
            "passive_mode": {
                "mode": passive_mode.get("mode"),
                "supported": passive_mode.get("supported"),
                "port": passive_mode.get("port"),
            },
            "explicit_tls": {
                "supported": data.get("explicit_tls"),
                "handshake": data.get("tls_handshake"),
                "version": tls.get("version"),
                "cipher": tls.get("cipher"),
            },
            "tls_protection": data.get("tls_protection") or {},
            "anomalies": list(data.get("anomalies") or []),
            "command_status": command_status,
        }


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

    def _probe_http(self, target, address, address_family, port, *, https):
        scheme = "https" if https else "http"
        host = self._format_host(address, address_family)
        url = f"{scheme}://{host}:{port}/"

        def build_data(response, method, body_probe=None):
            headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            status = int(response.status)
            http_version = self._http_version(getattr(response, "version", None))

            data = {
                "scheme": scheme,
                "requested_url": url,
                "final_url": response.geturl(),
                "redirected": response.geturl() != url,
                "method_used": method,
                "status_code": status,
                "reason": getattr(response, "reason", None),
                "http_version": http_version,
                "server": headers.get("server"),
                "content_type": headers.get("content-type"),
                "content_length": headers.get("content-length"),
                "location": headers.get("location"),
                "allow": headers.get("allow"),
                "headers": headers,
            }

            if body_probe is not None:
                data["body_probe"] = body_probe

            if https:
                data["tls"] = self._tls_metadata(response)

            return data

        def evidence_for(data):
            evidence = [
                f"HTTP status: {data.get('status_code')}",
                f"HTTP version: {data.get('http_version')}",
            ]

            if data.get("server"):
                evidence.append(f"Server: {data['server']}")
            if data.get("content_type"):
                evidence.append(f"Content-Type: {data['content_type']}")
            if data.get("location"):
                evidence.append(f"Location: {data['location']}")

            if https:
                tls = data.get("tls", {})
                for key, label in (
                    ("version", "TLS version"),
                    ("cipher", "TLS cipher"),
                    ("certificate_subject", "Certificate subject"),
                    ("certificate_issuer", "Certificate issuer"),
                ):
                    if tls.get(key):
                        evidence.append(f"{label}: {tls[key]}")

            return evidence

        def perform_get():
            request = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "SentinelForge/1.0 ProtocolProbe",
                    "Accept": "*/*",
                    "Range": f"bytes=0-{max(0, self._max_body_bytes - 1)}",
                    "Connection": "close",
                },
            )

            context = None
            if https and self._config is not None:
                context = ssl_context(self._config)

            response = urllib.request.urlopen(
                request,
                timeout=self._timeout,
                context=context,
            )

            try:
                body = response.read(self._max_body_bytes)
                return response, {
                    "attempted": True,
                    "bytes_read": len(body),
                    "truncated": len(body) >= self._max_body_bytes,
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
            except Exception:
                response.close()
                raise

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

            response = urllib.request.urlopen(
                request,
                timeout=self._timeout,
                context=context,
            )

            try:
                data = build_data(response, "HEAD")
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
                    timestamp=time.time(),
                    data=data,
                    evidence=evidence_for(data),
                    error=None,
                )
            finally:
                response.close()

        except urllib.error.HTTPError as exc:
            if exc.code not in {405, 501}:
                try:
                    data = build_data(exc, "HEAD")
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
                        timestamp=time.time(),
                        data=data,
                        evidence=evidence_for(data),
                        error=None,
                    )
                finally:
                    exc.close()

            exc.close()

            try:
                response, body_probe = perform_get()
                try:
                    data = build_data(response, "GET", body_probe)
                    return ProtocolObservation(
                        target=target,
                        address=address,
                        address_family=address_family,
                        port=port,
                        transport="tcp",
                        protocol=scheme,
                        success=True,
                        identification_method="http_get_fallback",
                        confidence=0.99,
                        timestamp=time.time(),
                        data=data,
                        evidence=evidence_for(data) + [
                            f"GET body bytes read: {body_probe['bytes_read']}",
                        ],
                        error=None,
                    )
                finally:
                    response.close()
            except ssl.SSLError as fallback_exc:
                return self._error_observation(
                    target, address, address_family, port, scheme,
                    "tls_error", fallback_exc
                )
            except (urllib.error.URLError, TimeoutError, ConnectionResetError) as fallback_exc:
                return self._error_observation(
                    target, address, address_family, port, scheme,
                    "connection_failed", fallback_exc
                )
            except OSError as fallback_exc:
                return self._error_observation(
                    target, address, address_family, port, scheme,
                    "socket_error", fallback_exc
                )

        except ssl.SSLError as exc:
            return self._error_observation(
                target, address, address_family, port, scheme,
                "tls_error", exc
            )
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            return self._error_observation(
                target, address, address_family, port, scheme,
                "connection_failed", exc
            )
        except OSError as exc:
            return self._error_observation(
                target, address, address_family, port, scheme,
                "socket_error", exc
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

            result["algorithm_profile"] = self._classify_ssh_algorithms(
                result
            )
            result["capabilities"] = self._analyze_ssh_capabilities(
                result
            )
            result["fingerprint"] = self._build_ssh_fingerprint(
                {
                    **result,
                    "capabilities": result["capabilities"],
                }
            )

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
    def _classify_ssh_algorithms(
        negotiation: dict[str, Any],
    ) -> dict[str, Any]:
        """Classify advertised SSH algorithms without claiming negotiation."""

        categories = {
            "kex_algorithms": "kex",
            "server_host_key_algorithms": "host_key",
            "encryption_algorithms_client_to_server": "encryption",
            "encryption_algorithms_server_to_client": "encryption",
            "mac_algorithms_client_to_server": "mac",
            "mac_algorithms_server_to_client": "mac",
            "compression_algorithms_client_to_server": "compression",
            "compression_algorithms_server_to_client": "compression",
        }

        profile: dict[str, Any] = {
            "kex": [],
            "host_key": [],
            "encryption": [],
            "mac": [],
            "compression": [],
            "legacy_algorithms": [],
            "weak_algorithms": [],
            "unknown_algorithms": [],
            "anomalies": [],
        }

        for field_name, category in categories.items():
            for algorithm in negotiation.get(field_name, []):
                classification = ProtocolProbe._classify_ssh_algorithm(
                    category,
                    algorithm,
                )

                entry = {
                    "algorithm": algorithm,
                    "classification": classification,
                }
                profile[category].append(entry)

                if classification == "legacy":
                    profile["legacy_algorithms"].append(
                        {
                            "category": category,
                            "algorithm": algorithm,
                        }
                    )
                elif classification == "weak":
                    profile["weak_algorithms"].append(
                        {
                            "category": category,
                            "algorithm": algorithm,
                        }
                    )
                elif classification == "unknown":
                    profile["unknown_algorithms"].append(
                        {
                            "category": category,
                            "algorithm": algorithm,
                        }
                    )

        required_fields = (
            "kex_algorithms",
            "server_host_key_algorithms",
            "encryption_algorithms_client_to_server",
            "encryption_algorithms_server_to_client",
            "mac_algorithms_client_to_server",
            "mac_algorithms_server_to_client",
            "compression_algorithms_client_to_server",
            "compression_algorithms_server_to_client",
        )

        for field_name in required_fields:
            if not negotiation.get(field_name):
                profile["anomalies"].append(
                    f"empty_{field_name}"
                )

        if negotiation.get("first_kex_follows"):
            profile["anomalies"].append(
                "first_kex_follows_set"
            )

        return profile

    @staticmethod
    def _classify_ssh_algorithm(
        category: str,
        algorithm: str,
    ) -> str:
        """Classify an advertised SSH algorithm conservatively."""

        name = algorithm.lower()

        if category == "kex":
            if name in {
                "diffie-hellman-group1-sha1",
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1",
            }:
                return "legacy"
            if "sha1" in name:
                return "legacy"
            if name.startswith("curve25519-") or name in {
                "diffie-hellman-group14-sha256",
                "diffie-hellman-group16-sha512",
                "diffie-hellman-group18-sha512",
            }:
                return "modern"
            if name in {
                "ext-info-s",
                "kex-strict-s-v00@openssh.com",
            }:
                return "modern"
            return "unknown"

        if category == "host_key":
            if name == "ssh-dss":
                return "weak"
            if name == "ssh-rsa":
                return "legacy"
            if name in {
                "ssh-ed25519",
                "rsa-sha2-256",
                "rsa-sha2-512",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
            }:
                return "modern"
            return "unknown"

        if category == "encryption":
            if name in {
                "arcfour",
                "arcfour128",
                "arcfour256",
                "3des-cbc",
                "blowfish-cbc",
                "cast128-cbc",
                "idea-cbc",
            }:
                return "weak"
            if name.endswith("-cbc"):
                return "legacy"
            if name in {
                "chacha20-poly1305@openssh.com",
                "aes128-ctr",
                "aes192-ctr",
                "aes256-ctr",
                "aes128-gcm@openssh.com",
                "aes256-gcm@openssh.com",
            }:
                return "modern"
            return "unknown"

        if category == "mac":
            if name in {
                "hmac-md5",
                "hmac-md5-96",
                "hmac-sha1",
                "hmac-sha1-96",
                "umac-64",
                "umac-64-etm@openssh.com",
            }:
                return "legacy"
            if "hmac-sha2-" in name or "umac-128" in name:
                return "modern"
            return "unknown"

        if category == "compression":
            if name in {"none", "zlib", "zlib@openssh.com"}:
                return "modern"
            return "unknown"

        return "unknown"

    @staticmethod
    def _analyze_ssh_capabilities(
        negotiation: dict[str, Any],
    ) -> dict[str, Any]:
        """Interpret SSH capability markers from the server advertisement."""

        kex_algorithms = [
            str(item)
            for item in negotiation.get("kex_algorithms", [])
        ]

        extensions = [
            item
            for item in kex_algorithms
            if item.startswith("ext-info-")
            or item.startswith("kex-strict-")
        ]

        return {
            "extensions": extensions,
            "ext_info": any(
                item == "ext-info-s"
                for item in extensions
            ),
            "strict_kex": any(
                item.startswith("kex-strict-")
                for item in extensions
            ),
            "first_kex_follows": bool(
                negotiation.get("first_kex_follows")
            ),
        }

    @staticmethod
    def _build_ssh_fingerprint(
        negotiation: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a deterministic fingerprint from observed SSH capabilities."""

        fingerprint_fields = (
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
        )

        canonical = "|".join(
            f"{field}="
            + ",".join(
                str(item)
                for item in negotiation.get(field, [])
            )
            for field in fingerprint_fields
        )

        observation_sha256 = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

        return {
            "protocol": "ssh",
            "message_type": negotiation.get("message_type"),
            "negotiation_complete": bool(
                negotiation.get("negotiation_complete")
            ),
            "observation_sha256": observation_sha256,
            "algorithm_counts": {
                field: len(negotiation.get(field, []))
                for field in fingerprint_fields
            },
            "capabilities": dict(
                negotiation.get("capabilities", {})
            ),
            "confidence": 0.95,
            "evidence": (
                "SSH observation fingerprint derived from the "
                "server SSH_MSG_KEXINIT algorithm advertisement; "
                "this is not a host-key fingerprint."
            ),
        }

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

        sock = getattr(response, "fp", None)
        sock = getattr(sock, "raw", None)
        sock = getattr(sock, "_sock", None)

        if sock is None:
            return ProtocolProbe._empty_tls_metadata()

        try:
            return ProtocolProbe._tls_socket_metadata(sock)
        except (AttributeError, OSError, ValueError, TypeError):
            return ProtocolProbe._empty_tls_metadata()

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
