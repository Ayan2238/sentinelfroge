"""Safe DNS protocol probing for SentinelForge.

Provides bounded, protocol-aware DNS/UDP intelligence without performing
zone transfers, recursive abuse, cache poisoning, or other intrusive actions.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
from dataclasses import dataclass

from .dnssec_adapter import DnssecAdapter
from datetime import datetime, timezone
from typing import Any


_DNS_HEADER_SIZE = 12
_MAX_DNS_PACKET = 4096
_MAX_NAME_POINTERS = 16


@dataclass(frozen=True)
class DnsObservation:
    """Structured DNS protocol observation."""

    target: str
    address: str
    address_family: str
    port: int
    transport: str
    success: bool
    query_name: str
    query_type: str
    query_class: str
    response_code: int | None
    response_code_name: str | None
    flags: dict[str, bool]
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int
    answers: tuple[dict[str, Any], ...]
    authorities: tuple[dict[str, Any], ...]
    additionals: tuple[dict[str, Any], ...]
    edns: dict[str, Any]
    dnssec: dict[str, Any]
    latency_ms: float | None
    truncated: bool
    tcp_fallback_attempted: bool
    tcp_fallback_successful: bool
    identification_method: str
    confidence: float
    timestamp: str
    evidence: tuple[str, ...] = ()
    error: str | None = None


class DnsProbe:
    """Bounded DNS protocol probe supporting UDP and TCP."""

    def __init__(
        self,
        *,
        timeout: float = 2.0,
        max_packet_bytes: int = _MAX_DNS_PACKET,
        edns_enabled: bool = True,
        edns_udp_payload_size: int = 1232,
        dnssec_ok: bool = True,
    ) -> None:
        if not 0.1 <= timeout <= 3600:
            raise ValueError("timeout must be between 0.1 and 3600 seconds")

        if not 512 <= max_packet_bytes <= 65535:
            raise ValueError(
                "max_packet_bytes must be between 512 and 65535"
            )

        if not isinstance(edns_enabled, bool):
            raise ValueError("edns_enabled must be a boolean")

        if (
            isinstance(edns_udp_payload_size, bool)
            or not isinstance(edns_udp_payload_size, int)
            or not 512 <= edns_udp_payload_size <= 65535
        ):
            raise ValueError(
                "edns_udp_payload_size must be an integer between 512 and 65535"
            )

        if not isinstance(dnssec_ok, bool):
            raise ValueError("dnssec_ok must be a boolean")

        self._timeout = float(timeout)
        self._max_packet_bytes = int(max_packet_bytes)
        self._edns_enabled = edns_enabled
        self._edns_udp_payload_size = edns_udp_payload_size
        self._dnssec_ok = dnssec_ok
        self._dnssec_adapter = DnssecAdapter()

    def probe(
        self,
        target: str,
        address: str,
        address_family: str,
        port: int = 53,
        *,
        transport: str = "udp",
        query_name: str | None = None,
        query_type: str = "A",
        query_class: str = "IN",
    ) -> DnsObservation:
        """Send one safe DNS query and return structured protocol data."""

        transport = transport.lower()
        query_name = (query_name or target).rstrip(".") or "."

        try:
            self._validate_inputs(
                address,
                port,
                transport,
                query_name,
                query_type,
                query_class,
            )

            query_type_code = self._type_code(query_type)
            query_class_code = self._class_code(query_class)

            transaction_id = random.SystemRandom().randrange(0, 65536)
            packet = self._build_query(
                transaction_id,
                query_name,
                query_type_code,
                query_class_code,
                edns_enabled=self._edns_enabled,
                edns_udp_payload_size=self._edns_udp_payload_size,
                dnssec_ok=self._dnssec_ok,
            )

            started = time.monotonic()
            tcp_fallback_attempted = False
            tcp_fallback_successful = False

            if transport == "udp":
                response = self._query_udp(
                    address,
                    port,
                    address_family,
                    packet,
                )

                parsed = self._parse_response(
                    response,
                    transaction_id,
                    query_name,
                    query_type,
                    query_class,
                )

                if parsed["truncated"]:
                    tcp_fallback_attempted = True

                    response = self._query_tcp(
                        address,
                        port,
                        address_family,
                        packet,
                    )

                    parsed = self._parse_response(
                        response,
                        transaction_id,
                        query_name,
                        query_type,
                        query_class,
                    )

                    tcp_fallback_successful = True
            else:
                response = self._query_tcp(
                    address,
                    port,
                    address_family,
                    packet,
                )

                parsed = self._parse_response(
                    response,
                    transaction_id,
                    query_name,
                    query_type,
                    query_class,
                )

            latency_ms = (time.monotonic() - started) * 1000.0

            evidence = [
                f"DNS {transport.upper()} response received from "
                f"{address}:{port}",
                f"Response code: {parsed['response_code_name']}",
                f"Answers: {parsed['answer_count']}",
            ]

            if parsed["flags"].get("aa"):
                evidence.append("Authoritative answer flag set")

            if parsed["flags"].get("ra"):
                evidence.append("Recursion available flag set")

            if parsed["flags"].get("rd"):
                evidence.append("Recursion desired flag echoed")

            if parsed["truncated"]:
                evidence.append("DNS response was truncated")

            if tcp_fallback_attempted:
                evidence.append(
                    "UDP response was truncated; TCP fallback was attempted"
                )

            if tcp_fallback_successful:
                evidence.append("TCP fallback completed successfully")

            if parsed["edns"]["present"]:
                evidence.append(
                    "EDNS(0) OPT record present in DNS response"
                )
                evidence.append(
                    "EDNS UDP payload size: "
                    f"{parsed['edns']['udp_payload_size']}"
                )

                if parsed["edns"]["dnssec_ok"]:
                    evidence.append("DNSSEC OK (DO) signaling present")

                if parsed["edns"]["version"] != 0:
                    evidence.append(
                        "Unexpected EDNS version: "
                        f"{parsed['edns']['version']}"
                    )
            elif self._edns_enabled:
                evidence.append(
                    "EDNS(0) was not present in DNS response"
                )

            dnssec = dict(parsed["dnssec"])

            if dnssec["present"]:
                dnssec_records = (
                    parsed["answers"]
                    + parsed["authorities"]
                    + parsed["additionals"]
                )

                validation = self._dnssec_adapter.validate(
                    name=query_name,
                    records=dnssec_records,
                )

                dnssec["validation"] = {
                    "status": validation.status,
                    "secure": validation.secure,
                    "ds_present": validation.ds_present,
                    "dnskey_present": validation.dnskey_present,
                    "rrsig_present": validation.rrsig_present,
                    "ds_matches_dnskey": validation.ds_matches_dnskey,
                    "signatures_valid": validation.signatures_valid,
                    "signatures_in_window": validation.signatures_in_window,
                    "key_tags": list(validation.key_tags),
                    "algorithms": list(validation.algorithms),
                    "validated_rrsets": validation.validated_rrsets,
                    "invalid_rrsets": validation.invalid_rrsets,
                    "unsupported_rrsets": validation.unsupported_rrsets,
                    "evidence": list(validation.evidence),
                    "warnings": list(validation.warnings),
                    "errors": list(validation.errors),
                }

                evidence.append(
                    "DNSSEC cryptographic validation status: "
                    f"{validation.status}"
                )

            if dnssec["present"]:
                evidence.append(
                    "DNSSEC records present: "
                    f"{dnssec['record_count']}"
                )

                if dnssec["algorithms"]:
                    evidence.append(
                        "DNSSEC algorithms: "
                        + ", ".join(dnssec["algorithms"])
                    )

                for warning in dnssec["warnings"]:
                    evidence.append(
                        "DNSSEC consistency warning: " + warning
                    )

            return DnsObservation(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport=transport,
                success=True,
                query_name=query_name,
                query_type=query_type.upper(),
                query_class=query_class.upper(),
                response_code=parsed["response_code"],
                response_code_name=parsed["response_code_name"],
                flags=parsed["flags"],
                question_count=parsed["question_count"],
                answer_count=parsed["answer_count"],
                authority_count=parsed["authority_count"],
                additional_count=parsed["additional_count"],
                answers=tuple(parsed["answers"]),
                authorities=tuple(parsed["authorities"]),
                additionals=tuple(parsed["additionals"]),
                edns=parsed["edns"],
                dnssec=dnssec,
                latency_ms=latency_ms,
                truncated=bool(parsed["truncated"]),
                tcp_fallback_attempted=bool(tcp_fallback_attempted),
                tcp_fallback_successful=bool(tcp_fallback_successful),
                identification_method="dns_protocol_response",
                confidence=1.0,
                timestamp=self._timestamp(),
                evidence=tuple(evidence),
            )

        except socket.timeout as exc:
            return self._error(
                target,
                address,
                address_family,
                port,
                transport,
                query_name,
                query_type,
                query_class,
                "timeout",
                exc,
            )

        except ConnectionRefusedError as exc:
            return self._error(
                target,
                address,
                address_family,
                port,
                transport,
                query_name,
                query_type,
                query_class,
                "connection_refused",
                exc,
            )

        except Exception as exc:
            return self._error(
                target,
                address,
                address_family,
                port,
                transport,
                query_name,
                query_type,
                query_class,
                "probe_error",
                exc,
            )

    def collect_dnssec(
        self,
        *,
        target: str,
        address: str,
        address_family: str,
        port: int = 53,
        transport: str = "udp",
        query_name: str | None = None,
        query_type: str = "A",
        query_class: str = "IN",
    ) -> dict[str, Any]:
        """Collect DNSSEC material with bounded protocol queries.

        The normal probe() contract remains a single-query operation.
        This method performs a small, fixed DNSSEC collection set and
        combines the returned records for cryptographic validation.
        """

        normalized_name = (query_name or target).rstrip(".") or "."

        query_types = []
        for requested_type in (
            query_type.upper(),
            "DNSKEY",
            "DS",
            "RRSIG",
        ):
            if requested_type not in query_types:
                query_types.append(requested_type)

        observations: list[DnsObservation] = []

        for current_type in query_types:
            observation = self.probe(
                target=target,
                address=address,
                address_family=address_family,
                port=port,
                transport=transport,
                query_name=normalized_name,
                query_type=current_type,
                query_class=query_class,
            )
            observations.append(observation)

        all_records: list[dict[str, Any]] = []

        for observation in observations:
            if not observation.success:
                continue

            all_records.extend(observation.answers)
            all_records.extend(observation.authorities)
            all_records.extend(observation.additionals)

        # Deduplicate records while preserving deterministic order.
        unique_records: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()

        for record in all_records:
            identity = (
                record.get("name"),
                record.get("type"),
                record.get("class"),
                record.get("ttl"),
                tuple(sorted(record.items())),
            )

            if identity in seen:
                continue

            seen.add(identity)
            unique_records.append(record)

        dnssec = self._dnssec_adapter.validate(
            name=normalized_name,
            records=unique_records,
        )

        return {
            "target": target,
            "address": address,
            "address_family": address_family,
            "port": port,
            "transport": transport,
            "query_name": normalized_name,
            "query_type": query_type.upper(),
            "query_class": query_class.upper(),
            "observations": tuple(observations),
            "records": tuple(unique_records),
            "record_count": len(unique_records),
            "validation": {
                "status": dnssec.status,
                "secure": dnssec.secure,
                "ds_present": dnssec.ds_present,
                "dnskey_present": dnssec.dnskey_present,
                "rrsig_present": dnssec.rrsig_present,
                "ds_matches_dnskey": dnssec.ds_matches_dnskey,
                "signatures_valid": dnssec.signatures_valid,
                "signatures_in_window": dnssec.signatures_in_window,
                "key_tags": list(dnssec.key_tags),
                "algorithms": list(dnssec.algorithms),
                "validated_rrsets": dnssec.validated_rrsets,
                "invalid_rrsets": dnssec.invalid_rrsets,
                "unsupported_rrsets": dnssec.unsupported_rrsets,
                "evidence": list(dnssec.evidence),
                "warnings": list(dnssec.warnings),
                "errors": list(dnssec.errors),
            },
        }

    @staticmethod
    def _validate_inputs(
        address: str,
        port: int,
        transport: str,
        query_name: str,
        query_type: str,
        query_class: str,
    ) -> None:
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError(f"invalid DNS server address: {address!r}") from exc

        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError("DNS port must be an integer")

        if not 1 <= port <= 65535:
            raise ValueError("DNS port must be between 1 and 65535")

        if transport not in {"udp", "tcp"}:
            raise ValueError("DNS transport must be 'udp' or 'tcp'")

        if not query_name:
            raise ValueError("DNS query name must not be empty")

        if len(query_name) > 253:
            raise ValueError("DNS query name is too long")

        if "\x00" in query_name:
            raise ValueError("DNS query name contains NUL")

        if query_type.upper() not in {
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "TXT",
            "SOA",
            "PTR",
            "SRV",
            "DS",
            "RRSIG",
            "NSEC",
            "DNSKEY",
            "NSEC3",
            "NSEC3PARAM",
        }:
            raise ValueError(f"unsupported DNS query type: {query_type!r}")

        if query_class.upper() not in {"IN"}:
            raise ValueError(f"unsupported DNS query class: {query_class!r}")

    @staticmethod
    def _type_code(query_type: str) -> int:
        return {
            "A": 1,
            "NS": 2,
            "CNAME": 5,
            "SOA": 6,
            "PTR": 12,
            "MX": 15,
            "TXT": 16,
            "AAAA": 28,
            "SRV": 33,
            "DS": 43,
            "RRSIG": 46,
            "NSEC": 47,
            "DNSKEY": 48,
            "NSEC3": 50,
            "NSEC3PARAM": 51,
        }[query_type.upper()]

    @staticmethod
    def _class_code(query_class: str) -> int:
        return {"IN": 1}[query_class.upper()]

    @staticmethod
    def _build_query(
        transaction_id: int,
        query_name: str,
        query_type: int,
        query_class: int,
        *,
        edns_enabled: bool = True,
        edns_udp_payload_size: int = 1232,
        dnssec_ok: bool = True,
    ) -> bytes:
        labels = query_name.rstrip(".").split(".") if query_name != "." else []

        encoded_name = bytearray()

        for label in labels:
            encoded = label.encode("idna")

            if not 1 <= len(encoded) <= 63:
                raise ValueError("DNS label must contain 1-63 bytes")

            encoded_name.append(len(encoded))
            encoded_name.extend(encoded)

        encoded_name.append(0)

        flags = 0x0100
        additional_count = 1 if edns_enabled else 0

        header = struct.pack(
            "!HHHHHH",
            transaction_id,
            flags,
            1,
            0,
            0,
            additional_count,
        )

        question = struct.pack(
            "!HH",
            query_type,
            query_class,
        )

        if not edns_enabled:
            return header + bytes(encoded_name) + question

        # EDNS(0) OPT pseudo-record.
        # CLASS = advertised UDP payload size.
        # TTL = extended RCODE, EDNS version, and EDNS flags.
        # DO (DNSSEC OK) is bit 15 of the EDNS flags.
        edns_flags = 0x8000 if dnssec_ok else 0

        opt = struct.pack(
            "!BHHIH",
            0,
            41,
            edns_udp_payload_size,
            edns_flags,
            0,
        )

        return (
            header
            + bytes(encoded_name)
            + question
            + opt
        )

    def _query_udp(
        self,
        address: str,
        port: int,
        address_family: str,
        packet: bytes,
    ) -> bytes:
        family = self._socket_family(address, address_family)

        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self._timeout)
            sock.sendto(packet, self._destination(address, port, family))
            response, _ = sock.recvfrom(self._max_packet_bytes)

        if not response:
            raise ValueError("empty DNS UDP response")

        return response

    def _query_tcp(
        self,
        address: str,
        port: int,
        address_family: str,
        packet: bytes,
    ) -> bytes:
        family = self._socket_family(address, address_family)

        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(self._timeout)
            sock.connect(self._destination(address, port, family))
            sock.sendall(struct.pack("!H", len(packet)) + packet)

            length_data = self._recv_exact(sock, 2)
            response_length = struct.unpack("!H", length_data)[0]

            if response_length == 0:
                raise ValueError("empty DNS TCP response")

            if response_length > self._max_packet_bytes:
                raise ValueError("DNS TCP response exceeds configured limit")

            return self._recv_exact(sock, response_length)

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        data = bytearray()

        while len(data) < size:
            chunk = sock.recv(size - len(data))

            if not chunk:
                raise ConnectionError("DNS TCP connection closed early")

            data.extend(chunk)

        return bytes(data)

    @staticmethod
    def _socket_family(address: str, address_family: str) -> int:
        if address_family.lower() == "ipv4":
            return socket.AF_INET

        if address_family.lower() == "ipv6":
            return socket.AF_INET6

        detected = ipaddress.ip_address(address)
        return socket.AF_INET if detected.version == 4 else socket.AF_INET6

    @staticmethod
    def _destination(
        address: str,
        port: int,
        family: int,
    ) -> tuple:
        if family == socket.AF_INET6:
            return (address, port, 0, 0)

        return (address, port)

    def _parse_response(
        self,
        packet: bytes,
        transaction_id: int,
        query_name: str,
        query_type: str,
        query_class: str,
    ) -> dict[str, Any]:
        if len(packet) < _DNS_HEADER_SIZE:
            raise ValueError("DNS response is shorter than the header")

        (
            response_id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        ) = struct.unpack("!HHHHHH", packet[:12])

        if response_id != transaction_id:
            raise ValueError("DNS transaction ID mismatch")

        qr = bool(flags & 0x8000)

        if not qr:
            raise ValueError("DNS response does not have the response flag")

        base_response_code = flags & 0x000F

        offset = _DNS_HEADER_SIZE
        questions = []

        for _ in range(question_count):
            name, offset = self._read_name(packet, offset)

            if offset + 4 > len(packet):
                raise ValueError("truncated DNS question")

            qtype, qclass = struct.unpack(
                "!HH",
                packet[offset:offset + 4],
            )
            offset += 4

            questions.append(
                {
                    "name": name,
                    "type": self._type_name(qtype),
                    "class": self._class_name(qclass),
                }
            )

        edns = {
            "present": False,
            "version": None,
            "udp_payload_size": None,
            "dnssec_ok": False,
            "extended_rcode": 0,
            "flags": {},
            "options": [],
        }

        sections = {}

        for section_name, count in (
            ("answers", answer_count),
            ("authorities", authority_count),
            ("additionals", additional_count),
        ):
            records = []

            for _ in range(count):
                if section_name == "additionals":
                    record, offset = self._read_record(
                        packet,
                        offset,
                        parse_edns=edns,
                    )
                else:
                    record, offset = self._read_record(
                        packet,
                        offset,
                    )

                if record.get("type") != "OPT":
                    records.append(record)

            sections[section_name] = records

        response_code = (
            base_response_code
            | (int(edns["extended_rcode"]) << 4)
        )

        all_records = (
            sections["answers"]
            + sections["authorities"]
            + sections["additionals"]
        )
        dnssec = self._analyze_dnssec_records(all_records)

        return {
            "response_code": response_code,
            "response_code_name": self._rcode_name(response_code),
            "flags": {
                "qr": qr,
                "aa": bool(flags & 0x0400),
                "tc": bool(flags & 0x0200),
                "rd": bool(flags & 0x0100),
                "ra": bool(flags & 0x0080),
                "ad": bool(flags & 0x0020),
                "cd": bool(flags & 0x0010),
            },
            "question_count": question_count,
            "answer_count": answer_count,
            "authority_count": authority_count,
            "additional_count": additional_count,
            "questions": questions,
            "answers": sections["answers"],
            "authorities": sections["authorities"],
            "additionals": sections["additionals"],
            "edns": edns,
            "dnssec": dnssec,
            "truncated": bool(flags & 0x0200),
            "query_name": query_name,
            "query_type": query_type,
            "query_class": query_class,
        }

    def _read_record(
        self,
        packet: bytes,
        offset: int,
        *,
        parse_edns: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], int]:
        name, offset = self._read_name(packet, offset)

        if offset + 10 > len(packet):
            raise ValueError("truncated DNS record header")

        record_type, record_class, ttl, rdlength = struct.unpack(
            "!HHIH",
            packet[offset:offset + 10],
        )
        offset += 10

        if offset + rdlength > len(packet):
            raise ValueError("truncated DNS record data")

        rdata_offset = offset
        rdata = packet[offset:offset + rdlength]
        offset += rdlength

        if record_type == 41:
            if parse_edns is not None:
                self._parse_edns_opt(
                    record_class,
                    ttl,
                    rdata,
                    parse_edns,
                )

            return {
                "name": name,
                "type": "OPT",
                "class": record_class,
                "ttl": ttl,
                "rdlength": rdlength,
            }, offset

        record: dict[str, Any] = {
            "name": name,
            "type": self._type_name(record_type),
            "class": self._class_name(record_class),
            "ttl": ttl,
            "rdlength": rdlength,
        }

        if record_type == 1 and rdlength == 4:
            record["address"] = socket.inet_ntop(socket.AF_INET, rdata)

        elif record_type == 28 and rdlength == 16:
            record["address"] = socket.inet_ntop(socket.AF_INET6, rdata)

        elif record_type in {2, 5, 12}:
            value, _ = self._read_name(packet, rdata_offset)
            record["target"] = value

        elif record_type == 15 and rdlength >= 3:
            preference = struct.unpack("!H", rdata[:2])[0]
            exchange, _ = self._read_name(packet, rdata_offset + 2)
            record["preference"] = preference
            record["exchange"] = exchange

        elif record_type == 6:
            mname, cursor = self._read_name(packet, rdata_offset)
            rname, cursor = self._read_name(packet, cursor)

            if cursor + 20 > rdata_offset + rdlength:
                raise ValueError("truncated DNS SOA record")

            serial, refresh, retry, expire, minimum = struct.unpack(
                "!IIIII",
                packet[cursor:cursor + 20],
            )

            record.update(
                {
                    "mname": mname,
                    "rname": rname,
                    "serial": serial,
                    "refresh": refresh,
                    "retry": retry,
                    "expire": expire,
                    "minimum": minimum,
                }
            )

        elif record_type == 16:
            strings = []
            cursor = 0

            while cursor < len(rdata):
                length = rdata[cursor]
                cursor += 1

                if cursor + length > len(rdata):
                    raise ValueError("truncated DNS TXT string")

                strings.append(
                    rdata[cursor:cursor + length].decode(
                        "utf-8",
                        errors="replace",
                    )
                )
                cursor += length

            record["strings"] = strings
            record["text"] = "".join(strings)

        elif record_type == 33 and rdlength >= 7:
            priority, weight, port = struct.unpack("!HHH", rdata[:6])
            target, _ = self._read_name(packet, rdata_offset + 6)

            record.update(
                {
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target,
                }
            )

        elif record_type == 43:
            if rdlength < 4:
                raise ValueError("truncated DNS DS record")

            key_tag, algorithm, digest_type = struct.unpack(
                "!HBB",
                rdata[:4],
            )

            record.update(
                {
                    "key_tag": key_tag,
                    "algorithm": algorithm,
                    "algorithm_name": self._dnssec_algorithm_name(algorithm),
                    "digest_type": digest_type,
                    "digest_name": self._dnssec_digest_name(digest_type),
                    "digest_hex": rdata[4:].hex(),
                }
            )

        elif record_type == 46:
            if rdlength < 18:
                raise ValueError("truncated DNS RRSIG record")

            (
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
            ) = struct.unpack(
                "!HBBIIIH",
                rdata[:18],
            )

            signer_name, signer_end = self._read_name(
                packet,
                rdata_offset + 18,
            )

            signature_offset = signer_end
            signature_end = rdata_offset + rdlength

            if signature_offset > signature_end:
                raise ValueError("invalid DNS RRSIG signer name")

            record.update(
                {
                    "type_covered": self._type_name(type_covered),
                    "type_covered_code": type_covered,
                    "algorithm": algorithm,
                    "algorithm_name": self._dnssec_algorithm_name(algorithm),
                    "labels": labels,
                    "original_ttl": original_ttl,
                    "expiration": expiration,
                    "inception": inception,
                    "key_tag": key_tag,
                    "signer_name": signer_name,
                    "signature_hex": packet[
                        signature_offset:signature_end
                    ].hex(),
                }
            )

        elif record_type == 48:
            if rdlength < 4:
                raise ValueError("truncated DNS DNSKEY record")

            flags, protocol, algorithm = struct.unpack(
                "!HBB",
                rdata[:4],
            )

            record.update(
                {
                    "flags": flags,
                    "protocol": protocol,
                    "algorithm": algorithm,
                    "algorithm_name": self._dnssec_algorithm_name(algorithm),
                    "secure_entry_point": bool(flags & 0x0001),
                    "zone_key": bool(flags & 0x0100),
                    "revoke": bool(flags & 0x0080),
                    "public_key_hex": rdata[4:].hex(),
                }
            )

        elif record_type == 47:
            next_domain, next_offset = self._read_name(
                packet,
                rdata_offset,
            )

            bitmap_offset = next_offset
            bitmap_end = rdata_offset + rdlength

            if bitmap_offset > bitmap_end:
                raise ValueError("invalid DNS NSEC type bitmap")

            record.update(
                {
                    "next_domain": next_domain,
                    "types": self._parse_type_bitmap(
                        packet[bitmap_offset:bitmap_end]
                    ),
                }
            )

        elif record_type == 50:
            if rdlength < 5:
                raise ValueError("truncated DNS NSEC3 record")

            (
                hash_algorithm,
                flags,
                iterations,
                salt_length,
            ) = struct.unpack(
                "!BBHB",
                rdata[:5],
            )

            cursor = 5

            if cursor + salt_length > rdlength:
                raise ValueError("truncated DNS NSEC3 salt")

            salt = rdata[cursor:cursor + salt_length]
            cursor += salt_length

            if cursor >= rdlength:
                raise ValueError("truncated DNS NSEC3 hash length")

            hash_length = rdata[cursor]
            cursor += 1

            if cursor + hash_length > rdlength:
                raise ValueError("truncated DNS NSEC3 next hash")

            next_hashed_owner = rdata[
                cursor:cursor + hash_length
            ]
            cursor += hash_length

            record.update(
                {
                    "hash_algorithm": hash_algorithm,
                    "hash_algorithm_name": self._dnssec_hash_algorithm_name(
                        hash_algorithm
                    ),
                    "flags": flags,
                    "opt_out": bool(flags & 0x01),
                    "iterations": iterations,
                    "salt_hex": salt.hex(),
                    "next_hashed_owner_hex": next_hashed_owner.hex(),
                    "types": self._parse_type_bitmap(
                        rdata[cursor:]
                    ),
                }
            )

        elif record_type == 51:
            if rdlength < 5:
                raise ValueError("truncated DNS NSEC3PARAM record")

            (
                hash_algorithm,
                flags,
                iterations,
                salt_length,
            ) = struct.unpack(
                "!BBHB",
                rdata[:5],
            )

            if 5 + salt_length > rdlength:
                raise ValueError("truncated DNS NSEC3PARAM salt")

            salt = rdata[5:5 + salt_length]

            record.update(
                {
                    "hash_algorithm": hash_algorithm,
                    "hash_algorithm_name": self._dnssec_hash_algorithm_name(
                        hash_algorithm
                    ),
                    "flags": flags,
                    "iterations": iterations,
                    "salt_hex": salt.hex(),
                }
            )

        else:
            record["rdata_hex"] = rdata.hex()

        return record, offset

    @staticmethod
    def _dnssec_algorithm_name(value: int) -> str:
        return {
            1: "RSAMD5",
            3: "DSA",
            5: "RSASHA1",
            6: "DSA-NSEC3-SHA1",
            7: "RSASHA1-NSEC3-SHA1",
            8: "RSASHA256",
            10: "RSASHA512",
            12: "ECC-GOST",
            13: "ECDSAP256SHA256",
            14: "ECDSAP384SHA384",
            15: "ED25519",
            16: "ED448",
        }.get(value, f"ALG{value}")

    @staticmethod
    def _dnssec_digest_name(value: int) -> str:
        return {
            1: "SHA-1",
            2: "SHA-256",
            3: "GOST R 34.11-94",
            4: "SHA-384",
        }.get(value, f"DIGEST{value}")

    @staticmethod
    def _dnssec_hash_algorithm_name(value: int) -> str:
        return {
            1: "SHA-1",
        }.get(value, f"HASH{value}")

    def _parse_type_bitmap(self, data: bytes) -> list[str]:
        types = []
        cursor = 0

        while cursor < len(data):
            if cursor + 2 > len(data):
                raise ValueError("truncated DNS type bitmap window")

            window, length = struct.unpack(
                "!BB",
                data[cursor:cursor + 2],
            )
            cursor += 2

            if window > 255:
                raise ValueError("invalid DNS type bitmap window")

            if length == 0 or length > 32:
                raise ValueError("invalid DNS type bitmap length")

            if cursor + length > len(data):
                raise ValueError("truncated DNS type bitmap")

            bitmap = data[cursor:cursor + length]
            cursor += length

            for byte_index, value in enumerate(bitmap):
                for bit_index in range(8):
                    if value & (0x80 >> bit_index):
                        type_code = (
                            window * 256
                            + byte_index * 8
                            + bit_index
                        )
                        types.append(self._type_name(type_code))

        return types

    @staticmethod
    def _parse_edns_opt(
        udp_payload_size: int,
        ttl: int,
        rdata: bytes,
        edns: dict[str, Any],
    ) -> None:
        extended_rcode = (ttl >> 24) & 0xFF
        version = (ttl >> 16) & 0xFF
        flags = ttl & 0xFFFF

        options = []
        cursor = 0

        while cursor < len(rdata):
            if cursor + 4 > len(rdata):
                raise ValueError("truncated EDNS option header")

            option_code, option_length = struct.unpack(
                "!HH",
                rdata[cursor:cursor + 4],
            )
            cursor += 4

            if cursor + option_length > len(rdata):
                raise ValueError("truncated EDNS option data")

            option_data = rdata[cursor:cursor + option_length]
            cursor += option_length

            options.append(
                {
                    "code": option_code,
                    "length": option_length,
                    "data_hex": option_data.hex(),
                }
            )

        edns.update(
            {
                "present": True,
                "version": version,
                "udp_payload_size": udp_payload_size,
                "dnssec_ok": bool(flags & 0x8000),
                "extended_rcode": extended_rcode,
                "flags": {
                    "dnssec_ok": bool(flags & 0x8000),
                    "reserved": flags & 0x7FFF,
                },
                "options": options,
            }
        )

    def _read_name(
        self,
        packet: bytes,
        offset: int,
    ) -> tuple[str, int]:
        labels = []
        cursor = offset
        jumped = False
        return_offset = offset
        pointers = 0

        while True:
            if cursor >= len(packet):
                raise ValueError("DNS name exceeds packet")

            length = packet[cursor]

            if length == 0:
                cursor += 1

                if not jumped:
                    return_offset = cursor

                break

            if length & 0xC0 == 0xC0:
                if cursor + 1 >= len(packet):
                    raise ValueError("truncated DNS compression pointer")

                pointer = ((length & 0x3F) << 8) | packet[cursor + 1]

                pointers += 1

                if pointers > _MAX_NAME_POINTERS:
                    raise ValueError("too many DNS compression pointers")

                if not jumped:
                    return_offset = cursor + 2

                cursor = pointer
                jumped = True
                continue

            if length & 0xC0:
                raise ValueError("invalid DNS label encoding")

            cursor += 1

            if cursor + length > len(packet):
                raise ValueError("truncated DNS label")

            label = packet[cursor:cursor + length].decode(
                "ascii",
                errors="replace",
            )
            labels.append(label)
            cursor += length

        return ".".join(labels) if labels else ".", return_offset

    @staticmethod
    def _analyze_dnssec_records(
        records: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    ) -> dict[str, Any]:
        dnssec_types = {
            "DS",
            "RRSIG",
            "NSEC",
            "DNSKEY",
            "NSEC3",
            "NSEC3PARAM",
        }

        dnssec_records = [
            record
            for record in records
            if record.get("type") in dnssec_types
        ]

        algorithms = sorted(
            {
                record.get("algorithm_name")
                for record in dnssec_records
                if record.get("algorithm_name")
            }
        )

        warnings = []

        for record in dnssec_records:
            record_type = record.get("type")

            if record_type == "DNSKEY":
                if record.get("protocol") != 3:
                    warnings.append(
                        "DNSKEY protocol value is not 3"
                    )

                if not record.get("public_key_hex"):
                    warnings.append(
                        "DNSKEY record contains an empty public key"
                    )

            elif record_type == "DS":
                if not record.get("digest_hex"):
                    warnings.append(
                        "DS record contains an empty digest"
                    )

                if record.get("digest_type") not in {1, 2, 3, 4}:
                    warnings.append(
                        "DS record uses an unknown digest algorithm"
                    )

            elif record_type == "RRSIG":
                if not record.get("signer_name"):
                    warnings.append(
                        "RRSIG record has an empty signer name"
                    )

                if not record.get("signature_hex"):
                    warnings.append(
                        "RRSIG record contains an empty signature"
                    )

            elif record_type == "NSEC":
                if not record.get("next_domain"):
                    warnings.append(
                        "NSEC record has an empty next domain"
                    )

            elif record_type == "NSEC3":
                if not record.get("next_hashed_owner_hex"):
                    warnings.append(
                        "NSEC3 record contains an empty next hashed owner"
                    )

                if record.get("hash_algorithm") != 1:
                    warnings.append(
                        "NSEC3 record uses an unknown hash algorithm"
                    )

        return {
            "present": bool(dnssec_records),
            "record_count": len(dnssec_records),
            "record_types": sorted(
                {
                    record.get("type")
                    for record in dnssec_records
                }
            ),
            "algorithms": algorithms,
            "warnings": sorted(set(warnings)),
        }

    @staticmethod
    def _type_name(value: int) -> str:
        return {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            43: "DS",
            46: "RRSIG",
            47: "NSEC",
            48: "DNSKEY",
            50: "NSEC3",
            51: "NSEC3PARAM",
        }.get(value, f"TYPE{value}")

    @staticmethod
    def _class_name(value: int) -> str:
        return {1: "IN"}.get(value, f"CLASS{value}")

    @staticmethod
    def _rcode_name(value: int) -> str:
        return {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED",
            6: "YXDOMAIN",
            7: "YXRRSET",
            8: "NXRRSET",
            9: "NOTAUTH",
            10: "NOTZONE",
            16: "BADVERS",
            17: "BADKEY",
            18: "BADTIME",
            19: "BADMODE",
            20: "BADNAME",
            21: "BADALG",
            22: "BADTRUNC",
            23: "BADCOOKIE",
        }.get(value, f"RCODE{value}")

    @staticmethod
    def _error(
        target: str,
        address: str,
        address_family: str,
        port: int,
        transport: str,
        query_name: str,
        query_type: str,
        query_class: str,
        category: str,
        exc: Exception,
    ) -> DnsObservation:
        return DnsObservation(
            target=target,
            address=address,
            address_family=address_family,
            port=port,
            transport=transport,
            success=False,
            query_name=query_name,
            query_type=query_type.upper(),
            query_class=query_class.upper(),
            response_code=None,
            response_code_name=None,
            flags={},
            question_count=0,
            answer_count=0,
            authority_count=0,
            additional_count=0,
            answers=(),
            authorities=(),
            additionals=(),
            edns={
                "present": False,
                "version": None,
                "udp_payload_size": None,
                "dnssec_ok": False,
                "extended_rcode": 0,
                "flags": {},
                "options": [],
            },
            dnssec={
                "present": False,
                "record_count": 0,
                "record_types": [],
                "algorithms": [],
                "warnings": [],
            },
            latency_ms=None,
            truncated=False,
            tcp_fallback_attempted=False,
            tcp_fallback_successful=False,
            identification_method=category,
            confidence=0.0,
            timestamp=DnsProbe._timestamp(),
            evidence=(
                f"DNS {transport.upper()} probe failed: "
                f"{type(exc).__name__}: {exc}",
            ),
            error=f"{category}: {type(exc).__name__}: {exc}",
        )

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()


__all__ = [
    "DnsObservation",
    "DnsProbe",
]
