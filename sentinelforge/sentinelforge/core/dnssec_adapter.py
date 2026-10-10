"""
DNSSEC integration adapter for SentinelForge.

Converts parsed DNS records collected by DnsProbe into dnspython RRsets
and delegates cryptographic validation to DnssecValidator.
"""

from __future__ import annotations

from collections import defaultdict
import base64
from typing import Any, Iterable

import dns.name
import dns.rdataset
import dns.rdatatype
import dns.rrset

from .dnssec_validator import DnssecValidationResult, DnssecValidator


class DnssecAdapter:
    """Convert DnsProbe records and invoke the DNSSEC validator."""

    def __init__(
        self,
        validator: DnssecValidator | None = None,
    ) -> None:
        self._validator = validator or DnssecValidator()

    def validate(
        self,
        *,
        name: str,
        records: Iterable[dict[str, Any]],
        now: float | None = None,
    ) -> DnssecValidationResult:
        """Validate DNSSEC records collected by DnsProbe."""

        normalized_name = self._normalize_name(name)
        record_list = list(records)

        dnskey_rrset = self._build_rrset(
            normalized_name,
            "DNSKEY",
            [
                record
                for record in record_list
                if record.get("type") == "DNSKEY"
            ],
        )

        ds_rrset = self._build_rrset(
            normalized_name,
            "DS",
            [
                record
                for record in record_list
                if record.get("type") == "DS"
            ],
        )

        rrsets = self._build_signed_rrsets(
            normalized_name,
            record_list,
        )

        return self._validator.validate(
            name=normalized_name,
            dnskey_rrset=dnskey_rrset,
            ds_rrset=ds_rrset,
            rrsets=rrsets or None,
            now=now,
        )

    @staticmethod
    def _normalize_name(name: str) -> str:
        value = name.strip()

        if not value:
            raise ValueError("DNS name cannot be empty")

        return value if value.endswith(".") else value + "."

    def _build_signed_rrsets(
        self,
        default_name: str,
        records: list[dict[str, Any]],
    ) -> dict[
        tuple[str, str],
        tuple[dns.rrset.RRset, dns.rrset.RRset],
    ]:
        ordinary: dict[
            tuple[str, str],
            list[dict[str, Any]],
        ] = defaultdict(list)

        signatures: dict[
            tuple[str, str],
            list[dict[str, Any]],
        ] = defaultdict(list)

        for record in records:
            record_type = record.get("type")
            owner = self._normalize_name(
                str(record.get("name") or default_name)
            )

            if record_type == "RRSIG":
                covered = str(record.get("type_covered", "")).upper()

                if covered:
                    signatures[(owner, covered)].append(record)

            elif record_type not in {
                "OPT",
                "DS",
                "DNSKEY",
                "NSEC",
                "NSEC3",
                "NSEC3PARAM",
            }:
                ordinary[(owner, str(record_type).upper())].append(record)

        result: dict[
            tuple[str, str],
            tuple[dns.rrset.RRset, dns.rrset.RRset],
        ] = {}

        for key, signature_records in signatures.items():
            ordinary_records = ordinary.get(key)

            if not ordinary_records:
                continue

            owner, record_type = key

            try:
                rrset = self._build_rrset(
                    owner,
                    record_type,
                    ordinary_records,
                )

                rrsigset = self._build_rrsig_rrset(
                    owner,
                    signature_records,
                )

                if rrset is not None and rrsigset is not None:
                    result[key] = (rrset, rrsigset)

            except (TypeError, ValueError):
                continue

        return result

    def _build_rrset(
        self,
        owner: str,
        record_type: str,
        records: list[dict[str, Any]],
    ) -> dns.rrset.RRset | None:
        if not records:
            return None

        rdtype = dns.rdatatype.from_text(record_type)

        first = records[0]
        ttl = int(first.get("ttl", 0))

        rdataset = dns.rdataset.Rdataset(
            dns.rdataclass.IN,
            rdtype,
        )
        rdataset.ttl = ttl

        for record in records:
            rdata = self._record_to_rdata(
                owner,
                record_type,
                record,
            )

            if rdata is not None:
                rdataset.add(rdata)

        if not rdataset:
            return None

        rrset = dns.rrset.RRset(
            dns.name.from_text(owner),
            dns.rdataclass.IN,
            rdtype,
        )
        rrset.ttl = ttl

        for rdata in rdataset:
            rrset.add(rdata)

        return rrset

    def _build_rrsig_rrset(
        self,
        owner: str,
        records: list[dict[str, Any]],
    ) -> dns.rrset.RRset | None:
        if not records:
            return None

        rdataset = dns.rdataset.Rdataset(
            dns.rdataclass.IN,
            dns.rdatatype.RRSIG,
        )
        rdataset.ttl = int(records[0].get("original_ttl", 0))

        for record in records:
            rdata = self._record_to_rdata(
                owner,
                "RRSIG",
                record,
            )

            if rdata is not None:
                rdataset.add(rdata)

        if not rdataset:
            return None

        rrset = dns.rrset.RRset(
            dns.name.from_text(owner),
            dns.rdataclass.IN,
            dns.rdatatype.RRSIG,
        )
        rrset.ttl = rdataset.ttl

        for rdata in rdataset:
            rrset.add(rdata)

        return rrset

    @staticmethod
    def _record_to_rdata(
        owner: str,
        record_type: str,
        record: dict[str, Any],
    ) -> Any | None:
        """Convert one parsed record into dnspython RDATA."""

        # This adapter intentionally uses dnspython's text parser so that
        # canonical DNSSEC serialization remains dnspython's responsibility.

        if record_type == "A":
            address = record.get("address")
            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.A,
                str(address),
            )

        if record_type == "AAAA":
            address = record.get("address")
            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.AAAA,
                str(address),
            )

        if record_type == "CNAME":
            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.CNAME,
                str(record.get("target")),
            )

        if record_type == "NS":
            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.NS,
                str(record.get("target")),
            )

        if record_type == "PTR":
            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.PTR,
                str(record.get("target")),
            )

        if record_type == "MX":
            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.MX,
                f"{int(record['preference'])} {record['exchange']}",
            )

        if record_type == "TXT":
            strings = record.get("strings", [])

            quoted = " ".join(
                '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'
                for value in strings
            )

            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.TXT,
                quoted,
            )

        if record_type == "SRV":
            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.SRV,
                (
                    f"{int(record['priority'])} "
                    f"{int(record['weight'])} "
                    f"{int(record['port'])} "
                    f"{record['target']}"
                ),
            )

        if record_type == "RRSIG":
            signer = str(record.get("signer_name") or "").strip()
            if signer and not signer.endswith("."):
                signer += "."

            signature = str(record.get("signature_hex", ""))

            if not signature:
                return None

            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.RRSIG,
                (
                    f"{record['type_covered']} "
                    f"{int(record['algorithm'])} "
                    f"{int(record['labels'])} "
                    f"{int(record['original_ttl'])} "
                    f"{int(record['expiration'])} "
                    f"{int(record['inception'])} "
                    f"{int(record['key_tag'])} "
                    f"{signer} "
                    f"{base64.b64encode(bytes.fromhex(signature)).decode()}"
                ),
            )

        if record_type == "DS":
            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DS,
                (
                    f"{int(record['key_tag'])} "
                    f"{int(record['algorithm'])} "
                    f"{int(record['digest_type'])} "
                    f"{record['digest_hex']}"
                ),
            )

        if record_type == "DNSKEY":
            return dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DNSKEY,
                (
                    f"{int(record['flags'])} "
                    f"{int(record['protocol'])} "
                    f"{int(record['algorithm'])} "
                    f"{base64.b64encode(bytes.fromhex(record['public_key_hex'])).decode()}"
                ),
            )

        return None


__all__ = [
    "DnssecAdapter",
]
