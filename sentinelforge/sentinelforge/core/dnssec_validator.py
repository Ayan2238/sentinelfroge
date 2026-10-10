"""DNSSEC cryptographic validation for SentinelForge.

Provides bounded validation of DNSSEC material already collected by the
DNS protocol layer. Uses dnspython's DNSSEC implementation rather than
reimplementing cryptographic primitives.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

import dns.dnssec
import dns.name
import dns.rdataset
import dns.rdatatype
import dns.rrset


@dataclass(frozen=True)
class DnssecValidationResult:
    """Structured DNSSEC validation result."""

    status: str
    secure: bool
    ds_present: bool
    dnskey_present: bool
    rrsig_present: bool
    ds_matches_dnskey: bool | None
    signatures_valid: bool | None
    signatures_in_window: bool | None
    key_tags: tuple[int, ...]
    algorithms: tuple[str, ...]
    validated_rrsets: int
    invalid_rrsets: int
    unsupported_rrsets: int
    evidence: tuple[str, ...]
    warnings: tuple[str, ...]
    errors: tuple[str, ...]


class DnssecValidator:
    """Validate DNSSEC material using dnspython."""

    DIGEST_NAMES = {
        1: "SHA1",
        2: "SHA256",
        3: "GOST",
        4: "SHA384",
    }

    SUPPORTED_DIGESTS = {
        "SHA1",
        "SHA256",
        "SHA384",
    }

    def validate(
        self,
        *,
        name: str,
        dnskey_rrset: dns.rrset.RRset | None = None,
        ds_rrset: dns.rrset.RRset | None = None,
        rrsets: Mapping[
            tuple[str, str],
            tuple[dns.rrset.RRset, dns.rrset.RRset],
        ]
        | None = None,
        now: float | None = None,
    ) -> DnssecValidationResult:
        """Validate DNSKEY/DS relationships and supplied signed RRsets."""

        evidence: list[str] = []
        warnings: list[str] = []
        errors: list[str] = []

        ds_present = ds_rrset is not None and bool(ds_rrset)
        dnskey_present = dnskey_rrset is not None and bool(dnskey_rrset)
        rrsig_present = bool(rrsets)

        key_tags: list[int] = []
        algorithms: set[str] = set()

        if dnskey_rrset:
            for key in dnskey_rrset:
                try:
                    key_tags.append(dns.dnssec.key_id(key))
                    algorithms.add(str(key.algorithm))
                except Exception as exc:
                    warnings.append(
                        f"DNSKEY key metadata unavailable: {type(exc).__name__}"
                    )

        key_tags = sorted(set(key_tags))

        if dnskey_present:
            evidence.append(f"DNSKEY records present: {len(dnskey_rrset)}")
            evidence.append(f"DNSKEY key tags: {', '.join(map(str, key_tags))}")

        if ds_present:
            evidence.append(f"DS records present: {len(ds_rrset)}")

        ds_matches_dnskey: bool | None = None

        if ds_present and dnskey_present:
            ds_matches_dnskey = False

            for ds in ds_rrset:
                digest_name = self.DIGEST_NAMES.get(
                    int(ds.digest_type),
                    f"UNKNOWN({ds.digest_type})",
                )

                if digest_name not in self.SUPPORTED_DIGESTS:
                    warnings.append(
                        f"Unsupported DS digest algorithm: {digest_name}"
                    )
                    continue

                for key in dnskey_rrset:
                    try:
                        generated = dns.dnssec.make_ds(
                            name,
                            key,
                            digest_name,
                        )

                        if (
                            generated.key_tag == ds.key_tag
                            and generated.algorithm == ds.algorithm
                            and generated.digest == ds.digest
                        ):
                            ds_matches_dnskey = True
                            break
                    except Exception as exc:
                        warnings.append(
                            "DS/DNSKEY digest calculation failed: "
                            f"{type(exc).__name__}"
                        )

                if ds_matches_dnskey:
                    break

            if ds_matches_dnskey:
                evidence.append("At least one DS record matches a DNSKEY.")
            else:
                warnings.append("No DS record matches the supplied DNSKEY set.")

        elif ds_present and not dnskey_present:
            warnings.append("DS records exist but no DNSKEY records were supplied.")

        signatures_valid: bool | None = None
        signatures_in_window: bool | None = None
        validated_rrsets = 0
        invalid_rrsets = 0
        unsupported_rrsets = 0

        if rrsets:
            signatures_valid = True
            signatures_in_window = True

            for (_, _), pair in rrsets.items():
                rrset, rrsigset = pair

                try:
                    dns.dnssec.validate(
                        rrset,
                        rrsigset,
                        {dnskey_rrset.name: dnskey_rrset},
                        now=now,
                    )

                    validated_rrsets += 1
                    evidence.append(
                        f"RRSIG validation succeeded for {rrset.name} "
                        f"{dns.rdatatype.to_text(rrset.rdtype)}."
                    )

                except dns.dnssec.UnsupportedAlgorithm:
                    signatures_valid = False
                    unsupported_rrsets += 1
                    warnings.append(
                        f"Unsupported DNSSEC algorithm for {rrset.name}."
                    )

                except dns.dnssec.ValidationFailure as exc:
                    signatures_valid = False
                    signatures_in_window = False
                    invalid_rrsets += 1
                    errors.append(
                        f"RRSIG validation failed for {rrset.name}: {exc}"
                    )

                except Exception as exc:
                    signatures_valid = False
                    invalid_rrsets += 1
                    errors.append(
                        f"DNSSEC validation error for {rrset.name}: "
                        f"{type(exc).__name__}"
                    )

        if not rrsets:
            signatures_valid = None
            signatures_in_window = None

        if ds_present and dnskey_present and ds_matches_dnskey is False:
            status = "bogus"
        elif signatures_valid is False and invalid_rrsets:
            status = "bogus"
        elif ds_present and dnskey_present and ds_matches_dnskey:
            if rrsets and signatures_valid:
                status = "secure"
            else:
                status = "indeterminate"
        elif dnskey_present and rrsets and signatures_valid:
            status = "indeterminate"
            warnings.append(
                "DNSSEC signatures validate, but no matching DS was supplied."
            )
        else:
            status = "indeterminate"

        secure = status == "secure"

        if status == "secure":
            evidence.append("DNSSEC cryptographic validation succeeded.")
        elif status == "bogus":
            errors.append("DNSSEC validation indicates a bogus security state.")
        else:
            warnings.append(
                "DNSSEC security state is indeterminate with the supplied data."
            )

        return DnssecValidationResult(
            status=status,
            secure=secure,
            ds_present=ds_present,
            dnskey_present=dnskey_present,
            rrsig_present=rrsig_present,
            ds_matches_dnskey=ds_matches_dnskey,
            signatures_valid=signatures_valid,
            signatures_in_window=signatures_in_window,
            key_tags=tuple(key_tags),
            algorithms=tuple(sorted(algorithms)),
            validated_rrsets=validated_rrsets,
            invalid_rrsets=invalid_rrsets,
            unsupported_rrsets=unsupported_rrsets,
            evidence=tuple(evidence),
            warnings=tuple(sorted(set(warnings))),
            errors=tuple(errors),
        )
