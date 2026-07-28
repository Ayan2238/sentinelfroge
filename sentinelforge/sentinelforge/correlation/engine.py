"""
Correlation Engine
~~~~~~~~~~~~~~~~~~
Transforms isolated findings from multiple modules/plugins into meaningful
intelligence: risk scoring, attack chain detection, and de-duplication.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sentinelforge.modules.base import Finding, Severity


# ---------------------------------------------------------------------------
# Output types
# ---------------------------------------------------------------------------


@dataclass
class CorrelatedReport:
    """
    Fully correlated output for one scan.

    Attributes
    ----------
    findings:
        De-duplicated, priority-ordered list of all findings.
    risk_score:
        0–100 overall risk score for the target.
    attack_chains:
        Detected multi-step attack paths (list of finding title sequences).
    severity_distribution:
        Count of findings per severity level.
    statistics:
        Misc scan statistics.
    """

    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    severity_distribution: dict[str, int] = field(default_factory=dict)
    statistics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": round(self.risk_score, 1),
            "findings": [f.to_dict() for f in self.findings],
            "attack_chains": self.attack_chains,
            "severity_distribution": self.severity_distribution,
            "statistics": self.statistics,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class CorrelationEngine:
    """
    Correlates raw findings from all modules into actionable intelligence.

    Usage::

        engine = CorrelationEngine()
        report = engine.correlate(all_findings)
    """

    # Attack chain patterns: list of title fragments that, when all present,
    # form a meaningful attack chain.
    _ATTACK_CHAINS: list[dict[str, Any]] = [
        {
            "name": "Full Compromise Chain",
            "description": "SQL injection leads to data exfiltration and potential server takeover.",
            "severity": "critical",
            "required": ["SQL Injection", "Open Ports", "Lateral Movement"],
        },
        {
            "name": "Account Takeover Chain",
            "description": "Reflected XSS combined with missing cookie flags enables session hijacking.",
            "severity": "high",
            "required": ["Reflected XSS", "Cookie Missing"],
        },
        {
            "name": "Credential Harvesting Chain",
            "description": "Default credentials combined with sensitive data exposure.",
            "severity": "critical",
            "required": ["Default Credentials", "Sensitive Data"],
        },
        {
            "name": "Cloud Data Breach Chain",
            "description": "Public cloud storage combined with sensitive path exposure.",
            "severity": "critical",
            "required": ["S3 Bucket", "Sensitive"],
        },
        {
            "name": "Server Recon → Exploitation",
            "description": "Version disclosure enables targeted exploitation.",
            "severity": "medium",
            "required": ["Version Disclosed", "Open TCP Ports"],
        },
    ]

    def correlate(self, findings: list[Finding]) -> CorrelatedReport:
        """
        Correlate *findings* and return a :class:`CorrelatedReport`.

        Steps:
        1. De-duplicate near-identical findings.
        2. Sort by severity (critical first).
        3. Detect attack chains.
        4. Compute overall risk score.
        5. Build severity distribution.
        """
        deduplicated = self._deduplicate(findings)
        sorted_findings = self._sort_by_severity(deduplicated)
        chains = self._detect_chains(sorted_findings)
        risk_score = self._compute_risk_score(sorted_findings, chains)
        distribution = self._severity_distribution(sorted_findings)
        statistics = self._build_statistics(sorted_findings)

        return CorrelatedReport(
            findings=sorted_findings,
            risk_score=risk_score,
            attack_chains=chains,
            severity_distribution=distribution,
            statistics=statistics,
        )

    # ------------------------------------------------------------------
    # Steps
    # ------------------------------------------------------------------

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove findings that are semantically identical (same title + target)."""
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.title.lower().strip(), str(f.target).lower())
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    @staticmethod
    def _sort_by_severity(findings: list[Finding]) -> list[Finding]:
        order = {
            "critical": 0, "high": 1, "medium": 2,
            "low": 3, "info": 4, "none": 5,
        }
        return sorted(
            findings,
            key=lambda f: (order.get(f.severity.value, 9), -f.confidence),
        )

    def _detect_chains(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Detect multi-step attack chains present in this finding set."""
        titles_text = " | ".join(f.title for f in findings).lower()
        matched_chains: list[dict[str, Any]] = []

        for chain in self._ATTACK_CHAINS:
            if all(
                req.lower() in titles_text
                for req in chain["required"]
            ):
                matched_chains.append({
                    "name": chain["name"],
                    "description": chain["description"],
                    "severity": chain["severity"],
                    "steps": [
                        f.title for f in findings
                        if any(req.lower() in f.title.lower() for req in chain["required"])
                    ],
                })

        return matched_chains

    def _compute_risk_score(
        self,
        findings: list[Finding],
        chains: list[dict[str, Any]],
    ) -> float:
        """
        Compute an overall 0–100 risk score.

        Formula:
            Base score from weighted finding severity counts
            + chain bonus (each chain adds up to 10 points)
        """
        weights = {
            "critical": 20.0,
            "high": 10.0,
            "medium": 5.0,
            "low": 2.0,
            "info": 0.5,
        }
        base = sum(
            weights.get(f.severity.value, 0) * f.confidence
            for f in findings
        )
        chain_bonus = min(len(chains) * 8.0, 20.0)
        score = min(base + chain_bonus, 100.0)
        return round(score, 1)

    @staticmethod
    def _severity_distribution(findings: list[Finding]) -> dict[str, int]:
        counts = Counter(f.severity.value for f in findings)
        return {
            sev: counts.get(sev, 0)
            for sev in ("critical", "high", "medium", "low", "info")
        }

    @staticmethod
    def _build_statistics(findings: list[Finding]) -> dict[str, Any]:
        if not findings:
            return {"total": 0, "modules": [], "top_tags": []}
        modules = list({f.module for f in findings})
        all_tags: list[str] = [tag for f in findings for tag in f.tags]
        top_tags = [tag for tag, _ in Counter(all_tags).most_common(10)]
        return {
            "total": len(findings),
            "modules": sorted(modules),
            "top_tags": top_tags,
        }
