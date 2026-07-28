"""Tests for the reporting engine and formatters."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinelforge.correlation.engine import CorrelationEngine, CorrelatedReport
from sentinelforge.modules.base import Finding, Severity
from sentinelforge.reporting.engine import ReportEngine
from sentinelforge.core.session import Session


@pytest.fixture
def sample_findings() -> list[Finding]:
    return [
        Finding(
            module="vulnerability",
            title="Missing Security Header: Strict-Transport-Security",
            severity=Severity.HIGH,
            target="example.com",
            description="HSTS header missing.",
            evidence=["Header not found"],
            recommendation="Add HSTS header.",
            confidence=1.0,
            tags=["headers"],
        ),
        Finding(
            module="reconnaissance",
            title="Open TCP Ports Detected",
            severity=Severity.MEDIUM,
            target="example.com",
            evidence=["Port 80/tcp open", "Port 443/tcp open"],
            tags=["ports"],
        ),
        Finding(
            module="plugin:ssl",
            title="SSL Certificate Expiring Soon (< 30 days)",
            severity=Severity.MEDIUM,
            target="example.com",
            confidence=1.0,
            tags=["ssl"],
        ),
        Finding(
            module="reconnaissance",
            title="Subdomains Discovered",
            severity=Severity.INFO,
            target="example.com",
            evidence=["api.example.com", "mail.example.com"],
            tags=["recon"],
        ),
    ]


@pytest.fixture
def correlated(sample_findings: list[Finding]) -> CorrelatedReport:
    engine = CorrelationEngine()
    return engine.correlate(sample_findings)


@pytest.fixture
def session() -> Session:
    s = Session(targets=["example.com"], profile="normal")
    s.start()
    s.complete()
    return s


class TestCorrelationEngine:
    def test_deduplication(self) -> None:
        findings = [
            Finding(module="m", title="XSS", severity=Severity.HIGH, target="example.com"),
            Finding(module="m", title="XSS", severity=Severity.HIGH, target="example.com"),
        ]
        report = CorrelationEngine().correlate(findings)
        assert len(report.findings) == 1

    def test_severity_distribution(self, correlated: CorrelatedReport) -> None:
        dist = correlated.severity_distribution
        assert dist["high"] == 1
        assert dist["medium"] == 2
        assert dist["info"] == 1
        assert dist["critical"] == 0

    def test_risk_score_nonzero(self, correlated: CorrelatedReport) -> None:
        assert correlated.risk_score > 0

    def test_sorted_by_severity(self, correlated: CorrelatedReport) -> None:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        severities = [order[f.severity.value] for f in correlated.findings]
        assert severities == sorted(severities)

    def test_statistics_total(self, correlated: CorrelatedReport) -> None:
        assert correlated.statistics["total"] == 4

    def test_attack_chain_detection(self) -> None:
        findings = [
            Finding(module="m", title="Reflected XSS Confirmed", severity=Severity.HIGH, target="t"),
            Finding(module="m", title="Cookie Missing HttpOnly Flag", severity=Severity.MEDIUM, target="t"),
        ]
        report = CorrelationEngine().correlate(findings)
        chain_names = [c["name"] for c in report.attack_chains]
        assert "Account Takeover Chain" in chain_names

    def test_empty_findings(self) -> None:
        report = CorrelationEngine().correlate([])
        assert report.risk_score == 0.0
        assert report.findings == []


class TestReportEngine:
    def test_html_report_generated(
        self, correlated: CorrelatedReport, session: Session, tmp_path: Path
    ) -> None:
        engine = ReportEngine(output_dir=tmp_path, formats=["html"])
        paths = engine.generate(correlated, session)
        assert "html" in paths
        html_content = paths["html"].read_text()
        assert "SentinelForge" in html_content
        assert "example.com" in html_content

    def test_json_report_generated(
        self, correlated: CorrelatedReport, session: Session, tmp_path: Path
    ) -> None:
        import json
        engine = ReportEngine(output_dir=tmp_path, formats=["json"])
        paths = engine.generate(correlated, session)
        assert "json" in paths
        data = json.loads(paths["json"].read_text())
        assert "findings" in data
        assert "risk_score" in data
        assert len(data["findings"]) == 4

    def test_markdown_report_generated(
        self, correlated: CorrelatedReport, session: Session, tmp_path: Path
    ) -> None:
        engine = ReportEngine(output_dir=tmp_path, formats=["markdown"])
        paths = engine.generate(correlated, session)
        assert "markdown" in paths
        content = paths["markdown"].read_text()
        assert "SentinelForge" in content

    def test_csv_report_generated(
        self, correlated: CorrelatedReport, session: Session, tmp_path: Path
    ) -> None:
        import csv
        engine = ReportEngine(output_dir=tmp_path, formats=["csv"])
        paths = engine.generate(correlated, session)
        assert "csv" in paths
        rows = list(csv.DictReader(paths["csv"].read_text().splitlines()))
        assert len(rows) == len(correlated.findings)
        assert "severity" in rows[0]

    def test_multiple_formats(
        self, correlated: CorrelatedReport, session: Session, tmp_path: Path
    ) -> None:
        engine = ReportEngine(
            output_dir=tmp_path, formats=["html", "json", "markdown", "csv"]
        )
        paths = engine.generate(correlated, session)
        assert len(paths) == 4
