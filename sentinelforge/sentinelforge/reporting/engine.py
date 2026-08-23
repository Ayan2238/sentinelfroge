"""
Report Engine
~~~~~~~~~~~~~
Coordinates all output formatters and writes reports to disk.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from sentinelforge.correlation.engine import CorrelatedReport
    from sentinelforge.core.session import Session


class ReportEngine:
    """
    Generates reports in multiple formats from a :class:`CorrelatedReport`.

    Parameters
    ----------
    output_dir:
        Base directory for report output files.
        formats:
        List of format names to generate (``"html"``, ``"json"``,
        ``"markdown"``, ``"csv"``, ``"pdf"``).
    """

    def __init__(
        self,
        output_dir: str | Path = "output/reports",
        formats: list[str] | None = None,
    ) -> None:
        self._output_dir = Path(output_dir)
        self._formats = formats or ["html", "json"]
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        report: "CorrelatedReport",
        session: "Session",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Path]:
        """
        Write reports for all configured formats.

        Returns
        -------
        dict[str, Path]
            Mapping of format name → absolute output file path.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        session_short = session.session_id[:8]
        stem = f"sentinelforge-{session_short}-{ts}"

        report_data = self._build_report_data(report, session, metadata or {})
        written: dict[str, Path] = {}

        for fmt in self._formats:
            try:
                path = self._write(fmt, stem, report_data)
                if path:
                    written[fmt] = path
            except Exception as exc:  # noqa: BLE001
                # Non-fatal: log and continue
                import sys
                print(f"[ReportEngine] Failed to write {fmt} report: {exc}", file=sys.stderr)

        return written

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write(
        self,
        fmt: str,
        stem: str,
        data: dict[str, Any],
    ) -> Path | None:
        formatter = self._get_formatter(fmt)
        if formatter is None:
            return None
        content, ext = formatter(data)
        path = self._output_dir / f"{stem}.{ext}"
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path.resolve()

    def _get_formatter(self, fmt: str):  # type: ignore[return]
        from sentinelforge.reporting.formatters import html as html_fmt
        from sentinelforge.reporting.formatters import json_fmt, markdown_fmt, csv_fmt, pdf

        return {
            "html":     html_fmt.render,
            "json":     json_fmt.render,
            "markdown": markdown_fmt.render,
            "md":       markdown_fmt.render,
            "csv":      csv_fmt.render,
            "pdf":      pdf.render,
        }.get(fmt)

    @staticmethod
    def _build_report_data(
        report: "CorrelatedReport",
        session: "Session",
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session": {
                "id": session.session_id,
                "targets": session.targets,
                "profile": session.profile,
                "started_at": session.started_at,
                "finished_at": session.finished_at,
                "duration_seconds": session.duration_seconds,
            },
            "risk_score": report.risk_score,
            "severity_distribution": report.severity_distribution,
            "attack_chains": report.attack_chains,
            "statistics": report.statistics,
            "findings": [f.to_dict() for f in report.findings],
            "metadata": metadata,
        }
