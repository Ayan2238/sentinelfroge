"""CSV Report Formatter."""
from __future__ import annotations
import csv
import io
from typing import Any


def render(data: dict[str, Any]) -> tuple[str, str]:
    """Return (csv_string, 'csv')."""
    findings = data.get("findings", [])
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "severity", "title", "target", "module",
            "description", "recommendation", "confidence",
            "cve", "tags", "evidence",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "severity":       f.get("severity", ""),
            "title":          f.get("title", ""),
            "target":         f.get("target", ""),
            "module":         f.get("module", ""),
            "description":    f.get("description", ""),
            "recommendation": f.get("recommendation", ""),
            "confidence":     f.get("confidence", 1.0),
            "cve":            "; ".join(f.get("cve", [])),
            "tags":           "; ".join(f.get("tags", [])),
            "evidence":       " | ".join(f.get("evidence", [])),
        })
    return buf.getvalue(), "csv"
