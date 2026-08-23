"""Dependency-free, minimal PDF report formatter."""

from __future__ import annotations

from typing import Any


def _pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render(data: dict[str, Any]) -> tuple[bytes, str]:
    """Render a readable single-page PDF using the PDF text primitives."""
    lines = [
        "SentinelForge Security Assessment",
        f"Session: {data['session']['id']}",
        f"Targets: {', '.join(data['session'].get('targets', []))}",
        f"Risk score: {data.get('risk_score', 0):.1f}",
        f"Total findings: {len(data.get('findings', []))}",
        "",
    ]
    for finding in data.get("findings", []):
        lines.extend([
            f"[{finding.get('severity', 'info').upper()}] {finding.get('title', '')}",
            f"Target: {finding.get('target', '')}",
            finding.get("description", ""),
            "",
        ])
    lines = lines[:48]
    commands = ["BT", "/F1 10 Tf", "50 760 Td"]
    for index, line in enumerate(lines):
        if index:
            commands.append("0 -15 Td")
        commands.append(f"({_pdf_text(str(line)[:140])}) Tj")
    commands.append("ET")
    stream = "\n".join(commands).encode("latin-1", errors="replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode())
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(output), "pdf"