"""Markdown Report Formatter."""
from __future__ import annotations
from typing import Any

_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}


def render(data: dict[str, Any]) -> tuple[str, str]:
    """Return (markdown_string, 'md')."""
    session = data.get("session", {})
    findings = data.get("findings", [])
    dist = data.get("severity_distribution", {})
    chains = data.get("attack_chains", [])
    score = data.get("risk_score", 0)
    stats = data.get("statistics", {})

    lines: list[str] = []

    lines.append("# 🛡️ SentinelForge Security Assessment Report")
    lines.append("")
    lines.append(f"**Generated:** {data.get('generated_at','')[:19].replace('T',' ')} UTC  ")
    lines.append(f"**Session:** `{session.get('id','')[:8]}`  ")
    lines.append(f"**Target(s):** {', '.join(session.get('targets',[]))}  ")
    lines.append(f"**Profile:** {session.get('profile','normal').title()}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| **Overall Risk Score** | **{score:.0f} / 100** |")
    lines.append(f"| 🔴 Critical | {dist.get('critical', 0)} |")
    lines.append(f"| 🟠 High | {dist.get('high', 0)} |")
    lines.append(f"| 🟡 Medium | {dist.get('medium', 0)} |")
    lines.append(f"| 🟢 Low | {dist.get('low', 0)} |")
    lines.append(f"| 🔵 Info | {dist.get('info', 0)} |")
    lines.append(f"| **Total Findings** | **{stats.get('total', 0)}** |")
    lines.append(f"| Attack Chains | {len(chains)} |")
    lines.append("")

    # Attack chains
    if chains:
        lines.append("## ⛓ Attack Chains")
        lines.append("")
        for chain in chains:
            sev_emoji = _EMOJI.get(chain.get("severity", "medium"), "⚠️")
            lines.append(f"### {sev_emoji} {chain.get('name', '')}")
            lines.append(f"{chain.get('description', '')}")
            lines.append("")
            if chain.get("steps"):
                lines.append("**Steps:**")
                for step in chain["steps"]:
                    lines.append(f"- {step}")
            lines.append("")

    # Findings
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings._")
    else:
        lines.append("| Severity | Title | Target | Module |")
        lines.append("|----------|-------|--------|--------|")
        for f in findings:
            sev = f.get("severity", "info")
            emoji = _EMOJI.get(sev, "⚪")
            lines.append(
                f"| {emoji} {sev.title()} "
                f"| {f.get('title', '')} "
                f"| `{f.get('target', '')}` "
                f"| {f.get('module', '')} |"
            )
        lines.append("")

        # Detail sections
        lines.append("## Finding Details")
        lines.append("")
        for f in findings:
            sev = f.get("severity", "info")
            emoji = _EMOJI.get(sev, "⚪")
            lines.append(f"### {emoji} {f.get('title', '')}")
            lines.append("")
            lines.append(f"**Severity:** {sev.title()}  ")
            lines.append(f"**Target:** `{f.get('target', '')}`  ")
            lines.append(f"**Module:** {f.get('module', '')}  ")
            lines.append(f"**Confidence:** {f.get('confidence', 1.0):.0%}")
            lines.append("")
            if f.get("description"):
                lines.append(f.get("description", ""))
                lines.append("")
            if f.get("evidence"):
                lines.append("**Evidence:**")
                for ev in f["evidence"]:
                    lines.append(f"```\n{ev}\n```")
            if f.get("recommendation"):
                lines.append(f"> 💡 **Recommendation:** {f['recommendation']}")
                lines.append("")
            if f.get("references"):
                lines.append("**References:**")
                for ref in f["references"]:
                    lines.append(f"- {ref}")
                lines.append("")
            lines.append("---")
            lines.append("")

    # Scan info
    lines.append("## Scan Information")
    lines.append("")
    lines.append(f"- **Session ID:** `{session.get('id', '')}`")
    lines.append(f"- **Profile:** {session.get('profile', '')}")
    lines.append(f"- **Started:** {(session.get('started_at') or '')[:19]}")
    lines.append(f"- **Finished:** {(session.get('finished_at') or '')[:19]}")
    dur = session.get("duration_seconds")
    lines.append(f"- **Duration:** {f'{dur:.1f}s' if dur else 'N/A'}")
    lines.append(f"- **Modules Run:** {', '.join(stats.get('modules', []))}")
    lines.append("")
    lines.append("---")
    lines.append("_SentinelForge v2.0 — For authorised security assessments only._")

    return "\n".join(lines), "md"
