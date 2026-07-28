"""HTML Report Formatter."""
from __future__ import annotations
from typing import Any

_SEVERITY_COLOUR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#2563eb",
    "none": "#6b7280",
}

_RISK_COLOUR = lambda score: (
    "#dc2626" if score >= 70 else
    "#ea580c" if score >= 40 else
    "#d97706" if score >= 20 else
    "#65a30d"
)


def render(data: dict[str, Any]) -> tuple[str, str]:
    """Return (html_string, 'html')."""
    findings = data.get("findings", [])
    session = data.get("session", {})
    score = data.get("risk_score", 0)
    dist = data.get("severity_distribution", {})
    chains = data.get("attack_chains", [])
    stats = data.get("statistics", {})

    def badge(severity: str) -> str:
        colour = _SEVERITY_COLOUR.get(severity, "#6b7280")
        return (
            f'<span style="background:{colour};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase">'
            f'{severity}</span>'
        )

    def findings_rows() -> str:
        if not findings:
            return "<tr><td colspan='4' style='text-align:center;color:#9ca3af'>No findings</td></tr>"
        rows = []
        for f in findings:
            rows.append(
                f"<tr>"
                f"<td>{badge(f.get('severity','info'))}</td>"
                f"<td style='font-weight:500'>{_esc(f.get('title',''))}</td>"
                f"<td style='color:#6b7280;font-size:13px'>{_esc(f.get('target',''))}</td>"
                f"<td style='font-size:12px;color:#374151'>{_esc(f.get('module',''))}</td>"
                f"</tr>"
            )
        return "\n".join(rows)

    def chains_html() -> str:
        if not chains:
            return "<p style='color:#9ca3af'>No attack chains detected.</p>"
        items = []
        for c in chains:
            col = _SEVERITY_COLOUR.get(c.get("severity", "medium"), "#d97706")
            items.append(
                f'<div style="border-left:4px solid {col};padding:10px 16px;'
                f'background:#f9fafb;border-radius:0 6px 6px 0;margin-bottom:10px">'
                f'<strong>{_esc(c.get("name",""))}</strong><br>'
                f'<span style="color:#6b7280;font-size:13px">{_esc(c.get("description",""))}</span>'
                f'</div>'
            )
        return "\n".join(items)

    def severity_bar() -> str:
        total = sum(dist.values()) or 1
        colours = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#65a30d", "info": "#2563eb"}
        parts = []
        for sev, col in colours.items():
            cnt = dist.get(sev, 0)
            if cnt:
                pct = cnt / total * 100
                parts.append(
                    f'<div title="{sev}: {cnt}" style="width:{pct:.1f}%;background:{col};height:100%"></div>'
                )
        return "".join(parts)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelForge Security Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f3f4f6;color:#111827;line-height:1.6}}
.header{{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);color:#fff;padding:40px 48px}}
.header h1{{font-size:28px;font-weight:700;letter-spacing:-0.5px}}
.header .subtitle{{color:#94a3b8;margin-top:4px;font-size:14px}}
.container{{max-width:1200px;margin:0 auto;padding:32px 24px}}
.card{{background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.08);padding:24px;margin-bottom:24px}}
.card h2{{font-size:16px;font-weight:600;color:#374151;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid #e5e7eb}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px}}
.metric{{background:#f9fafb;border-radius:8px;padding:16px;text-align:center}}
.metric .value{{font-size:36px;font-weight:700}}
.metric .label{{font-size:12px;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th{{background:#f9fafb;padding:10px 12px;text-align:left;font-weight:600;color:#374151;border-bottom:2px solid #e5e7eb}}
td{{padding:10px 12px;border-bottom:1px solid #f3f4f6;vertical-align:top}}
tr:hover td{{background:#fafafa}}
.bar-container{{height:16px;background:#e5e7eb;border-radius:8px;overflow:hidden;display:flex;margin-top:8px}}
.footer{{text-align:center;color:#9ca3af;font-size:12px;margin-top:32px;padding-bottom:32px}}
.tag{{display:inline-block;background:#e0e7ff;color:#3730a3;font-size:11px;padding:1px 6px;border-radius:4px;margin:1px}}
</style>
</head>
<body>
<div class="header">
  <div style="display:flex;align-items:center;gap:12px">
    <span style="font-size:32px">🛡️</span>
    <div>
      <h1>SentinelForge Security Assessment Report</h1>
      <div class="subtitle">
        Generated: {data.get('generated_at','')[:19].replace('T',' ')} UTC &nbsp;·&nbsp;
        Session: {session.get('id','')[:8]} &nbsp;·&nbsp;
        Profile: {session.get('profile','normal').title()} &nbsp;·&nbsp;
        Target(s): {', '.join(session.get('targets',[]))}
      </div>
    </div>
  </div>
</div>
<div class="container">

  <!-- Risk Score + Distribution -->
  <div class="card">
    <h2>Executive Summary</h2>
    <div class="grid">
      <div class="metric">
        <div class="value" style="color:{_RISK_COLOUR(score)}">{score:.0f}</div>
        <div class="label">Risk Score</div>
      </div>
      <div class="metric">
        <div class="value" style="color:#dc2626">{dist.get('critical',0)}</div>
        <div class="label">Critical</div>
      </div>
      <div class="metric">
        <div class="value" style="color:#ea580c">{dist.get('high',0)}</div>
        <div class="label">High</div>
      </div>
      <div class="metric">
        <div class="value" style="color:#d97706">{dist.get('medium',0)}</div>
        <div class="label">Medium</div>
      </div>
      <div class="metric">
        <div class="value" style="color:#65a30d">{dist.get('low',0)}</div>
        <div class="label">Low</div>
      </div>
      <div class="metric">
        <div class="value" style="color:#2563eb">{dist.get('info',0)}</div>
        <div class="label">Info</div>
      </div>
      <div class="metric">
        <div class="value">{stats.get('total',0)}</div>
        <div class="label">Total Findings</div>
      </div>
      <div class="metric">
        <div class="value">{len(chains)}</div>
        <div class="label">Attack Chains</div>
      </div>
    </div>
    <div class="bar-container" style="margin-top:20px">{severity_bar()}</div>
  </div>

  <!-- Attack Chains -->
  {'<div class="card"><h2>⛓ Attack Chains Detected</h2>' + chains_html() + '</div>' if chains else ''}

  <!-- Findings Table -->
  <div class="card">
    <h2>Findings ({len(findings)})</h2>
    <table>
      <thead>
        <tr>
          <th style="width:100px">Severity</th>
          <th>Title</th>
          <th style="width:200px">Target</th>
          <th style="width:150px">Module</th>
        </tr>
      </thead>
      <tbody>{findings_rows()}</tbody>
    </table>
  </div>

  <!-- Finding Details -->
  {"".join(_finding_detail(f, badge) for f in findings) if findings else ""}

  <!-- Session Info -->
  <div class="card">
    <h2>Scan Information</h2>
    <table>
      <tr><td style="color:#6b7280;width:160px">Session ID</td><td>{session.get('id','')}</td></tr>
      <tr><td style="color:#6b7280">Profile</td><td>{session.get('profile','')}</td></tr>
      <tr><td style="color:#6b7280">Target(s)</td><td>{', '.join(session.get('targets',[]))}</td></tr>
      <tr><td style="color:#6b7280">Started</td><td>{(session.get('started_at') or '')[:19]}</td></tr>
      <tr><td style="color:#6b7280">Finished</td><td>{(session.get('finished_at') or '')[:19]}</td></tr>
      <tr><td style="color:#6b7280">Duration</td>
          <td>{f"{session.get('duration_seconds',0):.1f}s" if session.get('duration_seconds') else 'N/A'}</td></tr>
      <tr><td style="color:#6b7280">Modules</td><td>{', '.join(stats.get('modules',[]))}</td></tr>
    </table>
  </div>

  <div class="footer">
    SentinelForge v2.0 · Authorised security assessment only ·
    Generated {data.get('generated_at','')[:19].replace('T',' ')} UTC
  </div>
</div>
</body>
</html>"""
    return html, "html"


def _finding_detail(f: dict[str, Any], badge_fn) -> str:
    evidence = "".join(
        f"<li style='font-family:monospace;font-size:12px;color:#374151'>{_esc(e)}</li>"
        for e in f.get("evidence", [])
    )
    refs = "".join(
        f'<li><a href="{_esc(r)}" style="color:#2563eb;font-size:12px">{_esc(r)}</a></li>'
        for r in f.get("references", [])
    )
    return f"""
<div class="card" style="border-left:4px solid {_SEVERITY_COLOUR.get(f.get('severity','info'),'#6b7280')}">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
    {badge_fn(f.get('severity','info'))}
    <strong style="font-size:15px">{_esc(f.get('title',''))}</strong>
    <span style="color:#9ca3af;font-size:12px;margin-left:auto">{_esc(f.get('module',''))}</span>
  </div>
  <p style="color:#374151;font-size:14px;margin-bottom:12px">{_esc(f.get('description',''))}</p>
  {"<p style='font-weight:600;font-size:13px;margin-bottom:4px'>Evidence</p><ul style='padding-left:20px;margin-bottom:12px'>" + evidence + "</ul>" if evidence else ""}
  {"<p style='font-weight:600;font-size:13px;margin-bottom:4px;color:#059669'>Recommendation</p><p style='font-size:14px;color:#065f46;background:#ecfdf5;padding:10px;border-radius:6px'>" + _esc(f.get('recommendation','')) + "</p>" if f.get('recommendation') else ""}
  {"<p style='font-weight:600;font-size:13px;margin-top:12px;margin-bottom:4px'>References</p><ul style='padding-left:20px'>" + refs + "</ul>" if refs else ""}
</div>"""


def _esc(s: Any) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
