"""
vulnpilot/reports/html.py

Generates a self-contained HTML report from prioritized findings.
No external dependencies. Single file output. Works offline.

Usage:
    vulnpilot analyze scan.csv --html report.html
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from vulnpilot.parser.nessus import Finding


def _esc(text: str) -> str:
    return html.escape(str(text or ""))


def _risk_colour(risk: str) -> str:
    return {
        "critical": "#f85149",
        "high":     "#d29922",
        "medium":   "#58a6ff",
        "low":      "#3fb950",
    }.get(risk.lower(), "#8b949e")


def _priority_colour(label: str) -> str:
    return {
        "CRITICAL NOW": "#f85149",
        "HIGH":         "#d29922",
        "MEDIUM":       "#58a6ff",
        "LOW":          "#3fb950",
    }.get(label, "#8b949e")


def generate_html_report(
    findings: List[Finding],
    output_path: Path,
    scan_file: str = "scan.csv",
    limit: int = 0,
    is_paid: bool = False,
) -> Path:
    """
    Generate a self-contained HTML report.

    Args:
        findings:    Scored and sorted Finding list
        output_path: Where to write the .html file
        scan_file:   Original CSV filename for display
        limit:       If > 0, show only top N findings
        is_paid:     If True, show all findings

    Returns:
        Path to the generated file
    """
    total = len(findings)
    shown_findings = findings if is_paid else (findings[:limit] if limit else findings)
    shown = len(shown_findings)

    risk_counts  = Counter(f.risk.upper() for f in findings)
    kev_count    = sum(1 for f in findings if f.kev_match)
    high_epss    = sum(1 for f in findings if (f.epss_score or 0) >= 0.9)
    unique_hosts = len({f.host for f in findings})
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Top hosts
    from collections import defaultdict
    host_scores: dict = defaultdict(float)
    host_kev:    dict = defaultdict(int)
    host_crit:   dict = defaultdict(int)
    for f in findings:
        host_scores[f.host] += f.priority_score or 0
        if f.kev_match:
            host_kev[f.host] += 1
        if f.risk.lower() == "critical":
            host_crit[f.host] += 1
    top_hosts = sorted(host_scores.items(), key=lambda x: x[1], reverse=True)[:10]

    # Build findings rows
    rows_html = ""
    for i, f in enumerate(shown_findings, start=1):
        cve       = _esc(f.cve_list[0] if f.cve_list else "N/A")
        name      = _esc(f.name[:80] + "..." if len(f.name) > 80 else f.name)
        host      = _esc(f.host)
        risk      = _esc(f.risk)
        score     = f"{f.priority_score:.1f}"
        label     = _esc(f.priority_label or "")
        epss      = f"{f.epss_score:.3f}" if f.epss_score is not None else "N/A"
        kev_badge = '<span class="kev-badge">★ KEV</span>' if f.kev_match else ""
        lc        = _priority_colour(f.priority_label or "")
        rc        = _risk_colour(f.risk)

        rows_html += f"""
        <tr>
          <td class="num">{i}</td>
          <td><span class="score-pill" style="background:{lc}22;color:{lc}">{score}</span></td>
          <td><span class="label-pill" style="color:{lc}">{label}</span></td>
          <td class="host-cell">{host}</td>
          <td class="cve-cell">{cve}{kev_badge}</td>
          <td><span class="risk-dot" style="background:{rc}"></span> <span style="color:{rc}">{risk}</span></td>
          <td class="epss-cell">{epss}</td>
          <td class="name-cell">{name}</td>
        </tr>"""

    # Top hosts rows
    host_rows = ""
    for rank, (host, score) in enumerate(top_hosts, start=1):
        kev_tag  = f'<span class="kev-badge">★ {host_kev[host]} KEV</span>' if host_kev[host] else ""
        crit_tag = f'<span class="crit-tag">{host_crit[host]} critical</span>' if host_crit[host] else ""
        bar_w    = min(int((score / (top_hosts[0][1] or 1)) * 100), 100)
        host_rows += f"""
        <tr>
          <td class="num">{rank}</td>
          <td class="host-cell">{_esc(host)}</td>
          <td>
            <div class="bar-wrap">
              <div class="bar-fill" style="width:{bar_w}%"></div>
            </div>
          </td>
          <td class="score-val">{score:.1f}</td>
          <td>{kev_tag} {crit_tag}</td>
        </tr>"""

    # Upgrade banner
    upgrade_banner = ""
    if not is_paid and total > shown:
        hidden = total - shown
        upgrade_banner = f"""
        <div class="upgrade-banner">
          <div class="upgrade-inner">
            <div class="upgrade-text">
              <strong>Community Edition</strong> — showing top {shown} of {total} findings.
              <strong>{hidden} findings hidden.</strong>
            </div>
            <div class="upgrade-sub">
              Upgrade to VulnPilot Professional to see all findings, export PDF,
              enable Jira integration, and schedule automated scans.
            </div>
            <a href="https://patchvex.com/pricing" class="upgrade-btn">
              Upgrade to Professional — $149/year →
            </a>
          </div>
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VulnPilot Report — {_esc(scan_file)}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
      --green: #3fb950; --red: #f85149; --orange: #d29922;
      --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      --mono: 'SFMono-Regular', Consolas, monospace;
    }}
    body {{ background: var(--bg); color: var(--text); font-family: var(--font); line-height: 1.5; font-size: 14px; }}
    a {{ color: var(--accent); }}

    /* HEADER */
    .header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 1.5rem 2rem; display: flex; justify-content: space-between; align-items: center; }}
    .header-brand {{ font-size: 1.2rem; font-weight: 700; }}
    .header-brand span {{ color: var(--accent); }}
    .header-meta {{ font-size: 0.8rem; color: var(--muted); text-align: right; }}
    .header-meta div {{ margin-top: 2px; }}

    /* SUMMARY CARDS */
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; padding: 1.5rem 2rem; }}
    .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; }}
    .card-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.4rem; }}
    .card-value {{ font-size: 1.6rem; font-weight: 700; }}
    .card-value.red {{ color: var(--red); }}
    .card-value.orange {{ color: var(--orange); }}
    .card-value.blue {{ color: var(--accent); }}
    .card-value.green {{ color: var(--green); }}

    /* EXECUTIVE SUMMARY */
    .exec-summary {{ margin: 0 2rem 1.5rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem 1.5rem; }}
    .exec-title {{ font-size: 0.85rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.75rem; }}
    .exec-body {{ font-size: 0.9rem; color: var(--muted); line-height: 1.8; }}
    .exec-body strong {{ color: var(--text); }}

    /* SECTION */
    .section {{ padding: 0 2rem 2rem; }}
    .section-title {{ font-size: 1rem; font-weight: 600; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }}

    /* TABLE */
    .table-wrap {{ overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.83rem; }}
    th {{ background: var(--surface); padding: 0.65rem 0.75rem; text-align: left; font-weight: 500; color: var(--muted); border-bottom: 1px solid var(--border); white-space: nowrap; }}
    td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid #21262d; vertical-align: middle; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #1c2128; }}
    .num {{ color: var(--muted); font-family: var(--mono); font-size: 0.78rem; width: 36px; }}
    .host-cell {{ font-family: var(--mono); font-size: 0.8rem; }}
    .cve-cell {{ font-family: var(--mono); font-size: 0.8rem; white-space: nowrap; }}
    .name-cell {{ max-width: 280px; }}
    .epss-cell {{ font-family: var(--mono); font-size: 0.8rem; text-align: right; }}
    .score-val {{ font-family: var(--mono); font-weight: 600; }}

    /* PILLS */
    .score-pill {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-family: var(--mono); font-size: 0.8rem; font-weight: 600; white-space: nowrap; }}
    .label-pill {{ font-size: 0.78rem; font-weight: 600; white-space: nowrap; }}
    .kev-badge {{ display: inline-block; background: #f8514922; color: var(--red); border: 1px solid #f8514944; border-radius: 4px; padding: 0.1rem 0.4rem; font-size: 0.72rem; font-weight: 600; margin-left: 4px; white-space: nowrap; }}
    .crit-tag {{ display: inline-block; background: #f8514922; color: var(--red); border-radius: 4px; padding: 0.1rem 0.4rem; font-size: 0.72rem; margin-left: 4px; }}
    .risk-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; vertical-align: middle; margin-right: 2px; }}

    /* HOST BAR */
    .bar-wrap {{ background: #21262d; border-radius: 4px; height: 6px; width: 120px; overflow: hidden; }}
    .bar-fill {{ background: var(--accent); height: 100%; border-radius: 4px; }}

    /* UPGRADE */
    .upgrade-banner {{ margin: 0 2rem 2rem; border: 1px solid #d2992244; border-radius: 8px; background: #d2992211; padding: 1.25rem 1.5rem; }}
    .upgrade-text {{ font-size: 0.9rem; margin-bottom: 0.5rem; }}
    .upgrade-sub {{ font-size: 0.82rem; color: var(--muted); margin-bottom: 1rem; }}
    .upgrade-btn {{ display: inline-block; background: var(--accent); color: #0d1117; padding: 0.5rem 1.25rem; border-radius: 6px; font-size: 0.85rem; font-weight: 600; text-decoration: none; }}

    /* FOOTER */
    .footer {{ border-top: 1px solid var(--border); padding: 1rem 2rem; text-align: center; font-size: 0.78rem; color: var(--muted); }}
    .footer a {{ color: var(--muted); }}

    @media print {{
      .upgrade-banner {{ display: none; }}
      body {{ background: white; color: black; }}
    }}
  </style>
</head>
<body>

<div class="header">
  <div>
    <div class="header-brand">Patch<span>Vex</span> / VulnPilot</div>
    <div style="font-size:0.8rem;color:var(--muted);margin-top:4px">Vulnerability Prioritization Report</div>
  </div>
  <div class="header-meta">
    <div>Scan file: <strong>{_esc(scan_file)}</strong></div>
    <div>Generated: {generated_at}</div>
    <div>VulnPilot Community Edition</div>
  </div>
</div>

<div class="summary">
  <div class="card">
    <div class="card-label">Total findings</div>
    <div class="card-value">{total:,}</div>
  </div>
  <div class="card">
    <div class="card-label">Unique hosts</div>
    <div class="card-value blue">{unique_hosts}</div>
  </div>
  <div class="card">
    <div class="card-label">Critical</div>
    <div class="card-value red">{risk_counts.get('CRITICAL', 0)}</div>
  </div>
  <div class="card">
    <div class="card-label">High</div>
    <div class="card-value orange">{risk_counts.get('HIGH', 0)}</div>
  </div>
  <div class="card">
    <div class="card-label">KEV matches</div>
    <div class="card-value red">{kev_count}</div>
  </div>
  <div class="card">
    <div class="card-label">EPSS ≥ 90%</div>
    <div class="card-value orange">{high_epss}</div>
  </div>
</div>

<div class="exec-summary">
  <div class="exec-title">Executive Summary</div>
  <div class="exec-body">
    This scan identified <strong>{total:,} vulnerabilities</strong> across <strong>{unique_hosts} hosts</strong>.
    Of these, <strong style="color:var(--red)">{kev_count} findings match the CISA Known Exploited Vulnerabilities catalog</strong> —
    meaning attackers are actively using these vulnerabilities in the wild right now.
    An additional <strong>{high_epss} findings</strong> have an EPSS score above 90%, indicating high exploitation probability in the next 30 days.
    <br><br>
    Findings are prioritized using a composite score combining KEV status (40%), EPSS probability (35%),
    CVSS severity (15%), and scanner risk rating (10%). Address all CRITICAL NOW findings before any others.
    KEV findings should be treated as actively exploited until patched.
  </div>
</div>

{upgrade_banner}

<div class="section">
  <div class="section-title">Prioritized Findings — Top {shown} of {total:,}</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Score</th>
          <th>Priority</th>
          <th>Host</th>
          <th>CVE</th>
          <th>Risk</th>
          <th>EPSS</th>
          <th>Finding</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>
</div>

<div class="section">
  <div class="section-title">Top 10 Hosts by Aggregate Risk</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Host</th>
          <th>Risk distribution</th>
          <th>Score</th>
          <th>Flags</th>
        </tr>
      </thead>
      <tbody>
        {host_rows}
      </tbody>
    </table>
  </div>
</div>

<div class="footer">
  Generated by <a href="https://patchvex.com">VulnPilot by PatchVex</a> —
  Privacy-first vulnerability prioritization. Your scan data never leaves your machine.
  &nbsp;|&nbsp; <a href="https://github.com/PatchVex/vulnpilot">GitHub</a>
  &nbsp;|&nbsp; <a href="https://patchvex.com/pricing">Upgrade to Professional</a>
</div>

</body>
</html>"""

    output_path = Path(output_path)
    output_path.write_text(html_content, encoding="utf-8")
    return output_path
