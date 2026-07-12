"""Audit evidence pack generation.

v0.3.0 ships SOC 2 (CC7.1) only — one framework done well. The FRAMEWORKS
dict is the extension point for iso27001, dpdp, hipaa in later releases.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from vulnpilot import history

FRAMEWORKS = {
    "soc2": {
        "title": "SOC 2 Trust Services Criteria",
        "control": "CC7.1",
        "control_name": "System Operations — Vulnerability Identification and Monitoring",
        "objective": (
            "The entity uses detection and monitoring procedures to identify "
            "(1) changes to configurations that result in the introduction of "
            "new vulnerabilities, and (2) susceptibilities to newly discovered "
            "vulnerabilities."
        ),
    },
    "iso27001": {
        "title": "ISO/IEC 27001:2022 — Information Security Management",
        "control": "Annex A 8.8",
        "control_name": "Management of Technical Vulnerabilities",
        "objective": (
            "Information about technical vulnerabilities of information systems "
            "in use shall be obtained in a timely fashion. The organisation's "
            "exposure to such vulnerabilities shall be evaluated and appropriate "
            "measures taken to address the associated risk."
        ),
    },
}


def _fmt(v, dash="-"):
    return v if v not in (None, "", "N/A") else dash


def _governance_md_section(gs: dict) -> str:
    """Render a framework-agnostic governance posture section from a summary dict.

    Intentionally contains no framework-specific language so the same block
    can be embedded in SOC 2, ISO 27001, HIPAA, PCI DSS, or any future pack.
    """
    rows = [
        "| Status | Count |",
        "|---|---|",
        f"| Within SLA | {gs.get('within_sla', 0)} |",
        f"| Breached — approved exception | {gs.get('breached_approved', 0)} |",
        f"| Breached — exception expired | {gs.get('breached_expired', 0)} |",
        f"| Breached — no exception on file | {gs.get('breached_no_exception', 0)} |",
    ]
    unknown = gs.get("unknown", 0)
    if unknown:
        rows.append(f"| No history data (first seen) | {unknown} |")
    table = "\n".join(rows)

    audit = gs.get("audit_findings", 0)
    if audit:
        audit_line = (
            f"\n**Audit findings requiring action: {audit}.** "
            "These are SLA breaches with no valid approved exception on file. "
            "Each requires immediate remediation or a formally approved and "
            "documented exception before the next audit cycle."
        )
    else:
        audit_line = (
            "\nNo audit findings. All SLA breaches have valid approved "
            "exceptions, or no findings are currently in breach."
        )

    return (
        "## 4c. SLA compliance and exception register\n\n"
        f"{table}"
        f"{audit_line}\n\n"
    )


def _findings_table(findings: List, limit: int = 25) -> str:
    rows = [
        "| # | Score | Priority | Host | CVE | Finding | KEV |",
        "|---|-------|----------|------|-----|---------|-----|",
    ]
    for i, f in enumerate(findings[:limit], 1):
        rows.append(
            "| {i} | {score} | {prio} | {host} | {cve} | {name} | {kev} |".format(
                i=i,
                score=_fmt(getattr(f, "priority_score", None)),
                prio=_fmt(getattr(f, "priority_label", None)),
                host=_fmt(f.host),
                cve=_fmt(f.cve),
                name=(f.name or "")[:60].replace("|", "/"),
                kev="YES" if getattr(f, "kev_match", False) else "-",
            )
        )
    return "\n".join(rows)


def generate_evidence_pack(
    findings: List,
    framework: str,
    scan_file: Optional[Path] = None,
    output_path: Optional[Path] = None,
    verify_result=None,
    governance_summary: Optional[dict] = None,
) -> Path:
    if framework not in FRAMEWORKS:
        supported = ", ".join(sorted(FRAMEWORKS))
        raise ValueError(
            f"Unsupported framework '{framework}'. Supported: {supported}. "
            "DPDP and HIPAA packs are on the roadmap."
        )

    fw = FRAMEWORKS[framework]
    now = datetime.now(timezone.utc)
    total = len(findings)
    kev_count = sum(1 for f in findings if getattr(f, "kev_match", False))
    critical = sum(1 for f in findings if (f.risk or "").lower() == "critical")
    epss_high = sum(
        1 for f in findings
        if (getattr(f, "epss_score", None) or 0) >= 0.9
    )
    hist_n = history.scan_count()
    hist_since = history.first_scan_date()

    governance_section = (
        _governance_md_section(governance_summary)
        if governance_summary is not None else ""
    )

    verification_section = ""
    if verify_result is not None:
        vs = verify_result.summary
        scope_note = (
            "\n> **Scope note:** {n} host(s) present in the baseline scan were absent "
            "from this scan ({hosts}). Findings on these hosts are excluded from "
            "verified-fixed counts and require scope confirmation.\n".format(
                n=vs["out_of_scope_hosts"],
                hosts=", ".join(verify_result.out_of_scope_hosts[:5]) +
                      ("…" if len(verify_result.out_of_scope_hosts) > 5 else ""))
            if verify_result.out_of_scope_hosts else ""
        )
        fixed_rows = "\n".join(
            "| {h} | {c} | {n} |".format(
                h=d.get("host",""), c=d.get("cve") or "-",
                n=(d.get("name") or "")[:50].replace("|","/"))
            for d in verify_result.fixed[:15]
        ) or "| — | — | No findings verified fixed in this cycle |"
        verification_section = (
            "## 4b. Remediation verification (against baseline scan {base})\n\n"
            "| Status | Count |\n|---|---|\n"
            "| ✓ Verified fixed (absent in current scan, host in scope) | {f} |\n"
            "| ● Still open | {o} |\n"
            "| + New findings | {n} |\n"
            "{scope}"
            "\n**Verified fixed findings:**\n\n"
            "| Host | CVE | Finding |\n|---|---|---|\n{rows}\n\n"
            "Verification methodology: findings are matched between scans by "
            "(host, plugin, port) identity. A finding is reported as verified "
            "fixed only when it is absent from the current scan AND its host "
            "remains within scan scope — hosts missing from the current scan "
            "are never counted as remediated.\n\n"
        ).format(base=verify_result.baseline_date, f=vs["fixed"],
                 o=vs["still_open"], n=vs["new"], scope=scope_note,
                 rows=fixed_rows)

    history_line = (
        f"This organisation has {hist_n} recorded analysis run(s) in its local "
        f"VulnPilot history (since {hist_since})."
        if hist_n and hist_since
        else "This is the first recorded analysis run in the local history."
    )

    md = f"""# Vulnerability Management — Audit Evidence Pack

**Framework:** {fw['title']}
**Control:** {fw['control']} — {fw['control_name']}
**Generated:** {now.strftime('%Y-%m-%d %H:%M UTC')}
**Generated by:** VulnPilot (PatchVex) — local analysis, no data transmitted
**Source scan file:** {_fmt(scan_file.name if scan_file else None, 'provided at runtime')}

---

## 1. Control objective

> {fw['objective']}

This document provides timestamped, reproducible evidence of a documented,
risk-based vulnerability identification and prioritization process operated
against the source scan above.

## 2. Scan summary

| Metric | Value |
|---|---|
| Total findings evaluated | {total} |
| CISA KEV matches (confirmed exploited in the wild) | {kev_count} |
| Scanner-rated Critical | {critical} |
| EPSS >= 90% (high exploitation probability) | {epss_high} |

{history_line}

## 3. Prioritization methodology (documented and deterministic)

Findings are ranked by a composite risk score combining four public,
auditable signals:

| Signal | Weight | Source |
|---|---|---|
| CISA KEV match | 40% | cisa.gov Known Exploited Vulnerabilities catalog |
| FIRST EPSS | 35% | first.org Exploit Prediction Scoring System |
| CVSS base score | 15% | Scan data |
| Scanner severity | 10% | Scan data |

Any KEV-confirmed finding scores a minimum of 75/100 and is treated as an
immediate remediation priority. The methodology is deterministic: the same
inputs always produce the same ranking, satisfying auditor reproducibility
expectations.

## 4. Prioritized findings (top {min(total, 25)})

{_findings_table(findings)}

Full machine-readable results are retained locally by the organisation.

{verification_section}{governance_section}## 5. Control mapping statement

The process evidenced above supports **{fw['control']}** by demonstrating:

1. A repeatable procedure for identifying vulnerabilities from scan data
2. A documented, risk-based prioritization methodology using current
   threat intelligence (KEV / EPSS)
3. Timestamped records of each analysis run (local history database)

## 6. Management review and sign-off

| Role | Name | Signature | Date |
|---|---|---|---|
| Conducted by | | | |
| Reviewed by | | | |

---

*Generated locally by VulnPilot — scan data never leaves the organisation's
environment. https://patchvex.com*
"""

    if output_path is None:
        output_path = Path(f"evidence_{framework}_{now.strftime('%Y%m%d')}.md")
    output_path.write_text(md, encoding="utf-8")
    return output_path
