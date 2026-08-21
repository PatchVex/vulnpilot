"""Actionable remediation export — turns governance-classified findings into
ticket-ready records for import into any ticketing system.

Scope (v1.1 MVP): local file export only. No network calls, no credentials,
no direct Jira/ServiceNow/Slack API integration. See README for rationale.

This module deliberately contains NO new business logic. "Actionable" reuses
the exact governance classification already computed by
vulnpilot.exceptions.classify_all() — a finding is exported if and only if
FindingGovernance.audit_finding is True (i.e. governance_status is
"breached_no_exception" or "breached_expired"). That is the same definition
`verify`'s own terminal/JSON output already uses to flag audit findings.
Fixed findings are never candidates: fixed findings are absent from the
current scan and therefore never appear in the `scored`/`governance` lists
this module consumes.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass
from typing import List, Optional

from vulnpilot.exceptions import FindingGovernance
from vulnpilot.sla import SLAStatus

SUPPORTED_FORMATS = ("generic-csv", "json", "jira-csv")
DEFAULT_FORMAT = "generic-csv"


@dataclass
class TicketRecord:
    """One ticket-ready remediation record.

    Every field is sourced directly from Finding, SLAStatus, or
    FindingGovernance — nothing here is invented or estimated.
    """
    summary: str
    priority: Optional[str]          # Finding.priority_label
    score: Optional[float]           # Finding.priority_score
    host: str
    port: str
    plugin_id: str
    cve: str                         # comma-joined CVE list, "" if none
    finding: str                     # Finding.name
    severity: str                    # Finding.risk
    cvss: Optional[float]            # Finding.cvss (best available v3/v2)
    epss: Optional[float]            # Finding.epss_score
    kev: bool
    days_open: Optional[int]
    sla_days: Optional[int]
    sla_status: str                  # SLAStatus.status
    due_in_days: Optional[int]       # sla_days - days_open; None if either is unknown
    governance_status: str           # FindingGovernance.governance_status
    exception_ticket_ref: str
    exception_approver: str
    exception_expiry: str
    description: str                 # Finding.synopsis
    remediation: str                 # Finding.solution


def _due_in_days(sla_status: SLAStatus) -> Optional[int]:
    if sla_status.sla_days is None or sla_status.days_open is None:
        return None
    return sla_status.sla_days - sla_status.days_open


def _summary(finding, priority_label: Optional[str]) -> str:
    label = f"[{priority_label}] " if priority_label else ""
    return f"{label}{finding.name} on {finding.host}"


def build_ticket_records(
    findings: List,
    governance: List[FindingGovernance],
) -> List[TicketRecord]:
    """Build ticket records for findings that require action.

    findings and governance must both derive from the same scored finding
    set (this is how vulnpilot.cli.cmd_verify already computes them) —
    matched by finding_key = (host, plugin_id, port), the same identity
    used throughout history/verify/sla/exceptions.

    Returns records sorted KEV-first, then by descending priority score —
    the same ordering already used for verify's still_open/new sections.
    """
    gov_by_key = {g.finding_key: g for g in governance}

    records: List[TicketRecord] = []
    for f in findings:
        key = (f.host or "", f.plugin_id or "", f.port or "")
        gov = gov_by_key.get(key)
        if gov is None or not gov.audit_finding:
            continue

        sla = gov.sla_status
        exc = gov.exception

        records.append(TicketRecord(
            summary=_summary(f, f.priority_label),
            priority=f.priority_label,
            score=f.priority_score,
            host=f.host or "",
            port=f.port or "",
            plugin_id=f.plugin_id or "",
            cve=", ".join(f.cve_list),
            finding=f.name or "",
            severity=f.risk or "",
            cvss=f.cvss or None,
            epss=f.epss_score,
            kev=bool(f.kev_match),
            days_open=sla.days_open,
            sla_days=sla.sla_days,
            sla_status=sla.status,
            due_in_days=_due_in_days(sla),
            governance_status=gov.governance_status,
            exception_ticket_ref=exc.ticket_ref if exc else "",
            exception_approver=exc.approver if exc else "",
            exception_expiry=exc.expiry_date.isoformat() if exc and exc.expiry_date else "",
            description=f.synopsis or "",
            remediation=f.solution or "",
        ))

    records.sort(key=lambda r: (not r.kev, -(r.score or 0)))
    return records


CSV_FIELDS = [
    "summary", "priority", "score", "host", "port", "plugin_id", "cve",
    "finding", "severity", "cvss", "epss", "kev", "days_open", "sla_days",
    "sla_status", "due_in_days", "governance_status",
    "exception_ticket_ref", "exception_approver", "exception_expiry",
    "description", "remediation",
]


def to_generic_csv(records: List[TicketRecord]) -> str:
    """Render ticket records as generic CSV.

    Column order matches CSV_FIELDS exactly (documented in README). Uses
    csv.writer with default dialect (QUOTE_MINIMAL), which correctly
    escapes commas, quotes, and embedded newlines in any field —
    standard-compliant output any CSV-import tool can read.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for r in records:
        writer.writerow(asdict(r))
    return buf.getvalue()


def to_json(records: List[TicketRecord], scan_file: Optional[str] = None) -> str:
    """Render ticket records as a stable, documented JSON schema."""
    payload = {
        "schema_version": 1,
        "record_count": len(records),
        "scan_file": scan_file,
        "records": [asdict(r) for r in records],
    }
    return json.dumps(payload, indent=2)


# Jira's CSV importer (Project Settings > Import) recognises these column
# names out of the box for a generic "External System Import". This is NOT
# a Jira API integration — no credentials, no network call, no guarantee
# every Jira project configuration accepts every column (e.g. custom fields,
# required fields specific to a project's issue type screen are not
# addressed here). Documented explicitly in README as a starting point,
# not a certified integration.
JIRA_CSV_FIELDS = [
    "Summary", "Issue Type", "Priority", "Description", "Labels",
    "Host", "CVE", "Plugin ID", "CVSS", "EPSS", "KEV", "Days Open",
    "SLA Days", "Due In Days", "Governance Status",
]

_JIRA_PRIORITY_MAP = {
    "CRITICAL NOW": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}


def to_jira_csv(records: List[TicketRecord]) -> str:
    """Render ticket records as a Jira-importable CSV.

    Maps VulnPilot's priority_label onto Jira's default priority scheme
    (Highest/High/Medium/Low) and combines synopsis + remediation guidance
    into a single Description field. Column set intentionally minimal —
    see JIRA_CSV_FIELDS docstring for scope/limitations.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=JIRA_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for r in records:
        description = r.description
        if r.remediation:
            description = f"{description}\n\nRemediation: {r.remediation}" if description else f"Remediation: {r.remediation}"
        labels = "vulnpilot"
        if r.kev:
            labels += " kev"
        writer.writerow({
            "Summary": r.summary,
            "Issue Type": "Bug",
            "Priority": _JIRA_PRIORITY_MAP.get(r.priority or "", "Medium"),
            "Description": description,
            "Labels": labels,
            "Host": r.host,
            "CVE": r.cve,
            "Plugin ID": r.plugin_id,
            "CVSS": r.cvss if r.cvss is not None else "",
            "EPSS": r.epss if r.epss is not None else "",
            "KEV": "Yes" if r.kev else "No",
            "Days Open": r.days_open if r.days_open is not None else "",
            "SLA Days": r.sla_days if r.sla_days is not None else "",
            "Due In Days": r.due_in_days if r.due_in_days is not None else "",
            "Governance Status": r.governance_status,
        })
    return buf.getvalue()


def render(records: List[TicketRecord], fmt: str, scan_file: Optional[str] = None) -> str:
    if fmt == "generic-csv":
        return to_generic_csv(records)
    if fmt == "json":
        return to_json(records, scan_file=scan_file)
    if fmt == "jira-csv":
        return to_jira_csv(records)
    raise ValueError(
        f"Unsupported ticket format '{fmt}'. Supported: {', '.join(SUPPORTED_FORMATS)}"
    )
