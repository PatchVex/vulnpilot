"""Exceptions engine — tracks approved SLA breach exceptions.

Input: --exceptions exceptions.csv
Columns: host, plugin_id, port, ticket_ref, approver,
         approved_date, expiry_date, reason

Every open finding is classified as:
  within_sla         — SLA not yet breached
  breached_approved  — breached but valid exception on file
  breached_expired   — exception existed but has expired
  breached_no_exception — breached with no approval ← audit finding
  unknown            — no history data
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

from vulnpilot.sla import SLAStatus

Key = Tuple[str, str, str]  # (host, plugin_id, port)


@dataclass
class ExceptionRecord:
    host: str
    plugin_id: str
    port: str
    ticket_ref: str
    approver: str
    approved_date: Optional[date]
    expiry_date: Optional[date]
    reason: str

    @property
    def key(self) -> Key:
        return (self.host, self.plugin_id, self.port)

    def is_valid(self, as_of: Optional[date] = None) -> bool:
        """True if the exception is approved and not yet expired."""
        check = as_of or date.today()
        if self.expiry_date and self.expiry_date < check:
            return False
        return bool(self.approver and self.ticket_ref)


@dataclass
class FindingGovernance:
    """Complete governance classification for one finding."""
    finding_key: Key
    sla_status: SLAStatus
    exception: Optional[ExceptionRecord]
    governance_status: str   # within_sla / breached_approved /
                             # breached_expired / breached_no_exception / unknown
    audit_finding: bool      # True = auditor will flag this


def _parse_date(val: str) -> Optional[date]:
    val = val.strip()
    if not val:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(val, fmt).date()
        except ValueError:
            continue
    return None


def load_exceptions(path: Path) -> Dict[Key, ExceptionRecord]:
    """Load exceptions CSV. Returns empty dict if file missing or malformed."""
    if not path.exists():
        return {}
    records: Dict[Key, ExceptionRecord] = {}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                # normalise column names to lowercase, strip whitespace
                row = {k.lower().strip(): v.strip() for k, v in row.items()}
                host = row.get("host", "")
                plugin_id = row.get("plugin_id", "")
                port = row.get("port", "")
                if not host:
                    continue
                rec = ExceptionRecord(
                    host=host,
                    plugin_id=plugin_id,
                    port=port,
                    ticket_ref=row.get("ticket_ref", ""),
                    approver=row.get("approver", ""),
                    approved_date=_parse_date(row.get("approved_date", "")),
                    expiry_date=_parse_date(row.get("expiry_date", "")),
                    reason=row.get("reason", ""),
                )
                records[rec.key] = rec
    except Exception:
        return {}
    return records


def classify_finding(
    sla_status: SLAStatus,
    exceptions: Dict[Key, ExceptionRecord],
    as_of: Optional[date] = None,
) -> FindingGovernance:
    """Classify one finding into its governance status."""
    key = sla_status.finding_key
    exc = exceptions.get(key)

    if sla_status.status == "unknown":
        return FindingGovernance(
            finding_key=key, sla_status=sla_status,
            exception=exc, governance_status="unknown",
            audit_finding=False,
        )

    if sla_status.status in ("within", "approaching"):
        return FindingGovernance(
            finding_key=key, sla_status=sla_status,
            exception=exc, governance_status="within_sla",
            audit_finding=False,
        )

    # status == "breached"
    if exc is None:
        return FindingGovernance(
            finding_key=key, sla_status=sla_status,
            exception=None, governance_status="breached_no_exception",
            audit_finding=True,
        )

    if exc.is_valid(as_of):
        return FindingGovernance(
            finding_key=key, sla_status=sla_status,
            exception=exc, governance_status="breached_approved",
            audit_finding=False,
        )

    return FindingGovernance(
        finding_key=key, sla_status=sla_status,
        exception=exc, governance_status="breached_expired",
        audit_finding=True,
    )


def classify_all(
    sla_statuses: list,
    exceptions: Dict[Key, ExceptionRecord],
    as_of: Optional[date] = None,
) -> list:
    """Classify all findings. Returns list aligned with sla_statuses."""
    return [classify_finding(s, exceptions, as_of) for s in sla_statuses]


def governance_summary(govs: list) -> dict:
    """Count findings by governance status."""
    from collections import Counter
    counts = Counter(g.governance_status for g in govs)
    audit_findings = sum(1 for g in govs if g.audit_finding)
    return {
        "within_sla": counts.get("within_sla", 0),
        "breached_approved": counts.get("breached_approved", 0),
        "breached_expired": counts.get("breached_expired", 0),
        "breached_no_exception": counts.get("breached_no_exception", 0),
        "unknown": counts.get("unknown", 0),
        "audit_findings": audit_findings,
    }
