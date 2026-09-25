"""Exceptions engine — tracks approved SLA breach exceptions.

Input: --exceptions exceptions.csv
Columns: host, plugin_id, port, ticket_ref, approver,
         approved_date, expiry_date, reason

host, plugin_id and port may be "*" (any value); host may also be a CIDR
range (e.g. 10.0.0.0/24). An exact match wins over a pattern; otherwise the
most specific matching row applies — between CIDR rows of equal specificity
the narrower network wins, and remaining ties go to the earlier row. A row
that matches everything is rejected. If two rows have the same host,
plugin_id and port, the later row replaces the earlier one (with a warning).

Every open finding is classified as:
  within_sla         — SLA not yet breached
  breached_approved  — breached but valid exception on file
  breached_expired   — exception existed but has expired (or its expiry
                       date could not be read)
  breached_no_exception — breached with no approval ← audit finding
  unknown            — no history data
"""

from __future__ import annotations

import csv
import ipaddress
import logging
from dataclasses import dataclass
from datetime import date, datetime
from functools import cached_property
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

from vulnpilot.sla import SLAStatus

logger = logging.getLogger(__name__)

Key = Tuple[str, str, str]  # (host, plugin_id, port)
WILDCARD = "*"


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
    # A non-blank expiry_date that could not be read (e.g. "31st Dec",
    # "2026-02-30"). Such an exception is never valid: an unreadable end date
    # must not turn a time-limited approval into a permanent one. A blank
    # expiry_date still means "no expiry".
    expiry_unreadable: bool = False

    @property
    def key(self) -> Key:
        return (self.host, self.plugin_id, self.port)

    @property
    def is_pattern(self) -> bool:
        return (WILDCARD in self.key) or ("/" in self.host)

    @cached_property
    def network(self) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """The CIDR host as a network (parsed once). None for other hosts, and
        for an invalid CIDR — such a record never matches. load_exceptions()
        already skips invalid CIDR rows; this covers records built directly."""
        if "/" not in self.host:
            return None
        try:
            return ipaddress.ip_network(self.host, strict=False)
        except ValueError:
            return None

    def specificity(self) -> Tuple[int, int]:
        """Higher is more specific. First by field: exact field 2, CIDR host 1,
        wildcard 0 — so exact > CIDR > wildcard, and a row naming a plugin beats
        a host-wide one. Then, only between CIDR rows with the same field score,
        by prefix length (a narrower network wins). A matching IPv4 and IPv6
        network can never both match one host, so prefixes compare within a family."""
        net = self.network
        host = 1 if net is not None else 0 if self.host == WILDCARD else 2
        fields = host + sum(0 if v == WILDCARD else 2 for v in (self.plugin_id, self.port))
        return (fields, net.prefixlen if net is not None else 0)

    def matches(self, key: Key) -> bool:
        host, plugin_id, port = key
        if self.plugin_id not in (WILDCARD, plugin_id) or self.port not in (WILDCARD, port):
            return False
        if self.host in (WILDCARD, host):
            return True
        if self.network is not None:
            try:
                return ipaddress.ip_address(host) in self.network
            except ValueError:
                return False  # finding host is a hostname, not an IP
        return False

    def is_valid(self, as_of: Optional[date] = None) -> bool:
        """True if the exception is approved and not yet expired."""
        check = as_of or date.today()
        if self.expiry_unreadable:
            return False
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


REQUIRED_COLUMNS = ("host", "plugin_id", "port")


def load_exceptions(path: Path) -> Dict[Key, ExceptionRecord]:
    """Load exceptions CSV. Returns empty dict if the file does not exist.

    Accepts a UTF-8 BOM (as written by Excel). Rows that cannot be read are
    skipped with a warning rather than discarding the whole register. Raises
    ValueError if the file is unreadable or lacks the required columns.
    """
    if not path.exists():
        return {}
    records: Dict[Key, ExceptionRecord] = {}
    record_line: Dict[Key, int] = {}
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            columns = {(c or "").lower().strip() for c in (reader.fieldnames or [])}
            missing = [c for c in REQUIRED_COLUMNS if c not in columns]
            if missing:
                raise ValueError(
                    f"Exceptions file {path} is missing required column(s): "
                    f"{', '.join(missing)}"
                )
            for row in reader:
                line = reader.line_num
                if None in row:  # more fields than the header has columns
                    logger.warning("%s line %d: column count does not match header — "
                                   "row skipped", path, line)
                    continue
                # A short row leaves its trailing columns as None: required ones
                # make the row unusable; optional ones are simply empty.
                missing_required = [c for c in REQUIRED_COLUMNS if any(
                    (k or "").lower().strip() == c and v is None for k, v in row.items())]
                if missing_required:
                    logger.warning("%s line %d: missing required field(s) %s — row skipped",
                                   path, line, ", ".join(missing_required))
                    continue
                # normalise column names to lowercase, strip whitespace
                row = {k.lower().strip(): (v or "").strip() for k, v in row.items()}
                host = row.get("host", "")
                plugin_id = row.get("plugin_id", "")
                port = row.get("port", "")
                if not host:
                    logger.warning("%s line %d: no host — row skipped", path, line)
                    continue
                if "/" in host:
                    try:
                        net = ipaddress.ip_network(host, strict=False)
                    except ValueError:
                        logger.warning("%s line %d: invalid CIDR host %r — row skipped",
                                       path, line, host)
                        continue
                    if net.prefixlen == 0:
                        host = WILDCARD  # 0.0.0.0/0 is "every host"
                if host == WILDCARD and plugin_id == WILDCARD and port == WILDCARD:
                    logger.warning("%s line %d: host, plugin_id and port are all wildcards "
                                   "— a blanket exception is not allowed; row skipped",
                                   path, line)
                    continue
                dates = {}
                for col in ("approved_date", "expiry_date"):
                    raw = row.get(col, "")
                    dates[col] = _parse_date(raw)
                expiry_unreadable = bool(row.get("expiry_date")) and dates["expiry_date"] is None
                if row.get("approved_date") and dates["approved_date"] is None:
                    logger.warning("%s line %d: unrecognised approved_date %r — treated as "
                                   "not set", path, line, row.get("approved_date"))
                if expiry_unreadable:
                    logger.warning("%s line %d: unrecognised expiry_date %r — the exception "
                                   "is treated as expired until the date is corrected "
                                   "(use YYYY-MM-DD)", path, line, row.get("expiry_date"))
                rec = ExceptionRecord(
                    host=host,
                    plugin_id=plugin_id,
                    port=port,
                    ticket_ref=row.get("ticket_ref", ""),
                    approver=row.get("approver", ""),
                    approved_date=dates["approved_date"],
                    expiry_date=dates["expiry_date"],
                    reason=row.get("reason", ""),
                    expiry_unreadable=expiry_unreadable,
                )
                if rec.key in records:
                    # Same host/plugin_id/port twice: the later row wins, as in
                    # v1.1.0 — appended rows are how registers record renewals
                    # and revocations. It also takes the later row's file
                    # position for pattern tie-breaking.
                    logger.warning("%s line %d: same host, plugin_id and port as line %d — "
                                   "line %d replaces line %d", path, line,
                                   record_line[rec.key], line, record_line[rec.key])
                    del records[rec.key]
                records[rec.key] = rec
                record_line[rec.key] = line
    except (OSError, UnicodeDecodeError, csv.Error) as e:
        raise ValueError(f"Could not read exceptions file {path}: {e}") from e
    return records


def _best_pattern_match(key: Key,
                        exceptions: Dict[Key, ExceptionRecord]) -> Optional[ExceptionRecord]:
    """Most specific wildcard/CIDR exception matching `key`; file order breaks ties."""
    best: Optional[ExceptionRecord] = None
    for rec in exceptions.values():
        if rec.is_pattern and rec.matches(key):
            if best is None or rec.specificity() > best.specificity():
                best = rec
    return best


def classify_finding(
    sla_status: SLAStatus,
    exceptions: Dict[Key, ExceptionRecord],
    as_of: Optional[date] = None,
) -> FindingGovernance:
    """Classify one finding into its governance status."""
    key = sla_status.finding_key
    exc = exceptions.get(key) or _best_pattern_match(key, exceptions)

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
