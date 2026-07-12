"""Remediation verification — diff a new scan against recorded history.

Closes the loop free tools leave open: not just "here's what's broken"
but "here's proof it was fixed."
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from vulnpilot import history


Key = Tuple[str, str, str]  # (host, plugin_id, port)


def _key_from_dict(d: dict) -> Key:
    return (d.get("host", ""), d.get("plugin_id", ""), d.get("port", ""))


def _key_from_finding(f) -> Key:
    return (f.host or "", f.plugin_id or "", f.port or "")


@dataclass
class VerifyResult:
    baseline_date: str
    fixed: List[dict] = field(default_factory=list)        # in old, not in new
    still_open: List[dict] = field(default_factory=list)   # in both (+days_open)
    new: List[dict] = field(default_factory=list)          # in new only
    out_of_scope_hosts: List[str] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        return {
            "fixed": len(self.fixed),
            "still_open": len(self.still_open),
            "new": len(self.new),
            "out_of_scope_hosts": len(self.out_of_scope_hosts),
        }


def _load_history_rows() -> List[dict]:
    try:
        conn = sqlite3.connect(history.DB_PATH)
        rows = conn.execute(
            "SELECT timestamp_utc, findings_json FROM scan_history ORDER BY timestamp_utc"
        ).fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    return [{"timestamp": r[0], "findings": json.loads(r[1] or "[]")} for r in rows]


def _first_seen(key: Key, rows: List[dict]) -> Optional[str]:
    for row in rows:  # rows are chronological
        for d in row["findings"]:
            if _key_from_dict(d) == key:
                return row["timestamp"]
    return None


def verify_scan(new_findings: List) -> VerifyResult:
    """Diff new (scored) findings against the most recent recorded scan."""
    rows = _load_history_rows()
    if not rows:
        raise RuntimeError(
            "No scan history found. Run 'vulnpilot analyze <scan.csv>' at least "
            "once before using verify."
        )

    baseline = rows[-1]
    old_by_key: Dict[Key, dict] = {
        _key_from_dict(d): d for d in baseline["findings"]
    }
    new_by_key: Dict[Key, dict] = {}
    for f in new_findings:
        new_by_key[_key_from_finding(f)] = {
            "plugin_id": f.plugin_id, "cve": f.cve, "host": f.host,
            "port": f.port, "name": f.name, "risk": f.risk,
            "score": getattr(f, "priority_score", None),
            "kev": bool(getattr(f, "kev_match", False)),
            "priority": getattr(f, "priority_label", None),
        }

    new_hosts = {k[0] for k in new_by_key}
    old_hosts = {k[0] for k in old_by_key}
    missing_hosts = sorted(old_hosts - new_hosts)

    result = VerifyResult(baseline_date=baseline["timestamp"][:10],
                          out_of_scope_hosts=missing_hosts)
    now = datetime.now(timezone.utc)

    for key, d in old_by_key.items():
        if key[0] in missing_hosts:
            continue  # host absent from new scan — cannot claim fixed
        if key in new_by_key:
            first = _first_seen(key, rows)
            days = None
            if first:
                try:
                    days = (now - datetime.fromisoformat(first)).days
                except ValueError:
                    days = None
            entry = dict(new_by_key[key])
            entry["days_open"] = days
            result.still_open.append(entry)
        else:
            result.fixed.append(d)

    for key, d in new_by_key.items():
        if key not in old_by_key:
            result.new.append(d)

    # KEV first, then score, for both action lists
    for lst in (result.still_open, result.new):
        lst.sort(key=lambda d: (not d.get("kev"), -(d.get("score") or 0)))

    return result


def _render_governance_section(
    sla_statuses: List,
    use_colour: bool,
) -> List[str]:
    """Render SLA compliance summary lines.

    Designed to grow: Task 3 will add a `governance` parameter for exception
    and audit-finding data without requiring a rename.
    """
    GREEN  = "\033[92m" if use_colour else ""
    YELLOW = "\033[93m" if use_colour else ""
    RED    = "\033[91m" if use_colour else ""
    RESET  = "\033[0m"  if use_colour else ""
    BOLD   = "\033[1m"  if use_colour else ""

    from collections import Counter
    counts = Counter(s.status for s in sla_statuses)
    breached   = counts.get("breached",    0)
    approaching = counts.get("approaching", 0)
    within     = counts.get("within",      0)
    unknown    = counts.get("unknown",     0)

    lines = [
        "",
        "━" * 60,
        f"  {BOLD}SLA Compliance{RESET}",
        "━" * 60,
        f"  {GREEN}✓ Within SLA{RESET}            : {within}",
        f"  {YELLOW}⚠ Approaching (>80%){RESET}   : {approaching}",
        f"  {RED}✗ Breached{RESET}              : {breached}"
        + (f"   {RED}{BOLD}← REQUIRES ACTION{RESET}" if breached else ""),
    ]
    if unknown:
        lines.append(f"  — Unknown (no history)  : {unknown}")

    breached_items = [s for s in sla_statuses if s.status == "breached"]
    if breached_items:
        lines.append(f"\n  {BOLD}Breach detail:{RESET}")
        for s in breached_items:
            host = s.finding_key[0] or "-"
            lines.append(
                f"   {RED}{host:<20}{RESET}"
                f"{s.risk:<10}"
                f"{s.days_open}d open   SLA: {s.sla_days}d"
            )

    return lines


def _render_governance_classified(governance: List, use_colour: bool) -> List[str]:
    """Render governance summary for a List[FindingGovernance] (exceptions-aware).

    Called when cli.py has classified findings via exceptions.classify_all().
    _render_governance_section() (SLAStatus fallback) is left unchanged.
    """
    GREEN  = "\033[92m" if use_colour else ""
    YELLOW = "\033[93m" if use_colour else ""
    RED    = "\033[91m" if use_colour else ""
    RESET  = "\033[0m"  if use_colour else ""
    BOLD   = "\033[1m"  if use_colour else ""

    from collections import Counter
    counts = Counter(g.governance_status for g in governance)
    within         = counts.get("within_sla",            0)
    approaching    = counts.get("approaching",            0)  # SLAStatus maps here before classify
    approved       = counts.get("breached_approved",      0)
    expired        = counts.get("breached_expired",       0)
    no_exc         = counts.get("breached_no_exception",  0)
    unknown        = counts.get("unknown",                0)
    audit_count    = sum(1 for g in governance if g.audit_finding)

    lines = [
        "",
        "━" * 60,
        f"  {BOLD}Governance Summary{RESET}",
        "━" * 60,
        f"  {GREEN}✓ Within SLA{RESET}                     : {within}",
    ]
    if approaching:
        lines.append(f"  {YELLOW}⚠ Approaching SLA (>80%){RESET}        : {approaching}")
    if approved:
        lines.append(f"  {GREEN}✓ Breached — approved exception{RESET} : {approved}")
    if expired:
        lines.append(
            f"  {RED}✗ Breached — exception expired{RESET}  : {expired}"
            f"   {RED}{BOLD}← AUDIT FINDING{RESET}"
        )
    if no_exc:
        lines.append(
            f"  {RED}✗ Breached — no exception{RESET}       : {no_exc}"
            f"   {RED}{BOLD}← AUDIT FINDING{RESET}"
        )
    if unknown:
        lines.append(f"  — Unknown (no history)           : {unknown}")
    if audit_count:
        lines.append(
            f"\n  {RED}{BOLD}Audit findings requiring action  : {audit_count}{RESET}"
        )

    breached = [g for g in governance if g.audit_finding or
                g.governance_status == "breached_approved"]
    if breached:
        lines.append(f"\n  {BOLD}Breach detail:{RESET}")
        for g in breached:
            s = g.sla_status
            host = s.finding_key[0] or "-"
            if g.governance_status == "breached_approved" and g.exception:
                exc_note = (f"  {GREEN}{g.exception.ticket_ref} ✓ approved"
                            f" (exp {g.exception.expiry_date}){RESET}")
            elif g.governance_status == "breached_expired" and g.exception:
                exc_note = f"  {RED}{g.exception.ticket_ref} ✗ expired{RESET}"
            else:
                exc_note = f"  {RED}no exception on file{RESET}"
            lines.append(
                f"   {RED}{host:<20}{RESET}"
                f"{s.risk:<10}"
                f"{s.days_open}d open   SLA: {s.sla_days}d"
                f"{exc_note}"
            )

    return lines


def render_verify(result: VerifyResult, sla_statuses: Optional[List] = None,
                  governance: Optional[List] = None,
                  use_colour: bool = True) -> str:
    GREEN, RED, YELLOW, RESET, BOLD = "\033[92m", "\033[91m", "\033[93m", "\033[0m", "\033[1m"
    if not use_colour:
        GREEN = RED = YELLOW = RESET = BOLD = ""

    s = result.summary
    in_scope_baseline = s["fixed"] + s["still_open"]
    pct = round(100 * s["fixed"] / in_scope_baseline) if in_scope_baseline else 0
    bar = "█" * (pct // 10) + "░" * (10 - pct // 10)
    lines = [
        "",
        "━" * 60,
        f"  {BOLD}VulnPilot — Remediation Verification{RESET}",
        f"  Baseline scan: {result.baseline_date}",
        "━" * 60,
        f"  Baseline findings (in scope) : {in_scope_baseline}",
        f"  {GREEN}✓ Verified fixed{RESET}             : {s['fixed']} ({pct}%)",
        f"  {YELLOW}● Still open{RESET}                 : {s['still_open']}",
        f"  {RED}+ New findings{RESET}               : {s['new']}",
        f"  Remediation progress         : {GREEN}{bar}{RESET} {pct}%",
    ]
    kev_fixed = sum(1 for d in result.fixed if d.get("kev"))
    kev_open = sum(1 for d in result.still_open if d.get("kev"))
    kev_base = kev_fixed + kev_open
    if kev_base:
        lines.append(f"  {BOLD}KEV remediation{RESET}              : "
                     f"{kev_fixed} / {kev_base} verified fixed")
        if kev_open:
            lines.append(f"  {RED}⚠ {kev_open} KEV finding(s) remain open — "
                         f"highest audit and exploitation risk{RESET}")
    if result.out_of_scope_hosts:
        lines.append(
            f"  ⚠ Hosts not in new scan: {s['out_of_scope_hosts']} "
            f"({', '.join(result.out_of_scope_hosts[:5])}"
            f"{'…' if len(result.out_of_scope_hosts) > 5 else ''}) — "
            "findings on these hosts are NOT counted as fixed"
        )
    lines.append("━" * 60)

    def block(title, items, colour, show_days=False):
        if not items:
            return
        lines.append(f"\n  {BOLD}{title}{RESET}")
        for d in items[:15]:
            kev = f" {RED}★KEV{RESET}" if d.get("kev") else ""
            days = (f"  [{d['days_open']}d open]"
                    if show_days and d.get("days_open") is not None else "")
            lines.append(
                f"   {colour}{d.get('host',''):<18}{RESET}"
                f"{(d.get('cve') or '-'):<18}"
                f"{(d.get('name') or '')[:44]}{kev}{days}"
            )
        if len(items) > 15:
            lines.append(f"   … and {len(items) - 15} more")

    block("✓ VERIFIED FIXED", result.fixed, GREEN)
    block("● STILL OPEN", result.still_open, YELLOW, show_days=True)
    block("+ NEW FINDINGS", result.new, RED)

    if governance is not None:
        lines += _render_governance_classified(governance, use_colour)
    elif sla_statuses is not None:
        lines += _render_governance_section(sla_statuses, use_colour)

    lines.append("")
    return "\n".join(lines)
