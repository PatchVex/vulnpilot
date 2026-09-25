"""Remediation verification — diff a new scan against recorded history.

Closes the loop free tools leave open: not just "here's what's broken"
but "here's proof it was fixed."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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
    # Set only when the baseline run was imported with --scan-date: the date
    # the scanner ran. baseline_date is always the date VulnPilot recorded it.
    baseline_scan_date: Optional[str] = None
    # History row id of the baseline, and the SHA-256 of the scan file it was
    # recorded from (None for runs recorded without a scan file hash).
    baseline_run_id: Optional[int] = None
    baseline_file_hash: Optional[str] = None

    @property
    def summary(self) -> dict:
        return {
            "fixed": len(self.fixed),
            "still_open": len(self.still_open),
            "new": len(self.new),
            "out_of_scope_hosts": len(self.out_of_scope_hosts),
        }


def verify_scan(new_findings: List, exclude_run: Optional[int] = None,
                rows: Optional[List[dict]] = None) -> VerifyResult:
    """Diff new (scored) findings against the most recently recorded run
    (highest history id), whatever its stated scan date.

    `exclude_run` is a history row id (as returned by history.record_scan) that
    must not be used as the baseline — e.g. the row `analyze` just recorded for
    this same scan. Only that exact row is excluded.

    `rows` is history as returned by history.load_rows(); it is loaded here if
    not given (callers that also compute SLA pass it to both to read history once).

    Raises ValueError if `exclude_run` is not a recorded run, and RuntimeError
    if no baseline is available.
    """
    if rows is None:
        rows = history.load_rows()
    if not rows:
        raise RuntimeError(
            "No scan history found. Run 'vulnpilot analyze <scan.csv>"
            f"{history.command_hint()}' at least once before using verify."
        )

    candidates = rows
    if exclude_run is not None:
        if not any(r["id"] == exclude_run for r in rows):
            raise ValueError(f"--exclude-run {exclude_run}: no recorded history run "
                             "with that ID.")
        candidates = [r for r in rows if r["id"] != exclude_run]
        if not candidates:
            raise RuntimeError(
                f"No baseline available: history run {exclude_run} is the only "
                "recorded scan and it is excluded. Verify needs an earlier scan "
                "to compare against."
            )
    baseline = candidates[-1]
    first_seen = history.first_seen_map(rows)
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
                          baseline_scan_date=baseline.get("scan_date"),
                          baseline_run_id=baseline.get("id"),
                          baseline_file_hash=baseline.get("scan_file_hash"),
                          out_of_scope_hosts=missing_hosts)
    now = datetime.now(timezone.utc)

    for key, d in old_by_key.items():
        if key[0] in missing_hosts:
            continue  # host absent from new scan — cannot claim fixed
        if key in new_by_key:
            first = first_seen.get(key)
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


def self_comparison_warning(result: VerifyResult, scan_file: Path) -> Optional[str]:
    """Warning text when the baseline was recorded from this same scan file
    (identical SHA-256), i.e. verify is comparing the scan with itself; None
    otherwise. Never changes the baseline — the caller only reports it. Runs
    recorded without a hash never match."""
    if not result.baseline_file_hash:
        return None
    try:
        current = history.file_sha256(scan_file)
    except OSError:
        return None
    if current != result.baseline_file_hash:
        return None
    run = result.baseline_run_id
    return (
        f"WARNING: the baseline (history run {run}) was recorded from this same scan "
        "file, so this result compares the scan with itself and cannot show anything "
        "as fixed.\n  Review the run history before relying on it: "
        f"--exclude-run {run} skips only run {run}, and an earlier recording of the "
        "same scan (for example by 'analyze') may then become the baseline."
    )


def _finding_label(key: Key, findings_by_key: Dict[Key, object]) -> str:
    """'port N  CVE  name' for a breach-detail row: enough to tell apart two
    breaches on the same host with the same severity."""
    f = findings_by_key.get(key)
    port = key[2] or "-"
    if f is None:
        return f"port {port}"
    cves = getattr(f, "cve_list", None) or []
    cve = cves[0] if cves else "-"
    name = getattr(f, "name", "") or ""
    if len(name) > 50:
        name = name[:49] + "…"
    return f"port {port:<6}{cve:<18}{name}"


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


def _render_governance_classified(governance: List, use_colour: bool,
                                  findings: Optional[List] = None) -> List[str]:
    """Render governance summary for a List[FindingGovernance] (exceptions-aware).

    Called when cli.py has classified findings via exceptions.classify_all().
    `findings` are the scored findings the governance list was built from; each
    breach row is followed by its port, CVE and name from them.
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
    findings_by_key = {_key_from_finding(f): f for f in (findings or [])}
    if breached:
        lines.append(f"\n  {BOLD}Breach detail:{RESET}")
        for g in breached:
            s = g.sla_status
            host = s.finding_key[0] or "-"
            if g.governance_status == "breached_approved" and g.exception:
                exc_note = (f"  {GREEN}{g.exception.ticket_ref} ✓ approved"
                            f" (exp {g.exception.expiry_date}){RESET}")
            elif g.governance_status == "breached_expired" and g.exception:
                why = (" (unreadable expiry date)"
                       if getattr(g.exception, "expiry_unreadable", False) else "")
                exc_note = f"  {RED}{g.exception.ticket_ref} ✗ expired{why}{RESET}"
            else:
                exc_note = f"  {RED}no exception on file{RESET}"
            lines.append(
                f"   {RED}{host:<20}{RESET}"
                f"{s.risk:<10}"
                f"{s.days_open}d open   SLA: {s.sla_days}d"
                f"{exc_note}"
            )
            lines.append(f"      {_finding_label(s.finding_key, findings_by_key)}")

    return lines


def render_verify(result: VerifyResult, sla_statuses: Optional[List] = None,
                  governance: Optional[List] = None,
                  use_colour: bool = True,
                  findings: Optional[List] = None) -> str:
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
        f"  Baseline scan: {result.baseline_date}"
        + (f" (imported; scan date {result.baseline_scan_date})"
           if result.baseline_scan_date else ""),
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
        lines += _render_governance_classified(governance, use_colour, findings)
    elif sla_statuses is not None:
        lines += _render_governance_section(sla_statuses, use_colour)

    lines.append("")
    return "\n".join(lines)
