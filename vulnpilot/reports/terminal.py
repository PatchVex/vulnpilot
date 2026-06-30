"""
vulnpilot/reports/terminal.py
Renders prioritized findings to terminal output.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from typing import List
from vulnpilot.parser.nessus import Finding

RESET="\033[0m";BOLD="\033[1m";RED="\033[91m";ORANGE="\033[33m"
YELLOW="\033[93m";CYAN="\033[96m";GREY="\033[90m";WHITE="\033[97m"

def _c(text, colour, use_colour):
    return f"{colour}{text}{RESET}" if use_colour else text

def _label_colour(label, use_colour):
    colours = {"CRITICAL NOW": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": CYAN}
    return _c(label, colours.get(label, WHITE), use_colour)

def render_summary(findings: List[Finding], use_colour: bool = True) -> str:
    total = len(findings)
    risk_counts = Counter(f.risk.upper() for f in findings)
    kev_count = sum(1 for f in findings if f.kev_match)
    high_epss = sum(1 for f in findings if (f.epss_score or 0) >= 0.9)
    unique_hosts = len({f.host for f in findings})
    lines = [
        "", _c("━"*60, BOLD, use_colour),
        _c("  VulnPilot by PatchVex — Vulnerability Prioritization", BOLD, use_colour),
        _c("━"*60, BOLD, use_colour), "",
        f"  Total findings        : {_c(str(total), BOLD, use_colour)}",
        f"  Unique hosts          : {unique_hosts}", "",
        f"  {_c('Critical', RED, use_colour)}              : {risk_counts.get('CRITICAL', 0)}",
        f"  {_c('High', ORANGE, use_colour)}                 : {risk_counts.get('HIGH', 0)}",
        f"  {_c('Medium', YELLOW, use_colour)}               : {risk_counts.get('MEDIUM', 0)}",
        f"  {_c('Low', CYAN, use_colour)}                  : {risk_counts.get('LOW', 0)}", "",
        f"  {_c('KEV matches', RED, use_colour)} (exploited now) : {_c(str(kev_count), BOLD, use_colour)}",
        f"  {_c('EPSS >= 90%', ORANGE, use_colour)} (high risk)    : {high_epss}",
        "", _c("━"*60, BOLD, use_colour),
    ]
    return "\n".join(lines)

def render_findings(findings: List[Finding], limit: int = 20, use_colour: bool = True) -> str:
    shown = findings[:limit]
    lines = ["", _c(f"  TOP {limit} PRIORITIZED FINDINGS", BOLD, use_colour),
             _c("  (KEV + EPSS + CVSS composite score)", GREY, use_colour), ""]
    header = f"  {'#':<5}{'Score':<7}{'Priority':<14}{'Host':<22}{'CVE':<20}{'Finding':<36}"
    lines.append(_c(header, BOLD, use_colour))
    lines.append(_c("  " + "─"*100, GREY, use_colour))
    for i, f in enumerate(shown, start=1):
        cve_display = f.cve_list[0] if f.cve_list else "N/A"
        name_display = f.name[:34] + ".." if len(f.name) > 36 else f.name
        host_display = f.host[:20] + ".." if len(f.host) > 22 else f.host
        kev_flag = _c(" ★KEV", RED, use_colour) if f.kev_match else ""
        row = (f"  {i:<5}{f.priority_score:<7.1f}"
               f"{(f.priority_label or ''):<14}{host_display:<22}"
               f"{cve_display:<20}{name_display}{kev_flag}")
        lines.append(row)
    lines += ["", _c("  ★ KEV = CISA Known Exploited — patch these first, no debate.", RED, use_colour), ""]
    return "\n".join(lines)

def render_top_hosts(findings: List[Finding], top_n: int = 10, use_colour: bool = True) -> str:
    host_scores: dict = defaultdict(float)
    host_kev: dict = defaultdict(int)
    host_critical: dict = defaultdict(int)
    for f in findings:
        host_scores[f.host] += f.priority_score or 0
        if f.kev_match: host_kev[f.host] += 1
        if f.risk.lower() == "critical": host_critical[f.host] += 1
    ranked = sorted(host_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
    lines = ["", _c(f"  TOP {top_n} HOSTS BY AGGREGATE RISK", BOLD, use_colour), ""]
    for i, (host, score) in enumerate(ranked, start=1):
        kev_tag = _c(f" [{host_kev[host]} KEV]", RED, use_colour) if host_kev[host] else ""
        crit_tag = f" [{host_critical[host]} critical]" if host_critical[host] else ""
        lines.append(f"  {i:>2}. {host:<32} score={score:.1f}{kev_tag}{crit_tag}")
    lines.append("")
    return "\n".join(lines)

def render_free_tier_gate(total: int, shown: int, use_colour: bool = True) -> str:
    lines = [
        "", _c("─"*60, GREY, use_colour),
        _c(f"  FREE TIER: showing top {shown} of {total} findings", YELLOW, use_colour),
        _c(f"  {total - shown} findings hidden.", YELLOW, use_colour), "",
        "  Upgrade to VulnPilot Professional to unlock all findings,",
        "  PDF reports, Jira integration, and scheduled scans.", "",
        _c("  https://patchvex.com/pricing", CYAN, use_colour),
        _c("─"*60, GREY, use_colour), "",
    ]
    return "\n".join(lines)
