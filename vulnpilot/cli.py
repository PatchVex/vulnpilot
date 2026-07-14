#!/usr/bin/env python3
"""
VulnPilot CLI by PatchVex
Usage:
    vulnpilot analyze scan.csv
    vulnpilot analyze scan.csv --html report.html
    vulnpilot analyze scan.csv --all
    vulnpilot update-feeds
    vulnpilot --version
"""
from __future__ import annotations
import argparse
import logging
import sys
from pathlib import Path

from vulnpilot import __version__
from vulnpilot.parser import parse_nessus_csv
from vulnpilot.enrich import enrich, update_feeds
from vulnpilot.scoring import score_all
from vulnpilot.reports import (
    render_summary, render_findings, render_top_hosts,
    render_free_tier_gate, generate_html_report
)

FREE_TIER_LIMIT = 20


def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        findings = parse_nessus_csv(Path(args.csv))
    except FileNotFoundError as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1

    if not findings:
        print("\n  No actionable findings in this CSV.")
        return 0

    enrich(findings,
           kev_path=Path(args.kev) if args.kev else None,
           epss_path=Path(args.epss) if args.epss else None)

    scored = score_all(findings)

    from vulnpilot import history as _history
    _history.record_scan(scored, scan_file=Path(args.csv))

    if getattr(args, "evidence", None):
        from vulnpilot.evidence import generate_evidence_pack
        _out = generate_evidence_pack(
            findings=scored,
            framework=args.evidence,
            scan_file=Path(args.csv),
            output_path=Path(args.evidence_out) if getattr(args, "evidence_out", None) else None,
        )
        print(f"\n  Evidence pack written: {_out}")
    is_paid = args.all or bool(args.license)
    limit   = len(scored) if is_paid else FREE_TIER_LIMIT

    # Terminal output
    use_colour = sys.stdout.isatty() and not args.no_colour
    print(render_summary(scored, use_colour=use_colour))
    print(render_findings(scored, limit=limit, use_colour=use_colour))
    print(render_top_hosts(scored, top_n=args.top_hosts, use_colour=use_colour))
    if not is_paid and len(scored) > FREE_TIER_LIMIT:
        print(render_free_tier_gate(len(scored), FREE_TIER_LIMIT, use_colour=use_colour))

    # HTML report
    if args.html:
        out = generate_html_report(
            findings=scored,
            output_path=Path(args.html),
            scan_file=Path(args.csv).name,
            limit=FREE_TIER_LIMIT,
            is_paid=is_paid,
        )
        print(f"\n  HTML report saved: {out}")

    return 0


def cmd_update_feeds(args: argparse.Namespace) -> int:
    try:
        update_feeds(cache_dir=Path(args.cache) if args.cache else None)
    except Exception as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnpilot",
        description="VulnPilot by PatchVex — Local-first vulnerability governance. "
                    "Your scanner finds them. VulnPilot proves you managed them.",
        epilog="examples:\n"
               "  vulnpilot update-feeds\n"
               "  vulnpilot analyze scan.csv\n"
               "  vulnpilot analyze scan.csv --evidence soc2\n"
               "  vulnpilot verify new_scan.csv --exceptions exceptions.csv\n"
               "  vulnpilot verify new_scan.csv --exceptions exceptions.csv --evidence iso27001\n"
               "\n"
               "docs: https://github.com/PatchVex/vulnpilot/tree/main/docs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"VulnPilot {__version__}")
    parser.add_argument("--no-colour", "--no-color", action="store_true",
                        dest="no_colour", help="Disable coloured terminal output")

    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="Analyze a Nessus CSV export")
    analyze.add_argument("csv", help="Path to Nessus CSV file")
    analyze.add_argument("--kev",  help="Path to local KEV JSON")
    analyze.add_argument("--epss", help="Path to local EPSS CSV")
    analyze.add_argument("--top-hosts", type=int, default=10, metavar="N",
                         help="Show top N hosts by aggregate risk (default: 10)")
    analyze.add_argument("--all", action="store_true",
                         help="Show all findings [Professional Edition]")
    analyze.add_argument("--license", metavar="KEY",
                         help="License key for Professional Edition")
    analyze.add_argument("--evidence", choices=["soc2", "iso27001"], metavar="FRAMEWORK",
                         help="Generate audit evidence pack (soc2, iso27001; more frameworks coming)")
    analyze.add_argument("--evidence-out", metavar="FILE",
                         help="Evidence pack output path (default: evidence_<fw>_<date>.md)")
    analyze.add_argument("--html", metavar="FILE",
                         help="Export HTML report to FILE (e.g. report.html)")

    feeds = sub.add_parser("update-feeds", help="Download latest KEV and EPSS feeds")

    verify_p = sub.add_parser("verify", help="Verify remediation: diff a new scan against history")
    verify_p.add_argument("csv", help="New Nessus CSV export to verify")
    verify_p.add_argument("--kev", metavar="FILE", help="Local KEV JSON file")
    verify_p.add_argument("--epss", metavar="FILE", help="Local EPSS file")
    verify_p.add_argument("--exceptions", metavar="FILE",
                          help="Exception register CSV (host, plugin_id, port, ticket_ref, "
                               "approver, approved_date, expiry_date, reason)")
    verify_p.add_argument("--evidence", choices=["soc2", "iso27001"], metavar="FRAMEWORK",
                          help="Generate evidence pack including verification results")
    verify_p.add_argument("--evidence-out", metavar="FILE",
                          help="Evidence pack output path")

    sub.add_parser("trend", help="Show findings trend across recorded scan history")
    feeds.add_argument("--cache", help="Cache directory for feeds")

    return parser


def cmd_verify(args) -> int:
    from vulnpilot.verify import verify_scan, render_verify
    from vulnpilot import history as _history
    from vulnpilot.sla import compute_all_sla, load_sla_config
    from vulnpilot.exceptions import load_exceptions, classify_all

    try:
        findings = parse_nessus_csv(Path(args.csv))
    except (FileNotFoundError, ValueError) as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1

    if not findings:
        print("\n  No actionable findings in this CSV.")
        return 0
    enrich(findings,
           kev_path=Path(args.kev) if getattr(args, "kev", None) else None,
           epss_path=Path(args.epss) if getattr(args, "epss", None) else None)
    scored = score_all(findings)

    try:
        result = verify_scan(scored)
    except RuntimeError as e:
        print(f"\n  {e}")
        return 1

    sla_statuses = compute_all_sla(scored, load_sla_config())
    exceptions_path = getattr(args, "exceptions", None)
    exceptions_map = load_exceptions(Path(exceptions_path)) if exceptions_path else {}
    governance = classify_all(sla_statuses, exceptions_map)
    print(render_verify(result, sla_statuses=sla_statuses, governance=governance,
                        use_colour=not getattr(args, "no_colour", False)))
    _history.record_scan(scored, scan_file=Path(args.csv))

    if getattr(args, "evidence", None):
        from vulnpilot.evidence import generate_evidence_pack
        from vulnpilot.exceptions import governance_summary as _gov_summary
        _out = generate_evidence_pack(
            findings=scored,
            framework=args.evidence,
            scan_file=Path(args.csv),
            output_path=Path(args.evidence_out) if getattr(args, "evidence_out", None) else None,
            verify_result=result,
            governance_summary=_gov_summary(governance),
        )
        print(f"  Evidence pack (with verification): {_out}")

    return 0


def cmd_trend(args) -> int:
    import sqlite3 as _sql
    from vulnpilot import history as _history

    try:
        conn = _sql.connect(_history.DB_PATH)
        rows = conn.execute(
            "SELECT timestamp_utc, total_findings, kev_count, critical_count"
            " FROM scan_history ORDER BY timestamp_utc"
        ).fetchall()
        conn.close()
    except Exception:
        rows = []

    if not rows:
        print("\n  No scan history yet. Run 'vulnpilot analyze <scan.csv>' first.")
        return 0

    print("\n  VulnPilot — Posture Trend\n")
    print(f"  {'Date':<12}{'Findings':>10}{'KEV':>7}{'Critical':>10}")
    print("  " + "─" * 39)
    for ts, total, kev, crit in rows:
        print(f"  {ts[:10]:<12}{total:>10}{kev:>7}{crit:>10}")
    first, last = rows[0], rows[-1]
    d_total, d_kev = last[1] - first[1], last[2] - first[2]
    def arrow(v):
        if v == 0:
            return "unchanged"
        return ("▼ down " if v < 0 else "▲ up ") + str(abs(v))
    print("  " + "─" * 39)
    print(f"  Since first scan: findings {arrow(d_total)}, KEV {arrow(d_kev)}")
    print()
    return 0


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    if args.command == "analyze":
        sys.exit(cmd_analyze(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "trend":
        sys.exit(cmd_trend(args))
    elif args.command == "update-feeds":
        sys.exit(cmd_update_feeds(args))


if __name__ == "__main__":
    main()
