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
        description="VulnPilot by PatchVex — Turn vulnerability scan data into prioritized action.",
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
    analyze.add_argument("--evidence", choices=["soc2"], metavar="FRAMEWORK",
                         help="Generate audit evidence pack (soc2; more frameworks coming)")
    analyze.add_argument("--evidence-out", metavar="FILE",
                         help="Evidence pack output path (default: evidence_<fw>_<date>.md)")
    analyze.add_argument("--html", metavar="FILE",
                         help="Export HTML report to FILE (e.g. report.html)")

    feeds = sub.add_parser("update-feeds", help="Download latest KEV and EPSS feeds")
    feeds.add_argument("--cache", help="Cache directory for feeds")

    return parser


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    if args.command == "analyze":
        sys.exit(cmd_analyze(args))
    elif args.command == "update-feeds":
        sys.exit(cmd_update_feeds(args))


if __name__ == "__main__":
    main()
