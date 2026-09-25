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
import contextlib
import json
import logging
import re
import sys
from pathlib import Path
from typing import NoReturn, Optional

from vulnpilot import __version__
from vulnpilot.parser import parse
from vulnpilot.enrich import enrich, update_feeds
from vulnpilot.scoring import score_all
from vulnpilot.reports import (
    render_summary, render_findings, render_top_hosts, generate_html_report
)
from vulnpilot import export


def _finding_to_dict(f) -> dict:
    return {
        "plugin_id": f.plugin_id,
        "name": f.name,
        "cve": f.cve,
        "host": f.host,
        "port": f.port,
        "protocol": f.protocol,
        "risk": f.risk,
        "cvss_v3": f.cvss_v3,
        "cvss_v2": f.cvss_v2,
        "epss_score": f.epss_score,
        "epss_percentile": f.epss_percentile,
        "kev_match": f.kev_match,
        "priority_score": f.priority_score,
        "priority_label": f.priority_label,
        "synopsis": f.synopsis,
        "solution": f.solution,
    }


def _write_error(what: str, path, e: OSError, history_id: Optional[int] = None) -> int:
    """Report an output file that could not be written; returns exit code 1.
    History is recorded before outputs are written, so say so when it was."""
    path = e.filename or path
    reason = e.strerror or str(e)
    recorded = (f" The scan was already recorded to history as run {history_id}."
                if history_id is not None else "")
    print(f"\n  ERROR: Could not write {what} to {path}: {reason}.{recorded}",
          file=sys.stderr)
    return 1


def cmd_analyze(args: argparse.Namespace) -> int:
    scan_date = None
    if getattr(args, "scan_date", None) is not None:
        try:
            scan_date = _parse_scan_date(args.scan_date)
        except ValueError as e:
            print(f"\n  ERROR: {e}", file=sys.stderr)
            return 1

    try:
        findings = parse(Path(args.csv))
    except FileNotFoundError as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1

    if not findings:
        if getattr(args, "json", False):
            print("\n  No actionable findings in this CSV.", file=sys.stderr)
            # Same schema as a normal run; nothing is recorded to history.
            print(json.dumps({
                "command": "analyze",
                "scan_file": args.csv,
                "total_findings": 0,
                "findings": [],
                "history_id": None,
                "scan_date": scan_date,
                "recorded_at": None,
            }, indent=2))
            return 0
        print("\n  No actionable findings in this CSV.")
        return 0

    enrich(findings,
           kev_path=Path(args.kev) if args.kev else None,
           epss_path=Path(args.epss) if args.epss else None)

    scored = score_all(findings)

    from vulnpilot import history as _history
    from datetime import datetime, timezone
    recorded_at: Optional[str] = datetime.now(timezone.utc).isoformat()
    history_id = _history.record_scan(scored, scan_file=Path(args.csv),
                                      scan_date=scan_date, recorded_at=recorded_at)
    if history_id is None:
        recorded_at = None

    if getattr(args, "evidence", None):
        from vulnpilot.evidence import generate_evidence_pack
        try:
            _out = generate_evidence_pack(
                findings=scored,
                framework=args.evidence,
                scan_file=Path(args.csv),
                output_path=Path(args.evidence_out) if getattr(args, "evidence_out", None) else None,
                scan_date=scan_date,
                recorded_at=recorded_at,
            )
        except OSError as e:
            return _write_error("evidence pack", getattr(args, "evidence_out", None),
                                e, history_id)
        _ev_dest = sys.stderr if getattr(args, "json", False) else sys.stdout
        print(f"\n  Evidence pack written: {_out}", file=_ev_dest)

    if getattr(args, "json", False):
        if args.html:
            try:
                out = generate_html_report(
                    findings=scored,
                    output_path=Path(args.html),
                    scan_file=Path(args.csv).name,
                )
            except OSError as e:
                return _write_error("HTML report", args.html, e, history_id)
            print(f"\n  HTML report saved: {out}", file=sys.stderr)
        payload = {
            "command": "analyze",
            "scan_file": args.csv,
            "total_findings": len(scored),
            "findings": [_finding_to_dict(f) for f in scored],
            "history_id": history_id,
            "scan_date": scan_date,
            "recorded_at": recorded_at,
        }
        print(json.dumps(payload, indent=2))
        return 0

    # Terminal output
    use_colour = sys.stdout.isatty() and not args.no_colour
    print(render_summary(scored, use_colour=use_colour))
    print(render_findings(scored, limit=len(scored), use_colour=use_colour))
    print(render_top_hosts(scored, top_n=args.top_hosts, use_colour=use_colour))

    # HTML report
    if args.html:
        try:
            out = generate_html_report(
                findings=scored,
                output_path=Path(args.html),
                scan_file=Path(args.csv).name,
            )
        except OSError as e:
            return _write_error("HTML report", args.html, e, history_id)
        print(f"\n  HTML report saved: {out}")

    if history_id is not None:
        imported = (f" (imported; scan date {scan_date}, recorded {recorded_at[:10]})"
                    if scan_date and recorded_at else "")
        print(f"\n  History run ID: {history_id}{imported}")

    return 0


def cmd_update_feeds(args: argparse.Namespace) -> int:
    from vulnpilot.enrich.feeds import DEFAULT_CACHE
    as_json = getattr(args, "json", False)
    cache = Path(args.cache) if args.cache else None
    try:
        if as_json:
            # progress messages are diagnostics: keep stdout JSON-only
            with contextlib.redirect_stdout(sys.stderr):
                update_feeds(cache_dir=cache)
        else:
            update_feeds(cache_dir=cache)
    except Exception as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps({"command": "update-feeds",
                          "cache_dir": str(cache or DEFAULT_CACHE)}, indent=2))
    return 0


def _local_today():
    """Today's date in the user's local timezone. User-entered calendar dates
    (--scan-date, exception expiry dates) are compared with the local date;
    recording timestamps stay in UTC."""
    from datetime import date
    return date.today()


def _parse_scan_date(value: str) -> str:
    """Validate a --scan-date value: a real calendar date, exactly YYYY-MM-DD, not in the future."""
    from datetime import datetime
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        parsed = None
    if parsed is None or parsed.isoformat() != value:
        raise ValueError(f"--scan-date must be a valid date in YYYY-MM-DD format, got {value!r}")
    if parsed > _local_today():
        raise ValueError(f"--scan-date {value} is in the future")
    return value


def _add_workspace_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--workspace", metavar="NAME",
                   help="Keep scan history in a separate named workspace "
                        "(~/.vulnpilot/workspaces/NAME/), e.g. one per client. Names "
                        "are case-insensitive. Default: the shared ~/.vulnpilot/history.db")


def _select_workspace(args) -> int:
    """Point history at the requested workspace. Returns a non-zero exit code on error."""
    from vulnpilot import history as _history
    name = getattr(args, "workspace", None)
    if name is None:
        return 0
    try:
        _history.DB_PATH = _history.workspace_db_path(name)
        _history.WORKSPACE = _history.workspace_name(name)
    except ValueError as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1
    return 0


# Hidden compatibility aliases (see build_parser); never shown to users.
_HIDDEN_ALIASES = frozenset({"--exc", "--s"})
_AMBIGUOUS = re.compile(r"^(ambiguous option: .* could match )(.+)$")


class _ArgumentParser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors; VulnPilot reserves 2 for audit
    findings (--fail-on-breach), so usage errors exit 1 (tool error) instead.
    The usage line and message still go to stderr as argparse prints them."""

    def error(self, message: str) -> NoReturn:
        # Keep hidden aliases out of "ambiguous option ... could match ..." lists.
        m = _AMBIGUOUS.match(message)
        if m:
            matches = [o for o in m.group(2).split(", ") if o not in _HIDDEN_ALIASES]
            message = m.group(1) + ", ".join(matches)
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="vulnpilot",
        description="VulnPilot by PatchVex — Local-first vulnerability governance. "
                    "Your scanner finds them. VulnPilot proves you managed them.",
        epilog="examples:\n"
               "  vulnpilot update-feeds\n"
               "  vulnpilot analyze scan.csv\n"
               "  vulnpilot analyze scan.csv --evidence soc2\n"
               "  vulnpilot verify new_scan.csv --exceptions exceptions.csv\n"
               "  vulnpilot verify new_scan.csv --exceptions exceptions.csv --evidence iso27001\n"
               "  vulnpilot verify new_scan.csv --exceptions exceptions.csv "
               "--export-tickets tickets.csv\n"
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
                         help="(no-op; all findings are always shown in Community edition)")
    analyze.add_argument("--license", metavar="KEY",
                         help="License key (reserved for Workflow edition plugins)")
    analyze.add_argument("--evidence", choices=["soc2", "iso27001"], metavar="FRAMEWORK",
                         help="Generate audit evidence pack (soc2, iso27001; more frameworks coming)")
    analyze.add_argument("--evidence-out", metavar="FILE",
                         help="Evidence pack output path (default: evidence_<fw>_<date>.md)")
    analyze.add_argument("--html", metavar="FILE",
                         help="Export HTML report to FILE (e.g. report.html)")
    analyze.add_argument("--json", action="store_true",
                         help="Output findings as JSON (suppresses terminal output)")
    analyze.add_argument("--sla-config", metavar="FILE",
                         help="Path to SLA policy YAML (default: ~/.vulnpilot/sla.yaml)")
    # `--s` was an unambiguous abbreviation of --sla-config before --scan-date
    # existed; keep it resolving there (argparse matches exact strings first).
    analyze.add_argument("--s", dest="sla_config", metavar="FILE", help=argparse.SUPPRESS)
    _add_workspace_arg(analyze)
    analyze.add_argument("--scan-date", metavar="YYYY-MM-DD",
                         help="Date the scanner actually ran this scan, for importing "
                              "older scans into history. The row is marked as imported.")

    feeds = sub.add_parser("update-feeds", help="Download latest KEV and EPSS feeds")

    verify_p = sub.add_parser("verify", help="Verify remediation: diff a new scan against history")
    verify_p.add_argument("csv", help="New Nessus CSV export to verify")
    verify_p.add_argument("--kev", metavar="FILE", help="Local KEV JSON file")
    verify_p.add_argument("--epss", metavar="FILE", help="Local EPSS file")
    verify_p.add_argument("--exceptions", metavar="FILE",
                          help="Exception register CSV (host, plugin_id, port, ticket_ref, "
                               "approver, approved_date, expiry_date, reason). host, "
                               "plugin_id and port accept '*'; host accepts a CIDR range")
    # `--exc` was an unambiguous abbreviation of --exceptions before --exclude-run
    # existed; keep it resolving there (argparse matches exact strings first).
    verify_p.add_argument("--exc", dest="exceptions", metavar="FILE", help=argparse.SUPPRESS)
    verify_p.add_argument("--evidence", choices=["soc2", "iso27001"], metavar="FRAMEWORK",
                          help="Generate evidence pack including verification results")
    verify_p.add_argument("--evidence-out", metavar="FILE",
                          help="Evidence pack output path")
    verify_p.add_argument("--json", action="store_true",
                          help="Output verify result as JSON (suppresses terminal output)")
    verify_p.add_argument("--sla-config", metavar="FILE",
                          help="Path to SLA policy YAML (default: ~/.vulnpilot/sla.yaml)")
    verify_p.add_argument("--fail-on-breach", action="store_true",
                          help="Exit 2 if audit findings exist (expired/missing exceptions). "
                               "Exit 0 = clean. Exit 1 = tool error. Exit 2 = breach found.")
    _add_workspace_arg(verify_p)
    verify_p.add_argument("--exclude-run", metavar="ID",
                          help="History run ID to exclude as the baseline — pass the ID "
                               "'analyze' reported when verifying the same scan it just "
                               "analyzed")
    verify_p.add_argument("--export-tickets", metavar="FILE",
                          help="Export actionable findings (audit findings: breached with no "
                               "valid exception) as ticket-ready records to FILE")
    verify_p.add_argument("--ticket-format", choices=list(export.SUPPORTED_FORMATS),
                          default=export.DEFAULT_FORMAT, metavar="FORMAT",
                          help=f"Format for --export-tickets (default: {export.DEFAULT_FORMAT}). "
                               f"Choices: {', '.join(export.SUPPORTED_FORMATS)}")

    trend_p = sub.add_parser("trend", help="Show findings trend across recorded scan history")
    _add_workspace_arg(trend_p)
    trend_p.add_argument("--json", action="store_true",
                         help="Output the recorded runs as JSON (suppresses terminal output)")
    feeds.add_argument("--cache", help="Cache directory for feeds")
    feeds.add_argument("--json", action="store_true",
                       help="Print the result as JSON (progress goes to stderr)")

    return parser


def cmd_verify(args) -> int:
    from vulnpilot.verify import verify_scan, render_verify
    from vulnpilot import history as _history
    from vulnpilot.sla import compute_all_sla, load_sla_config
    from vulnpilot.exceptions import load_exceptions, classify_all

    exclude_run = None
    raw_exclude = getattr(args, "exclude_run", None)
    if raw_exclude is not None:
        try:
            exclude_run = int(raw_exclude)
        except ValueError:
            exclude_run = 0
        if exclude_run < 1:
            print(f"\n  ERROR: --exclude-run expects a positive history run ID, "
                  f"got {raw_exclude!r}", file=sys.stderr)
            return 1

    try:
        findings = parse(Path(args.csv))
    except (FileNotFoundError, ValueError) as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1

    if not findings:
        if getattr(args, "json", False):
            print("\n  No actionable findings in this CSV.", file=sys.stderr)
            # Same schema as a normal run; no baseline is loaded and nothing is
            # recorded to history, so baseline_date is null and all counts are 0.
            from vulnpilot.exceptions import governance_summary as _gov_summary
            from vulnpilot.verify import VerifyResult
            empty = VerifyResult(baseline_date="")
            print(json.dumps({
                "command": "verify",
                "scan_file": args.csv,
                "baseline_date": None,
                "summary": empty.summary,
                "governance": _gov_summary([]),
                "fixed": [],
                "still_open": [],
                "new": [],
                "out_of_scope_hosts": [],
                "findings": [],
                "baseline_run_id": None,
                "history_id": None,
            }, indent=2))
            return 0
        print("\n  No actionable findings in this CSV.")
        return 0
    enrich(findings,
           kev_path=Path(args.kev) if getattr(args, "kev", None) else None,
           epss_path=Path(args.epss) if getattr(args, "epss", None) else None)
    scored = score_all(findings)

    try:
        # One history read serves both baseline selection and SLA first-seen.
        history_rows = _history.load_rows()
        result = verify_scan(scored, exclude_run=exclude_run, rows=history_rows)
    except RuntimeError as e:
        print(f"\n  {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        return 1

    from vulnpilot.verify import self_comparison_warning
    self_compare = self_comparison_warning(result, Path(args.csv))

    sla_cfg_path = getattr(args, "sla_config", None)
    sla_config = load_sla_config(Path(sla_cfg_path)) if sla_cfg_path else load_sla_config()
    sla_statuses = compute_all_sla(scored, sla_config, rows=history_rows)
    exceptions_path = getattr(args, "exceptions", None)
    exceptions_map = {}
    if exceptions_path:
        if not Path(exceptions_path).is_file():
            print(f"\n  ERROR: Exceptions file not found: {exceptions_path}", file=sys.stderr)
            return 1
        try:
            exceptions_map = load_exceptions(Path(exceptions_path))
        except ValueError as e:
            print(f"\n  ERROR: {e}", file=sys.stderr)
            return 1
    governance = classify_all(sla_statuses, exceptions_map)

    from vulnpilot.exceptions import governance_summary as _gov_summary
    gov_summary = _gov_summary(governance)
    audit_findings = gov_summary.get("audit_findings", 0)
    fail_on_breach = getattr(args, "fail_on_breach", False)

    history_id = _history.record_scan(scored, scan_file=Path(args.csv))

    if getattr(args, "export_tickets", None):
        fmt = getattr(args, "ticket_format", None) or export.DEFAULT_FORMAT
        try:
            records = export.build_ticket_records(scored, governance)
            rendered = export.render(records, fmt, scan_file=args.csv)
        except ValueError as e:
            print(f"\n  ERROR: {e}", file=sys.stderr)
            return 1
        try:
            Path(args.export_tickets).write_text(rendered, encoding="utf-8")
        except OSError as e:
            return _write_error("ticket export", args.export_tickets, e, history_id)
        _dest = sys.stderr if getattr(args, "json", False) else sys.stdout
        print(f"  Ticket export ({fmt}, {len(records)} actionable finding(s)): "
              f"{args.export_tickets}", file=_dest)

    if getattr(args, "json", False):
        if getattr(args, "evidence", None):
            try:
                _write_verify_evidence(args, scored, result, gov_summary)
            except OSError as e:
                return _write_error("evidence pack", getattr(args, "evidence_out", None),
                                    e, history_id)
        if self_compare:
            print(f"\n  {self_compare}", file=sys.stderr)
        payload = {
            "command": "verify",
            "scan_file": args.csv,
            "baseline_date": result.baseline_date,
            "summary": result.summary,
            "governance": gov_summary,
            "fixed": result.fixed,
            "still_open": result.still_open,
            "new": result.new,
            "out_of_scope_hosts": result.out_of_scope_hosts,
            "findings": [_finding_to_dict(f) for f in scored],
            "baseline_run_id": result.baseline_run_id,
            "history_id": history_id,
        }
        print(json.dumps(payload, indent=2))
        return 2 if (fail_on_breach and audit_findings) else 0

    use_colour = sys.stdout.isatty() and not getattr(args, "no_colour", False)
    print(render_verify(result, sla_statuses=sla_statuses, governance=governance,
                        use_colour=use_colour, findings=scored))
    if self_compare:
        print(f"  {self_compare}\n", file=sys.stderr)

    if getattr(args, "evidence", None):
        try:
            _write_verify_evidence(args, scored, result, gov_summary)
        except OSError as e:
            return _write_error("evidence pack", getattr(args, "evidence_out", None),
                                e, history_id)

    return 2 if (fail_on_breach and audit_findings) else 0


def _write_verify_evidence(args, scored, result, gov_summary) -> None:
    from vulnpilot.evidence import generate_evidence_pack
    _out = generate_evidence_pack(
        findings=scored,
        framework=args.evidence,
        scan_file=Path(args.csv),
        output_path=Path(args.evidence_out) if getattr(args, "evidence_out", None) else None,
        verify_result=result,
        governance_summary=gov_summary,
    )
    _ev_dest = sys.stderr if getattr(args, "json", False) else sys.stdout
    print(f"  Evidence pack (with verification): {_out}", file=_ev_dest)


def cmd_trend(args) -> int:
    from vulnpilot import history as _history

    rows = _history.get_trend_rows()

    if getattr(args, "json", False):
        if not rows:
            print("\n  No scan history yet. Run "
                  f"'vulnpilot analyze <scan.csv>{_history.command_hint()}' first.",
                  file=sys.stderr)
        print(json.dumps({"command": "trend", "runs": [
            {"timestamp_utc": ts, "total_findings": total, "kev_count": kev,
             "critical_count": crit, "scan_date": scan_date}
            for ts, total, kev, crit, scan_date, _recorded_at in rows]}, indent=2))
        return 0

    if not rows:
        print("\n  No scan history yet. Run "
              f"'vulnpilot analyze <scan.csv>{_history.command_hint()}' first.")
        return 0

    print("\n  VulnPilot — Posture Trend\n")
    print(f"  {'Date':<12}{'Findings':>10}{'KEV':>7}{'Critical':>10}")
    print("  " + "─" * 39)
    imported = False
    for ts, total, kev, crit, scan_date, recorded_at in rows:
        # Date is when VulnPilot recorded the run; an import also shows its scan date.
        note = f"  imported; scan date {scan_date}" if scan_date else ""
        imported = imported or bool(scan_date)
        print(f"  {ts[:10]:<12}{total:>10}{kev:>7}{crit:>10}{note}")
    first, last = rows[0], rows[-1]
    d_total, d_kev = last[1] - first[1], last[2] - first[2]
    def arrow(v):
        if v == 0:
            return "unchanged"
        return ("▼ down " if v < 0 else "▲ up ") + str(abs(v))
    print("  " + "─" * 39)
    print(f"  Since first scan: findings {arrow(d_total)}, KEV {arrow(d_kev)}")
    if imported:
        print("  Date is when VulnPilot recorded each run. Rows marked 'imported' were "
              "added with --scan-date;\n  their scan date is when the scanner ran.")
    print()
    return 0


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    rc = _select_workspace(args)
    if rc:
        sys.exit(rc)
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
