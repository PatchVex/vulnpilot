"""Tests for vulnpilot.export — actionable remediation ticket export."""
import argparse
import csv
import io
import json
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnpilot import history
from vulnpilot.cli import cmd_verify
from vulnpilot.exceptions import ExceptionRecord, FindingGovernance
from vulnpilot.export import (
    DEFAULT_FORMAT,
    SUPPORTED_FORMATS,
    build_ticket_records,
    render,
    to_generic_csv,
    to_jira_csv,
    to_json,
)
from vulnpilot.parser.base import Finding
from vulnpilot.sla import SLAStatus

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"
SAMPLE_AFTER = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus_after.csv"


# ── fixtures / helpers ──────────────────────────────────────────────────

def _finding(
    host="10.0.0.1", plugin_id="33850", port="443", cve="CVE-2021-44228",
    name="Apache Log4Shell RCE", risk="Critical", cvss_v3=10.0, cvss_v2=9.3,
    synopsis="Remote code execution via Log4j.",
    description="Log4Shell allows unauthenticated RCE.",
    solution="Upgrade Log4j to 2.15.0+.",
    epss_score=0.975, kev_match=True,
    priority_score=100.0, priority_label="CRITICAL NOW",
):
    return Finding(
        plugin_id=plugin_id, cve=cve, host=host, port=port, protocol="tcp",
        risk=risk, cvss_v3=cvss_v3, cvss_v2=cvss_v2, name=name,
        synopsis=synopsis, description=description, solution=solution,
        references="", plugin_output="",
        epss_score=epss_score, epss_percentile=0.99, kev_match=kev_match,
        priority_score=priority_score, priority_label=priority_label,
    )


def _sla(host="10.0.0.1", plugin_id="33850", port="443", status="breached",
         days_open=10, sla_days=7, risk="critical"):
    return SLAStatus(
        finding_key=(host, plugin_id, port),
        risk=risk, first_seen="2026-07-01",
        days_open=days_open, sla_days=sla_days,
        pct_elapsed=round(days_open / sla_days, 2) if sla_days else None,
        status=status,
    )


def _governance(sla_status, governance_status, exception=None):
    return FindingGovernance(
        finding_key=sla_status.finding_key,
        sla_status=sla_status,
        exception=exception,
        governance_status=governance_status,
        audit_finding=governance_status in ("breached_no_exception", "breached_expired"),
    )


def _exception(ticket_ref="JIRA-100", approver="CISO", expiry="2026-12-31"):
    return ExceptionRecord(
        host="10.0.0.1", plugin_id="33850", port="443",
        ticket_ref=ticket_ref, approver=approver,
        approved_date=date(2026, 7, 1),
        expiry_date=date.fromisoformat(expiry) if expiry else None,
        reason="vendor patch unavailable",
    )


# ── 1-2: empty / single actionable result ───────────────────────────────

def test_no_findings_produces_empty_export():
    records = build_ticket_records([], [])
    assert records == []


def test_single_actionable_finding_exported():
    f = _finding()
    sla = _sla()
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    assert len(records) == 1
    assert records[0].host == "10.0.0.1"
    assert records[0].cve == "CVE-2021-44228"


# ── findings that must NOT be exported ───────────────────────────────────

@pytest.mark.parametrize("governance_status", ["within_sla", "breached_approved", "unknown"])
def test_non_actionable_findings_excluded(governance_status):
    f = _finding()
    sla = _sla(status="within" if governance_status == "within_sla" else "breached")
    gov = _governance(sla, governance_status,
                       exception=_exception() if governance_status == "breached_approved" else None)
    records = build_ticket_records([f], [gov])
    assert records == []


def test_finding_with_no_governance_match_excluded():
    """A finding whose key doesn't appear in governance (e.g. a fixed
    finding, which is absent from `scored` entirely in real usage, but
    defensively tested here) must never be exported."""
    f = _finding(host="unrelated-host")
    sla = _sla()  # keyed to 10.0.0.1, not unrelated-host
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    assert records == []


# ── 3-6: multiple findings, priorities, KEV ──────────────────────────────

def test_multiple_findings_all_actionable_exported():
    f1 = _finding(host="10.0.0.1", plugin_id="33850", priority_score=100.0, kev_match=True)
    f2 = _finding(host="10.0.0.2", plugin_id="44000", priority_score=40.0, kev_match=False,
                   priority_label="MEDIUM", risk="Medium")
    sla1 = _sla(host="10.0.0.1", plugin_id="33850")
    sla2 = _sla(host="10.0.0.2", plugin_id="44000")
    gov1 = _governance(sla1, "breached_no_exception")
    gov2 = _governance(sla2, "breached_no_exception")
    records = build_ticket_records([f1, f2], [gov1, gov2])
    assert len(records) == 2


def test_sorted_kev_first_then_score():
    f_low_kev = _finding(host="a", plugin_id="1", priority_score=80.0, kev_match=True)
    f_high_no_kev = _finding(host="b", plugin_id="2", priority_score=95.0, kev_match=False)
    sla_a = _sla(host="a", plugin_id="1", port="443")
    sla_b = _sla(host="b", plugin_id="2", port="443")
    gov_a = _governance(sla_a, "breached_no_exception")
    gov_b = _governance(sla_b, "breached_no_exception")
    records = build_ticket_records([f_high_no_kev, f_low_kev], [gov_b, gov_a])
    # KEV finding must sort first even though its score is lower
    assert records[0].kev is True
    assert records[0].host == "a"


@pytest.mark.parametrize("label,risk", [
    ("CRITICAL NOW", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low"),
])
def test_all_priority_labels_carried_through(label, risk):
    f = _finding(priority_label=label, risk=risk)
    sla = _sla()
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    assert records[0].priority == label
    assert records[0].severity == risk


def test_kev_flag_carried_through():
    f = _finding(kev_match=True)
    sla = _sla()
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    assert records[0].kev is True


# ── 7: EPSS/CVSS values ──────────────────────────────────────────────────

def test_cvss_and_epss_values_carried_through():
    f = _finding(cvss_v3=9.1, cvss_v2=None, epss_score=0.481)
    sla = _sla()
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    assert records[0].cvss == 9.1
    assert records[0].epss == 0.481


def test_missing_cvss_and_epss_do_not_crash():
    f = _finding(cvss_v3=None, cvss_v2=None, epss_score=None)
    sla = _sla()
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    assert records[0].cvss is None
    assert records[0].epss is None


# ── 8: SLA information ───────────────────────────────────────────────────

def test_sla_fields_and_due_in_days():
    f = _finding()
    sla = _sla(days_open=10, sla_days=7, status="breached")
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    r = records[0]
    assert r.days_open == 10
    assert r.sla_days == 7
    assert r.sla_status == "breached"
    assert r.due_in_days == -3  # 3 days overdue


def test_due_in_days_none_when_sla_unknown():
    f = _finding()
    sla = _sla(days_open=None, sla_days=None, status="unknown")
    # unknown SLA status never has audit_finding True in real classify_finding,
    # but exercise the export layer directly for robustness.
    gov = FindingGovernance(
        finding_key=sla.finding_key, sla_status=sla, exception=None,
        governance_status="breached_no_exception", audit_finding=True,
    )
    records = build_ticket_records([f], [gov])
    assert records[0].due_in_days is None


# ── 9: governance status ─────────────────────────────────────────────────

@pytest.mark.parametrize("status", ["breached_no_exception", "breached_expired"])
def test_governance_status_carried_through(status):
    f = _finding()
    sla = _sla()
    gov = _governance(sla, status, exception=_exception() if status == "breached_expired" else None)
    records = build_ticket_records([f], [gov])
    assert records[0].governance_status == status


# ── 10: exception-related behaviour ──────────────────────────────────────

def test_expired_exception_details_included():
    f = _finding()
    sla = _sla()
    exc = _exception(ticket_ref="JIRA-OLD", approver="CISO", expiry="2026-01-01")
    gov = _governance(sla, "breached_expired", exception=exc)
    records = build_ticket_records([f], [gov])
    assert records[0].exception_ticket_ref == "JIRA-OLD"
    assert records[0].exception_approver == "CISO"
    assert records[0].exception_expiry == "2026-01-01"


def test_no_exception_fields_blank():
    f = _finding()
    sla = _sla()
    gov = _governance(sla, "breached_no_exception", exception=None)
    records = build_ticket_records([f], [gov])
    assert records[0].exception_ticket_ref == ""
    assert records[0].exception_approver == ""
    assert records[0].exception_expiry == ""


# ── 11: CSV escaping (commas, quotes, newlines) ─────────────────────────

def test_csv_escapes_commas_quotes_newlines():
    f = _finding(
        name='RCE, "critical" bug\nmulti-line',
        synopsis='Contains, a comma and "quotes"',
        solution="Line one\nLine two",
    )
    sla = _sla()
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    rendered = to_generic_csv(records)

    # Round-trip through csv.reader must recover the exact original values.
    rows = list(csv.reader(io.StringIO(rendered)))
    header, row = rows[0], rows[1]
    finding_idx = header.index("finding")
    desc_idx = header.index("description")
    remediation_idx = header.index("remediation")
    assert row[finding_idx] == 'RCE, "critical" bug\nmulti-line'
    assert row[desc_idx] == 'Contains, a comma and "quotes"'
    assert row[remediation_idx] == "Line one\nLine two"


def test_jira_csv_escapes_special_characters():
    f = _finding(synopsis='Has, a comma', solution='Has "quotes"')
    sla = _sla()
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    rendered = to_jira_csv(records)
    rows = list(csv.reader(io.StringIO(rendered)))
    assert len(rows) == 2  # header + 1 data row
    desc_idx = rows[0].index("Description")
    assert "Has, a comma" in rows[1][desc_idx]
    assert 'Has "quotes"' in rows[1][desc_idx]


# ── 12: deterministic output ──────────────────────────────────────────────

def test_output_is_deterministic():
    f1 = _finding(host="a", plugin_id="1", priority_score=90.0)
    f2 = _finding(host="b", plugin_id="2", priority_score=95.0)
    sla_a = _sla(host="a", plugin_id="1")
    sla_b = _sla(host="b", plugin_id="2")
    gov_a = _governance(sla_a, "breached_no_exception")
    gov_b = _governance(sla_b, "breached_no_exception")

    run1 = to_generic_csv(build_ticket_records([f1, f2], [gov_a, gov_b]))
    run2 = to_generic_csv(build_ticket_records([f1, f2], [gov_a, gov_b]))
    assert run1 == run2

    j1 = to_json(build_ticket_records([f1, f2], [gov_a, gov_b]))
    j2 = to_json(build_ticket_records([f1, f2], [gov_a, gov_b]))
    assert j1 == j2


# ── 13: JSON structure ────────────────────────────────────────────────────

def test_json_structure():
    f = _finding()
    sla = _sla()
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    payload = json.loads(to_json(records, scan_file="scan.csv"))
    assert payload["schema_version"] == 1
    assert payload["record_count"] == 1
    assert payload["scan_file"] == "scan.csv"
    assert isinstance(payload["records"], list)
    assert payload["records"][0]["host"] == "10.0.0.1"
    assert payload["records"][0]["cve"] == "CVE-2021-44228"


def test_json_empty_records_still_valid():
    payload = json.loads(to_json([], scan_file="scan.csv"))
    assert payload["record_count"] == 0
    assert payload["records"] == []


# ── render() dispatch / invalid format ────────────────────────────────────

def test_render_dispatches_to_correct_format():
    f = _finding()
    sla = _sla()
    gov = _governance(sla, "breached_no_exception")
    records = build_ticket_records([f], [gov])
    assert "summary,priority" in render(records, "generic-csv")
    assert json.loads(render(records, "json"))["record_count"] == 1
    assert "Summary,Issue Type" in render(records, "jira-csv")


def test_render_invalid_format_raises():
    with pytest.raises(ValueError, match="Unsupported ticket format"):
        render([], "yaml")


def test_supported_formats_constant_matches_render():
    for fmt in SUPPORTED_FORMATS:
        render([], fmt)  # must not raise for any declared-supported format


def test_default_format_is_generic_csv():
    assert DEFAULT_FORMAT == "generic-csv"


# ── CLI integration: --export-tickets / --ticket-format ──────────────────

def _seed_history_with_breach(tmp_path):
    """Seed history so a finding first-seen 10 days ago exists — matches
    a plugin_id/host present in sample_nessus_after.csv so it shows up as
    still_open with a breached SLA."""
    db = tmp_path / "history.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT, scan_file_name TEXT, scan_file_hash TEXT,
            total_findings INTEGER, kev_count INTEGER,
            critical_count INTEGER, high_count INTEGER, findings_json TEXT
        );
    """)
    ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    finding = {"host": "192.168.1.25", "plugin_id": "64786", "port": "443",
               "cve": "", "name": "test", "risk": "critical",
               "score": 100.0, "kev": False, "priority": "HIGH"}
    conn.execute(
        "INSERT INTO scan_history (timestamp_utc, findings_json, total_findings,"
        " kev_count, critical_count, high_count) VALUES (?, ?, 1, 0, 1, 0)",
        (ts, json.dumps([finding])),
    )
    conn.commit()
    conn.close()
    return db


def _verify_args(tmp_path, **kwargs):
    defaults = dict(
        csv=str(SAMPLE_AFTER), kev=None, epss=None, no_colour=True,
        evidence=None, evidence_out=None, exceptions=None, json=False,
        sla_config=None, fail_on_breach=False,
        export_tickets=None, ticket_format="generic-csv",
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ── 14: output file creation ──────────────────────────────────────────────

def test_cli_creates_export_file(tmp_path, monkeypatch, capsys):
    db = _seed_history_with_breach(tmp_path)
    monkeypatch.setattr(history, "DB_PATH", db)
    out = tmp_path / "tickets.csv"
    args = _verify_args(tmp_path, export_tickets=str(out))
    rc = cmd_verify(args)
    assert rc == 0
    assert out.exists()
    content = out.read_text()
    assert content.startswith("summary,priority")


def test_cli_export_message_printed(tmp_path, monkeypatch, capsys):
    db = _seed_history_with_breach(tmp_path)
    monkeypatch.setattr(history, "DB_PATH", db)
    out = tmp_path / "tickets.csv"
    args = _verify_args(tmp_path, export_tickets=str(out))
    cmd_verify(args)
    captured = capsys.readouterr()
    assert "Ticket export" in captured.out
    assert str(out) in captured.out


def test_cli_json_format_export(tmp_path, monkeypatch, capsys):
    db = _seed_history_with_breach(tmp_path)
    monkeypatch.setattr(history, "DB_PATH", db)
    out = tmp_path / "tickets.json"
    args = _verify_args(tmp_path, export_tickets=str(out), ticket_format="json")
    rc = cmd_verify(args)
    assert rc == 0
    payload = json.loads(out.read_text())
    assert "record_count" in payload


# ── 15: invalid format handling ───────────────────────────────────────────

def test_cli_invalid_ticket_format_rejected_by_argparse():
    from vulnpilot.cli import build_parser
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["verify", "scan.csv", "--export-tickets", "out.csv",
                            "--ticket-format", "yaml"])


# ── 16: backwards compatibility when export flags are absent ─────────────

def test_cli_verify_unaffected_when_export_flag_absent(tmp_path, monkeypatch, capsys):
    db = _seed_history_with_breach(tmp_path)
    monkeypatch.setattr(history, "DB_PATH", db)
    args = _verify_args(tmp_path)  # export_tickets=None
    rc = cmd_verify(args)
    captured = capsys.readouterr()
    assert rc == 0
    assert "Ticket export" not in captured.out
    assert "Remediation Verification" in captured.out


def test_cli_verify_json_mode_unaffected_when_export_flag_absent(tmp_path, monkeypatch, capsys):
    db = _seed_history_with_breach(tmp_path)
    monkeypatch.setattr(history, "DB_PATH", db)
    args = _verify_args(tmp_path, json=True)
    rc = cmd_verify(args)
    data = json.loads(capsys.readouterr().out)
    assert data["command"] == "verify"


def test_cli_export_in_json_mode_goes_to_stderr_not_stdout(tmp_path, monkeypatch, capsys):
    db = _seed_history_with_breach(tmp_path)
    monkeypatch.setattr(history, "DB_PATH", db)
    out = tmp_path / "tickets.csv"
    args = _verify_args(tmp_path, export_tickets=str(out), json=True)
    rc = cmd_verify(args)
    captured = capsys.readouterr()
    # stdout must remain pure, parseable JSON
    data = json.loads(captured.out)
    assert data["command"] == "verify"
    assert "Ticket export" in captured.err
