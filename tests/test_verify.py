import json
from pathlib import Path

import pytest

from vulnpilot.parser.nessus import parse_nessus_csv
from vulnpilot.scoring import score_all
from vulnpilot import history
from datetime import date

from vulnpilot.verify import verify_scan, render_verify, VerifyResult
from vulnpilot.sla import SLAStatus
from vulnpilot.exceptions import ExceptionRecord, FindingGovernance

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"


def _scored(exclude_cves=(), exclude_hosts=()):
    findings = parse_nessus_csv(SAMPLE)
    findings = [f for f in findings
                if f.cve not in exclude_cves and f.host not in exclude_hosts]
    for f in findings:
        f.kev_match = f.cve in ("CVE-2021-44228", "CVE-2020-1472")
        f.epss_score = 0.95 if f.kev_match else 0.01
    return score_all(findings)


def _seed_history(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "history.db")
    history.record_scan(_scored(), scan_file=SAMPLE)


def test_verify_detects_fixed_same_scope(tmp_path, monkeypatch):
    _seed_history(tmp_path, monkeypatch)
    # remove one finding but keep its host present (host 192.168.1.10 has 3 findings)
    new = _scored(exclude_cves=("CVE-2021-44228",))
    result = verify_scan(new)
    fixed_cves = {d["cve"] for d in result.fixed}
    assert "CVE-2021-44228" in fixed_cves
    assert result.summary["new"] == 0


def test_verify_scope_guard(tmp_path, monkeypatch):
    _seed_history(tmp_path, monkeypatch)
    # drop an entire host — its findings must NOT be counted fixed
    new = _scored(exclude_hosts=("192.168.1.15",))
    result = verify_scan(new)
    assert "192.168.1.15" in result.out_of_scope_hosts
    assert all(d["host"] != "192.168.1.15" for d in result.fixed)


def test_verify_detects_new(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "history.db")
    baseline = _scored(exclude_cves=("CVE-2023-34362",))
    history.record_scan(baseline, scan_file=SAMPLE)
    result = verify_scan(_scored())
    assert any(d["cve"] == "CVE-2023-34362" for d in result.new)


def test_verify_without_history_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "none.db")
    with pytest.raises(RuntimeError):
        verify_scan(_scored())


def _make_sla(status, host="10.0.0.1", days_open=10, sla_days=7, risk="critical"):
    return SLAStatus(
        finding_key=(host, "33850", "443"),
        risk=risk,
        first_seen="2026-07-01",
        days_open=days_open,
        sla_days=sla_days,
        pct_elapsed=round(days_open / sla_days, 2),
        status=status,
    )


def _empty_result():
    return VerifyResult(baseline_date="2026-07-01")


def test_render_verify_sla_block_present():
    sla_statuses = [
        _make_sla("within",     host="10.0.0.1", days_open=3,  sla_days=7),
        _make_sla("approaching", host="10.0.0.2", days_open=6,  sla_days=7),
        _make_sla("breached",   host="10.0.0.3", days_open=10, sla_days=7),
    ]
    output = render_verify(_empty_result(), sla_statuses=sla_statuses, use_colour=False)
    assert "SLA Compliance" in output
    assert "Within SLA"     in output and ": 1" in output
    assert "Approaching"    in output and ": 1" in output
    assert "Breached"       in output and ": 1" in output
    assert "REQUIRES ACTION" in output
    assert "Breach detail"  in output
    assert "10.0.0.3"       in output   # breached host appears in detail
    assert "10d open"       in output
    assert "SLA: 7d"        in output


def test_render_verify_without_sla_statuses_unchanged():
    # Existing callers that omit sla_statuses must not see any SLA output.
    output = render_verify(_empty_result(), use_colour=False)
    assert "SLA Compliance" not in output
    assert "Breach detail"  not in output


# ── governance (FindingGovernance) rendering tests ────────────────────────────

def _make_governance(governance_status, host="10.0.0.1", days_open=10,
                     sla_days=7, risk="critical", exception=None):
    sla = _make_sla(
        "breached" if "breached" in governance_status else
        ("unknown" if governance_status == "unknown" else "within"),
        host=host, days_open=days_open, sla_days=sla_days, risk=risk,
    )
    return FindingGovernance(
        finding_key=sla.finding_key,
        sla_status=sla,
        exception=exception,
        governance_status=governance_status,
        audit_finding=governance_status in ("breached_no_exception", "breached_expired"),
    )


def _make_exception(ticket_ref="JIRA-1", expiry="2026-12-31"):
    return ExceptionRecord(
        host="10.0.0.1", plugin_id="33850", port="443",
        ticket_ref=ticket_ref, approver="CISO",
        approved_date=date(2026, 7, 1),
        expiry_date=date.fromisoformat(expiry),
        reason="vendor patch unavailable",
    )


def test_render_verify_governance_prefers_governance_over_sla_statuses():
    # When both are supplied governance wins — "Governance Summary" not "SLA Compliance".
    sla = [_make_sla("breached")]
    gov = [_make_governance("breached_no_exception")]
    output = render_verify(_empty_result(), sla_statuses=sla, governance=gov,
                           use_colour=False)
    assert "Governance Summary" in output
    assert "SLA Compliance"     not in output


def test_render_verify_governance_audit_findings_count():
    gov = [
        _make_governance("within_sla",            host="10.0.0.1"),
        _make_governance("breached_no_exception",  host="10.0.0.2"),
        _make_governance("breached_no_exception",  host="10.0.0.3"),
    ]
    output = render_verify(_empty_result(), governance=gov, use_colour=False)
    assert "Audit findings requiring action  : 2" in output


def test_render_verify_governance_approved_exception_shown():
    exc = _make_exception(ticket_ref="JIRA-4521", expiry="2026-12-31")
    gov = [_make_governance("breached_approved", exception=exc)]
    output = render_verify(_empty_result(), governance=gov, use_colour=False)
    assert "JIRA-4521" in output
    assert "approved"  in output


def test_render_verify_governance_no_exception_note():
    gov = [_make_governance("breached_no_exception", host="10.0.0.5")]
    output = render_verify(_empty_result(), governance=gov, use_colour=False)
    assert "no exception on file" in output
    assert "10.0.0.5"             in output


def test_render_verify_governance_expired_exception_shown():
    exc = _make_exception(ticket_ref="JIRA-OLD", expiry="2026-01-01")
    gov = [_make_governance("breached_expired", exception=exc)]
    output = render_verify(_empty_result(), governance=gov, use_colour=False)
    assert "JIRA-OLD" in output
    assert "expired"  in output
