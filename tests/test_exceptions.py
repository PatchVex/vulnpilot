"""Tests for the exceptions engine."""
import csv
import json
import sqlite3
from datetime import date, timedelta, datetime, timezone
from pathlib import Path

import pytest

from vulnpilot import history
from vulnpilot.sla import SLAStatus, compute_sla_status
from vulnpilot.exceptions import (
    ExceptionRecord, FindingGovernance,
    load_exceptions, classify_finding, classify_all, governance_summary,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_sla(status: str, key=("10.0.0.1", "33850", "443"),
              risk="critical") -> SLAStatus:
    return SLAStatus(
        finding_key=key, risk=risk,
        first_seen="2026-07-01", days_open=10,
        sla_days=7, pct_elapsed=1.43,
        status=status,
    )


def _write_exceptions_csv(path: Path, rows: list[dict]):
    fields = ["host", "plugin_id", "port", "ticket_ref",
              "approver", "approved_date", "expiry_date", "reason"]
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow(row)


# ── ExceptionRecord ───────────────────────────────────────────────────────────

def test_exception_valid_not_expired():
    rec = ExceptionRecord(
        host="10.0.0.1", plugin_id="33850", port="443",
        ticket_ref="JIRA-1", approver="CISO",
        approved_date=date(2026, 7, 1),
        expiry_date=date(2026, 12, 31),
        reason="vendor patch unavailable",
    )
    assert rec.is_valid(as_of=date(2026, 7, 7))


def test_exception_expired():
    rec = ExceptionRecord(
        host="10.0.0.1", plugin_id="33850", port="443",
        ticket_ref="JIRA-1", approver="CISO",
        approved_date=date(2026, 6, 1),
        expiry_date=date(2026, 6, 30),
        reason="temporary",
    )
    assert not rec.is_valid(as_of=date(2026, 7, 7))


# ── load_exceptions ───────────────────────────────────────────────────────────

def test_load_exceptions_valid(tmp_path):
    p = tmp_path / "e.csv"
    _write_exceptions_csv(p, [{
        "host": "10.0.0.1", "plugin_id": "33850", "port": "443",
        "ticket_ref": "JIRA-1", "approver": "CISO",
        "approved_date": "2026-07-01", "expiry_date": "2026-12-31",
        "reason": "vendor patch unavailable",
    }])
    recs = load_exceptions(p)
    assert ("10.0.0.1", "33850", "443") in recs
    assert recs[("10.0.0.1", "33850", "443")].approver == "CISO"


def test_load_exceptions_missing_file(tmp_path):
    recs = load_exceptions(tmp_path / "nonexistent.csv")
    assert recs == {}


# ── classify_finding ──────────────────────────────────────────────────────────

def test_within_sla_no_exception_needed():
    g = classify_finding(_make_sla("within"), {})
    assert g.governance_status == "within_sla"
    assert not g.audit_finding


def test_breached_no_exception_is_audit_finding():
    g = classify_finding(_make_sla("breached"), {})
    assert g.governance_status == "breached_no_exception"
    assert g.audit_finding


def test_breached_with_valid_exception(tmp_path):
    key = ("10.0.0.1", "33850", "443")
    exc = ExceptionRecord(
        host=key[0], plugin_id=key[1], port=key[2],
        ticket_ref="JIRA-1", approver="CISO",
        approved_date=date(2026, 7, 1),
        expiry_date=date(2026, 12, 31),
        reason="vendor patch unavailable",
    )
    g = classify_finding(_make_sla("breached", key=key),
                         {key: exc}, as_of=date(2026, 7, 7))
    assert g.governance_status == "breached_approved"
    assert not g.audit_finding


def test_breached_with_expired_exception(tmp_path):
    key = ("10.0.0.1", "33850", "443")
    exc = ExceptionRecord(
        host=key[0], plugin_id=key[1], port=key[2],
        ticket_ref="JIRA-1", approver="CISO",
        approved_date=date(2026, 6, 1),
        expiry_date=date(2026, 6, 30),
        reason="temporary",
    )
    g = classify_finding(_make_sla("breached", key=key),
                         {key: exc}, as_of=date(2026, 7, 7))
    assert g.governance_status == "breached_expired"
    assert g.audit_finding


def test_unknown_status_not_audit_finding():
    g = classify_finding(_make_sla("unknown"), {})
    assert g.governance_status == "unknown"
    assert not g.audit_finding


# ── governance_summary ────────────────────────────────────────────────────────

def test_governance_summary():
    govs = [
        classify_finding(_make_sla("within"), {}),
        classify_finding(_make_sla("breached"), {}),
        classify_finding(_make_sla("breached"), {}),
    ]
    s = governance_summary(govs)
    assert s["within_sla"] == 1
    assert s["breached_no_exception"] == 2
    assert s["audit_findings"] == 2
