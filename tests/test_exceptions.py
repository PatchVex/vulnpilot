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



_VALID_ROW = {
    "host": "10.0.0.1", "plugin_id": "33850", "port": "443",
    "ticket_ref": "JIRA-1", "approver": "CISO",
    "approved_date": "2026-07-01", "expiry_date": "2026-12-31",
    "reason": "vendor patch unavailable",
}


def test_load_exceptions_accepts_excel_bom(tmp_path):
    plain = tmp_path / "plain.csv"
    _write_exceptions_csv(plain, [_VALID_ROW])
    bom = tmp_path / "bom.csv"
    bom.write_bytes(b"\xef\xbb\xbf" + plain.read_bytes())
    assert ("10.0.0.1", "33850", "443") in load_exceptions(bom)


def test_load_exceptions_skips_only_malformed_row(tmp_path, caplog):
    p = tmp_path / "e.csv"
    _write_exceptions_csv(p, [_VALID_ROW])
    with open(p, "a") as fh:
        fh.write("10.0.0.2,1,22,T-2,CISO,2026-07-01,2026-12-31,reason,EXTRA\n")
        fh.write("10.0.0.3,1\n")
    recs = load_exceptions(p)
    assert list(recs) == [("10.0.0.1", "33850", "443")]
    assert caplog.text.count("line 3: column count does not match header") == 1  # extra field
    assert caplog.text.count("line 4: missing required field(s) port") == 1       # short row


def test_load_exceptions_warns_on_missing_host(tmp_path, caplog):
    p = tmp_path / "e.csv"
    _write_exceptions_csv(p, [_VALID_ROW, dict(_VALID_ROW, host="")])
    assert len(load_exceptions(p)) == 1
    assert "no host" in caplog.text


def test_load_exceptions_warns_on_unparseable_date(tmp_path, caplog):
    p = tmp_path / "e.csv"
    _write_exceptions_csv(p, [dict(_VALID_ROW, expiry_date="31st Dec")])
    rec = load_exceptions(p)[("10.0.0.1", "33850", "443")]
    assert rec.expiry_date is None
    assert "unrecognised expiry_date" in caplog.text


def test_load_exceptions_missing_required_columns_raises(tmp_path):
    p = tmp_path / "e.csv"
    p.write_text("hostname,plugin,ticket\n10.0.0.1,33850,JIRA-1\n")
    with pytest.raises(ValueError, match="missing required column"):
        load_exceptions(p)


# ── wildcard / CIDR exceptions ──────────────────────────────────────────────

def _load(tmp_path, rows):
    p = tmp_path / "e.csv"
    _write_exceptions_csv(p, [dict(_VALID_ROW, **r) for r in rows])
    return load_exceptions(p)


def test_wildcard_plugin_across_all_hosts(tmp_path):
    excs = _load(tmp_path, [{"host": "*", "plugin_id": "33850", "port": "*"}])
    g = classify_finding(_make_sla("breached", key=("10.9.9.9", "33850", "8443")), excs)
    assert g.governance_status == "breached_approved"
    assert g.exception.ticket_ref == "JIRA-1"
    g = classify_finding(_make_sla("breached", key=("10.9.9.9", "99999", "8443")), excs)
    assert g.governance_status == "breached_no_exception"


def test_cidr_host_range(tmp_path):
    excs = _load(tmp_path, [{"host": "10.0.0.0/24", "plugin_id": "33850", "port": "*"}])
    inside = classify_finding(_make_sla("breached", key=("10.0.0.77", "33850", "443")), excs)
    outside = classify_finding(_make_sla("breached", key=("10.0.1.77", "33850", "443")), excs)
    hostname = classify_finding(_make_sla("breached", key=("web01", "33850", "443")), excs)
    assert inside.governance_status == "breached_approved"
    assert outside.governance_status == "breached_no_exception"
    assert hostname.governance_status == "breached_no_exception"


def test_exact_match_wins_over_pattern(tmp_path):
    excs = _load(tmp_path, [
        {"host": "*", "plugin_id": "33850", "port": "*", "ticket_ref": "WIDE"},
        {"host": "10.0.0.1", "plugin_id": "33850", "port": "443", "ticket_ref": "EXACT",
         "expiry_date": "2020-01-01"},
    ])
    g = classify_finding(_make_sla("breached"), excs)
    # the exact (expired) row applies, not the broader valid wildcard
    assert g.exception.ticket_ref == "EXACT"
    assert g.governance_status == "breached_expired"


def test_most_specific_pattern_wins(tmp_path):
    excs = _load(tmp_path, [
        {"host": "*", "plugin_id": "33850", "port": "*", "ticket_ref": "ANY-HOST"},
        {"host": "10.0.0.0/24", "plugin_id": "33850", "port": "*", "ticket_ref": "SUBNET"},
        {"host": "10.0.0.1", "plugin_id": "*", "port": "*", "ticket_ref": "HOST-WIDE"},
    ])
    # plugin + subnet (score 3) is narrower than any-host (2) or host-wide (2)
    g = classify_finding(_make_sla("breached"), excs)
    assert g.exception.ticket_ref == "SUBNET"


def test_equal_specificity_uses_first_row_in_file(tmp_path):
    excs = _load(tmp_path, [
        {"host": "10.0.0.1", "plugin_id": "*", "port": "*", "ticket_ref": "HOST-WIDE"},
        {"host": "*", "plugin_id": "33850", "port": "*", "ticket_ref": "ANY-HOST"},
    ])
    assert classify_finding(_make_sla("breached"), excs).exception.ticket_ref == "HOST-WIDE"


def test_blanket_exception_rejected(tmp_path, caplog):
    excs = _load(tmp_path, [{"host": "*", "plugin_id": "*", "port": "*"},
                            {"host": "0.0.0.0/0", "plugin_id": "*", "port": "*"}])
    assert excs == {}
    assert caplog.text.count("blanket exception is not allowed") == 2


def test_invalid_cidr_skipped(tmp_path, caplog):
    excs = _load(tmp_path, [{"host": "10.0.0.0/33", "plugin_id": "33850", "port": "*"}])
    assert excs == {}
    assert "invalid CIDR host" in caplog.text


def test_exact_rows_behave_as_before(tmp_path):
    excs = _load(tmp_path, [{}])
    assert classify_finding(_make_sla("breached"), excs).governance_status == "breached_approved"
    other = classify_finding(_make_sla("breached", key=("10.0.0.2", "33850", "443")), excs)
    assert other.governance_status == "breached_no_exception"



# ── CIDR specificity: narrower network wins ────────────────────────────────

def _ticket(tmp_path, rows, key=("10.1.2.3", "33850", "443")):
    return classify_finding(_make_sla("breached", key=key), _load(tmp_path, rows)).exception


@pytest.mark.parametrize("order", [("/8", "/16"), ("/16", "/8")])
def test_narrower_ipv4_cidr_wins_regardless_of_file_order(tmp_path, order):
    nets = {"/8": "10.0.0.0/8", "/16": "10.1.0.0/16"}
    rows = [{"host": nets[o], "plugin_id": "33850", "port": "*", "ticket_ref": o} for o in order]
    assert _ticket(tmp_path, rows).ticket_ref == "/16"


def test_narrower_ipv6_cidr_wins(tmp_path):
    rows = [{"host": "2001:db8::/32", "plugin_id": "33850", "port": "*", "ticket_ref": "/32"},
            {"host": "2001:db8:1::/48", "plugin_id": "33850", "port": "*", "ticket_ref": "/48"}]
    assert _ticket(tmp_path, rows, key=("2001:db8:1::5", "33850", "443")).ticket_ref == "/48"
    # an IPv4 host is never matched by an IPv6 network (and vice versa)
    assert _ticket(tmp_path, rows) is None


def test_equally_specific_cidr_rows_use_file_order(tmp_path):
    rows = [{"host": "10.1.0.0/16", "plugin_id": "33850", "port": "*", "ticket_ref": "FIRST"},
            {"host": "10.1.0.0/16", "plugin_id": "*", "port": "443", "ticket_ref": "SECOND"}]
    assert _ticket(tmp_path, rows).ticket_ref == "FIRST"
    assert _ticket(tmp_path, rows[::-1]).ticket_ref == "SECOND"


def test_exact_host_beats_cidr_with_same_other_fields(tmp_path):
    rows = [{"host": "10.1.2.3/32", "plugin_id": "33850", "port": "*", "ticket_ref": "CIDR"},
            {"host": "10.1.2.3", "plugin_id": "33850", "port": "*", "ticket_ref": "EXACT-HOST"}]
    # exact host scores 2+2+0 = 4, CIDR host 1+2+0 = 3 — even for a /32
    assert _ticket(tmp_path, rows).ticket_ref == "EXACT-HOST"


def test_exact_key_always_wins_over_patterns(tmp_path):
    rows = [{"host": "10.1.2.3/32", "plugin_id": "33850", "port": "443", "ticket_ref": "CIDR"},
            {"host": "10.1.2.3", "plugin_id": "33850", "port": "443", "ticket_ref": "EXACT"}]
    assert _ticket(tmp_path, rows).ticket_ref == "EXACT"


def test_cidr_beats_wildcard_host(tmp_path):
    rows = [{"host": "*", "plugin_id": "33850", "port": "*", "ticket_ref": "ANY"},
            {"host": "10.0.0.0/8", "plugin_id": "33850", "port": "*", "ticket_ref": "CIDR"}]
    assert _ticket(tmp_path, rows).ticket_ref == "CIDR"


def test_field_specificity_still_outranks_prefix_length(tmp_path):
    # naming the plugin (score 3) beats a narrower but plugin-agnostic range (score 1)
    rows = [{"host": "10.1.2.0/24", "plugin_id": "*", "port": "*", "ticket_ref": "NARROW-ANY"},
            {"host": "10.0.0.0/8", "plugin_id": "33850", "port": "*", "ticket_ref": "WIDE-PLUGIN"}]
    assert _ticket(tmp_path, rows).ticket_ref == "WIDE-PLUGIN"



def test_directly_built_record_with_invalid_cidr_never_matches():
    bad = ExceptionRecord(host="10.0.0.0/33", plugin_id="33850", port="*",
                          ticket_ref="BAD", approver="CISO", approved_date=None,
                          expiry_date=None, reason="")
    assert bad.network is None
    assert bad.matches(("10.0.0.1", "33850", "443")) is False
    good = ExceptionRecord(host="*", plugin_id="33850", port="*", ticket_ref="GOOD",
                           approver="CISO", approved_date=None, expiry_date=None, reason="")
    g = classify_finding(_make_sla("breached"), {bad.key: bad, good.key: good})
    assert g.exception.ticket_ref == "GOOD"  # no exception raised; valid row applies

# ── duplicate rows: the later row replaces the earlier one ──────────────────

def test_duplicate_exact_row_later_wins_with_warning(tmp_path, caplog):
    excs = _load(tmp_path, [{"ticket_ref": "OLD", "expiry_date": "2026-01-31"},
                            {"ticket_ref": "RENEWED", "expiry_date": "2026-12-31"}])
    rec = excs[("10.0.0.1", "33850", "443")]
    assert (rec.ticket_ref, rec.expiry_date) == ("RENEWED", date(2026, 12, 31))
    assert "line 3: same host, plugin_id and port as line 2 — line 3 replaces line 2" in caplog.text
    g = classify_finding(_make_sla("breached"), excs, as_of=date(2026, 6, 1))
    assert g.governance_status == "breached_approved"  # renewal takes effect


def test_duplicate_row_can_revoke_an_approval(tmp_path):
    excs = _load(tmp_path, [{"ticket_ref": "APPROVED", "expiry_date": "2026-12-31"},
                            {"ticket_ref": "ENDED", "expiry_date": "2026-03-01"}])
    g = classify_finding(_make_sla("breached"), excs, as_of=date(2026, 6, 1))
    assert (g.exception.ticket_ref, g.governance_status) == ("ENDED", "breached_expired")


def test_duplicate_pattern_takes_its_own_file_position_for_ties(tmp_path):
    rows = [{"host": "*", "plugin_id": "33850", "port": "*", "ticket_ref": "A"},
            {"host": "10.0.0.1", "plugin_id": "*", "port": "*", "ticket_ref": "B"},
            {"host": "*", "plugin_id": "33850", "port": "*", "ticket_ref": "A-AGAIN"}]
    excs = _load(tmp_path, rows)
    assert [r.ticket_ref for r in excs.values()] == ["B", "A-AGAIN"]
    # A-AGAIN (line 4) now comes after B (line 3): the tie goes to B
    assert classify_finding(_make_sla("breached"), excs).exception.ticket_ref == "B"


def test_duplicate_handling_is_deterministic(tmp_path):
    rows = [{"ticket_ref": f"T{i}"} for i in range(5)]
    results = {_load(tmp_path, rows)[("10.0.0.1", "33850", "443")].ticket_ref for _ in range(5)}
    assert results == {"T4"}

# ── short rows: missing trailing optional columns ──────────────────────────

_HEADER = "host,plugin_id,port,ticket_ref,approver,approved_date,expiry_date,reason\n"


def test_short_row_missing_trailing_reason_is_accepted(tmp_path, caplog):
    p = tmp_path / "e.csv"
    p.write_text(_HEADER + "10.0.0.1,33850,443,JIRA-1,CISO,2026-07-01,2026-12-31\n")
    rec = load_exceptions(p)[("10.0.0.1", "33850", "443")]
    assert rec.reason == ""
    assert (rec.ticket_ref, rec.approver) == ("JIRA-1", "CISO")
    assert rec.expiry_date == date(2026, 12, 31)
    assert caplog.text == ""
    assert classify_finding(_make_sla("breached"), {rec.key: rec},
                            as_of=date(2026, 7, 7)).governance_status == "breached_approved"


def test_short_row_missing_several_optional_columns_is_accepted(tmp_path):
    p = tmp_path / "e.csv"
    p.write_text(_HEADER + "10.0.0.1,33850,443,JIRA-1,CISO\n")
    rec = load_exceptions(p)[("10.0.0.1", "33850", "443")]
    assert rec.approved_date is None and rec.expiry_date is None and rec.reason == ""


def test_short_row_missing_required_column_is_skipped(tmp_path, caplog):
    p = tmp_path / "e.csv"
    p.write_text(_HEADER + "10.0.0.1,33850\n")
    assert load_exceptions(p) == {}
    assert "line 2: missing required field(s) port — row skipped" in caplog.text


def test_required_column_last_in_header_still_required(tmp_path, caplog):
    p = tmp_path / "e.csv"
    p.write_text("ticket_ref,approver,host,plugin_id,port\nJIRA-1,CISO,10.0.0.1,33850\n")
    assert load_exceptions(p) == {}
    assert "missing required field(s) port" in caplog.text


def test_row_with_extra_field_is_still_skipped(tmp_path, caplog):
    # e.g. an unquoted comma in the reason — normal CSV parsing, not reinterpreted
    p = tmp_path / "e.csv"
    p.write_text(_HEADER + "10.0.0.1,33850,443,JIRA-1,CISO,2026-07-01,2026-12-31,"
                 "vendor patch unavailable, WAF in place\n")
    assert load_exceptions(p) == {}
    assert "line 2: column count does not match header — row skipped" in caplog.text


def test_full_rows_unchanged_by_short_row_handling(tmp_path, caplog):
    excs = _load(tmp_path, [{}, {"host": "*", "plugin_id": "99", "port": "*",
                                  "ticket_ref": "WIDE", "reason": "fleet-wide"}])
    exact = excs[("10.0.0.1", "33850", "443")]
    assert exact.reason == "vendor patch unavailable" and exact.ticket_ref == "JIRA-1"
    assert excs[("*", "99", "*")].is_pattern
    assert caplog.text == ""

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
