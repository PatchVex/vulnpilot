"""Tests for analyze's history_id and verify --exclude-run (explicit baseline exclusion)."""
import argparse
import json
import sqlite3
from pathlib import Path

import pytest

from vulnpilot import history
from vulnpilot.cli import build_parser, cmd_analyze, cmd_verify

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"
SAMPLE_AFTER = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus_after.csv"


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "history.db")


def _analyze(csv, capsys, json_out=True):
    args = argparse.Namespace(
        csv=str(csv), kev=None, epss=None, no_colour=True, evidence=None,
        evidence_out=None, html=None, all=False, license=None, top_hosts=10,
        json=json_out, sla_config=None,
    )
    assert cmd_analyze(args) == 0
    out = capsys.readouterr().out
    return json.loads(out)["history_id"] if json_out else out


def _verify(csv, capsys, **kwargs):
    defaults = dict(
        csv=str(csv), kev=None, epss=None, no_colour=True, evidence=None,
        evidence_out=None, exceptions=None, json=True, sla_config=None,
        fail_on_breach=False, export_tickets=None, ticket_format="generic-csv",
        exclude_run=None,
    )
    defaults.update(kwargs)
    rc = cmd_verify(argparse.Namespace(**defaults))
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _row_ids():
    conn = sqlite3.connect(history.DB_PATH)
    ids = [r[0] for r in conn.execute("SELECT id FROM scan_history ORDER BY id")]
    conn.close()
    return ids


# ── analyze exposes the history row id ──────────────────────────────────────

def test_analyze_json_history_id_is_record_scan_primary_key(capsys):
    args = argparse.Namespace(
        csv=str(SAMPLE), kev=None, epss=None, no_colour=True, evidence=None,
        evidence_out=None, html=None, all=False, license=None, top_hosts=10,
        json=True, sla_config=None,
    )
    assert cmd_analyze(args) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["history_id"] == _row_ids()[-1]
    # existing fields are unchanged
    assert data["command"] == "analyze"
    assert data["scan_file"] == str(SAMPLE)
    assert data["total_findings"] == len(data["findings"]) == 6


def test_analyze_terminal_reports_history_id(capsys):
    out = _analyze(SAMPLE, capsys, json_out=False)
    assert f"History run ID: {_row_ids()[-1]}" in out


# ── verify --exclude-run ────────────────────────────────────────────────────

def test_analyze_then_verify_same_scan_does_not_self_compare(capsys):
    run_a = _analyze(SAMPLE, capsys)
    rc, out, err = _verify(SAMPLE, capsys, exclude_run=str(run_a), json=False)
    assert rc == 1
    assert "No baseline available" in err
    assert "Verified fixed" not in out
    assert _row_ids() == [run_a]  # nothing recorded on a failed verify


def test_analyze_a_analyze_b_verify_b_compares_against_a(capsys):
    _analyze(SAMPLE, capsys)
    run_b = _analyze(SAMPLE_AFTER, capsys)
    rc, out, err = _verify(SAMPLE_AFTER, capsys, exclude_run=str(run_b))
    assert rc == 0
    summary = json.loads(out)["summary"]
    assert summary["fixed"] == 1 and summary["new"] == 1


def test_repeated_identical_scan_compares_against_previous_identical_run(capsys):
    _analyze(SAMPLE, capsys)
    _analyze(SAMPLE_AFTER, capsys)
    run_b2 = _analyze(SAMPLE_AFTER, capsys)
    rc, out, err = _verify(SAMPLE_AFTER, capsys, exclude_run=str(run_b2))
    assert rc == 0
    summary = json.loads(out)["summary"]
    # compared against the earlier identical B, not skipped back to A
    assert summary == {"fixed": 0, "still_open": 5, "new": 0, "out_of_scope_hosts": 0}


def test_only_excluded_run_in_history_json_no_baseline(capsys):
    run_a = _analyze(SAMPLE, capsys)
    rc, out, err = _verify(SAMPLE, capsys, exclude_run=str(run_a))
    assert rc == 1
    assert out == ""  # stdout carries JSON only — nothing on failure
    assert "No baseline available" in err


@pytest.mark.parametrize("bad", ["abc", "0", "-3", "1.5", "999"])
def test_invalid_exclude_run_is_a_clear_error(capsys, bad):
    _analyze(SAMPLE, capsys)
    rc, out, err = _verify(SAMPLE, capsys, exclude_run=bad)
    assert rc == 1
    assert out == ""
    assert "ERROR" in err and "--exclude-run" in err


def test_exclude_run_is_a_verify_cli_option():
    args = build_parser().parse_args(["verify", "scan.csv", "--exclude-run", "7"])
    assert args.exclude_run == "7"


# ── JSON stdout contract on verify error paths ──────────────────────────────

def test_verify_json_no_history_keeps_stdout_clean(capsys):
    rc, out, err = _verify(SAMPLE, capsys)
    assert rc == 1
    assert out == ""
    assert "No scan history found" in err


NORMAL_VERIFY_JSON_TYPES = {
    "command": str, "scan_file": str, "baseline_date": str, "summary": dict,
    "governance": dict, "fixed": list, "still_open": list, "new": list,
    "out_of_scope_hosts": list, "findings": list,
}


def _info_only_csv(tmp_path):
    p = tmp_path / "info.csv"
    p.write_text("Plugin ID,CVE,Risk,Host,Protocol,Port,Name\n"
                 "19506,,None,10.0.0.1,tcp,0,Nessus Scan Information\n")
    return p


def test_verify_json_no_actionable_findings_emits_empty_verify_json(tmp_path, capsys):
    info_only = _info_only_csv(tmp_path)
    rc, out, err = _verify(info_only, capsys)
    assert rc == 0
    data = json.loads(out)
    assert data == {
        "command": "verify",
        "scan_file": str(info_only),
        "baseline_date": None,
        "summary": {"fixed": 0, "still_open": 0, "new": 0, "out_of_scope_hosts": 0},
        "governance": {"within_sla": 0, "breached_approved": 0, "breached_expired": 0,
                       "breached_no_exception": 0, "unknown": 0, "audit_findings": 0},
        "fixed": [], "still_open": [], "new": [], "out_of_scope_hosts": [],
        "findings": [],
    }
    assert "No actionable findings" in err
    assert not history.DB_PATH.exists()  # nothing recorded


def test_verify_empty_json_matches_normal_verify_json_shape(tmp_path, capsys):
    _analyze(SAMPLE, capsys)
    rc, out, err = _verify(SAMPLE_AFTER, capsys)
    normal = json.loads(out)
    rc, out, err = _verify(_info_only_csv(tmp_path), capsys)
    empty = json.loads(out)
    assert list(empty) == list(normal) == list(NORMAL_VERIFY_JSON_TYPES)
    assert set(empty["summary"]) == set(normal["summary"])
    assert set(empty["governance"]) == set(normal["governance"])
    for key, typ in NORMAL_VERIFY_JSON_TYPES.items():
        assert isinstance(normal[key], typ), key
        if key != "baseline_date":
            assert isinstance(empty[key], typ), key


def test_verify_no_actionable_findings_terminal_mode_unchanged(tmp_path, capsys):
    rc, out, err = _verify(_info_only_csv(tmp_path), capsys, json=False)
    assert rc == 0
    assert out == "\n  No actionable findings in this CSV.\n"
    assert err == ""


# ── compatibility ───────────────────────────────────────────────────────────

# Schema exactly as v1.1.0 created it (no scan_date / recorded_at columns).
_V110_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_utc TEXT NOT NULL,
    scan_file_name TEXT, scan_file_hash TEXT, total_findings INTEGER,
    kev_count INTEGER, critical_count INTEGER, high_count INTEGER, findings_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_ts ON scan_history (timestamp_utc);
"""


def test_exclude_run_on_v110_history_selects_the_earlier_run(capsys):
    from vulnpilot.parser import parse_nessus_csv
    conn = sqlite3.connect(history.DB_PATH)
    conn.executescript(_V110_SCHEMA)
    # Two distinguishable v1.1.0 runs: January = SAMPLE, February = SAMPLE_AFTER.
    for ts, csv in (("2026-01-01T09:00:00+00:00", SAMPLE),
                    ("2026-02-01T09:00:00+00:00", SAMPLE_AFTER)):
        keys = [history._finding_key(f) for f in parse_nessus_csv(csv)]
        conn.execute("INSERT INTO scan_history (timestamp_utc, findings_json) VALUES (?, ?)",
                     (ts, json.dumps(keys)))
    conn.commit()
    conn.close()
    jan, feb = _row_ids()

    # Without exclusion, February (identical to the scan) is the baseline.
    # (Library call: it records nothing, unlike the CLI verify below.)
    from vulnpilot.parser import parse_nessus_csv as _parse
    from vulnpilot.scoring import score_all
    from vulnpilot.verify import verify_scan
    default = verify_scan(score_all(_parse(SAMPLE_AFTER)))
    assert default.baseline_date == "2026-02-01"
    assert default.summary["fixed"] == 0 and default.summary["new"] == 0

    # Excluding February must fall back to January: Log4Shell fixed, Terrapin new.
    rc, out, _ = _verify(SAMPLE_AFTER, capsys, exclude_run=str(feb))
    assert rc == 0
    data = json.loads(out)
    assert data["baseline_date"] == "2026-01-01"
    assert data["summary"] == {"fixed": 1, "still_open": 4, "new": 1, "out_of_scope_hosts": 1}
    assert [d["cve"] for d in data["fixed"]] == ["CVE-2021-44228"]


def test_verify_without_exclude_run_matches_previous_release(capsys):
    # v1.1.0 semantics: the latest recorded row is the baseline.
    _analyze(SAMPLE, capsys)
    rc, out, err = _verify(SAMPLE_AFTER, capsys)
    assert rc == 0
    summary = json.loads(out)["summary"]
    assert summary == {"fixed": 1, "still_open": 4, "new": 1, "out_of_scope_hosts": 1}
