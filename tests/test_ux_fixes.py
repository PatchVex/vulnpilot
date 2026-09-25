"""Regression tests for the 1.2.1 UX fixes:

A. verify warns when the baseline was recorded from the same scan file
B. a non-blank but unreadable exception expiry_date makes the exception invalid
C. terminal breach detail identifies the finding (port, CVE, name)
D. unwritable output paths are a clean ERROR, exit 1, never a traceback
E. evidence-pack metadata renders as separate Markdown lines
F. verify output has no ANSI colour when stdout is not a terminal
"""
import csv
import json
import sqlite3
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnpilot import history
from vulnpilot.cli import main
from vulnpilot.exceptions import ExceptionRecord, classify_finding, load_exceptions
from vulnpilot.parser.base import Finding
from vulnpilot.parser.nessus import parse_nessus_csv
from vulnpilot.scoring import score_all
from vulnpilot.sla import SLAStatus
from vulnpilot.exceptions import FindingGovernance
from vulnpilot.verify import render_verify, VerifyResult

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"
SAMPLE_AFTER = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus_after.csv"
ANSI = "\033["

LONG_NAME = "OpenSSL Example Vulnerability With A Deliberately Long Finding Name For Truncation"

# Two High findings on one host: identical host/severity/days in breach detail.
TWO_ON_ONE_HOST = (
    "Plugin ID,CVE,CVSS v3.0 Base Score,CVSS v2.0 Base Score,Risk,Host,Protocol,Port,"
    "Name,Synopsis,Description,Solution,See Also,Plugin Output\n"
    f"111,CVE-2024-0001,7.5,,High,10.0.0.5,tcp,443,{LONG_NAME},s,d,Upgrade.,,\n"
    "222,,7.5,,High,10.0.0.5,tcp,8443,Web Server Example Misconfiguration,s,d,Fix.,,\n"
)
EXC_HEADER = ["host", "plugin_id", "port", "ticket_ref", "approver",
              "approved_date", "expiry_date", "reason"]


@pytest.fixture(autouse=True)
def _paths(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "default" / "history.db")
    monkeypatch.setattr(history, "WORKSPACES_DIR", tmp_path / "workspaces")
    monkeypatch.setattr(history, "WORKSPACE", None)
    monkeypatch.chdir(tmp_path)  # default evidence-pack paths land here


def _run(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["vulnpilot", *argv])
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return exc.value.code, captured.out, captured.err


def _two_on_one_host(tmp_path) -> Path:
    p = tmp_path / "two.csv"
    p.write_text(TWO_ON_ONE_HOST)
    return p


def _seed_breached(scan: Path, days_ago: int = 60, scan_file=None) -> int:
    """Record `scan`'s findings `days_ago` days ago, so High findings breach SLA.
    scan_file=None records no file hash (no self-comparison)."""
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    return history.record_scan(score_all(parse_nessus_csv(scan)), scan_file=scan_file,
                               recorded_at=ts)


def _exceptions(tmp_path, rows) -> Path:
    p = tmp_path / "exceptions.csv"
    with open(p, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=EXC_HEADER)
        w.writeheader()
        for r in rows:
            w.writerow({"approver": "CISO", "approved_date": "2026-01-01", "reason": "r",
                        **r})
    return p


def _v110_db(path: Path, csv_path: Path, file_hash=None) -> None:
    """A history DB exactly as v1.1.0 wrote it (no scan_date / recorded_at)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp_utc TEXT NOT NULL,
            scan_file_name TEXT, scan_file_hash TEXT, total_findings INTEGER,
            kev_count INTEGER, critical_count INTEGER, high_count INTEGER,
            findings_json TEXT);
    """)
    keys = [history._finding_key(f) for f in parse_nessus_csv(csv_path)]
    conn.execute("INSERT INTO scan_history (timestamp_utc, scan_file_hash, findings_json) "
                 "VALUES (?, ?, ?)", ("2026-01-01T09:00:00+00:00", file_hash, json.dumps(keys)))
    conn.commit()
    conn.close()


# ── A. self-comparison warning ──────────────────────────────────────────────

def test_analyze_then_verify_same_scan_warns_on_stderr_only(monkeypatch, capsys):
    rc, out, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json")
    run_id = json.loads(out)["history_id"]
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE), "--json")
    assert rc == 0
    data = json.loads(out)  # stdout is still JSON only
    assert "WARNING" not in out
    assert f"baseline (history run {run_id}) was recorded from this same scan file" in err
    assert f"--exclude-run {run_id} skips only run {run_id}" in err
    assert data["baseline_run_id"] == run_id
    assert data["history_id"] == run_id + 1


def test_warning_does_not_change_baseline_selection(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER))
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json")
    data = json.loads(out)
    assert data["baseline_run_id"] == 2  # latest run, as before
    assert data["summary"] == {"fixed": 0, "still_open": 5, "new": 0, "out_of_scope_hosts": 0}
    assert "history run 2" in err


def test_ci_retry_of_exclude_run_command_warns(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER))
    cmd = ("verify", str(SAMPLE_AFTER), "--exclude-run", "2", "--json")
    rc, out, err = _run(monkeypatch, capsys, *cmd)
    first = json.loads(out)
    assert (first["baseline_run_id"], first["history_id"]) == (1, 3)
    assert "WARNING" not in err  # baseline is a different file
    rc, out, err = _run(monkeypatch, capsys, *cmd)  # same command again
    assert rc == 0
    assert json.loads(out)["baseline_run_id"] == 3
    assert "baseline (history run 3) was recorded from this same scan file" in err
    # the warning must not promise that --exclude-run fixes a retry: excluding
    # run 3 would select run 2, analyze's recording of the same scan
    assert "--exclude-run 3 skips only run 3" in err
    assert "earlier recording of the same scan" in err
    assert "compare against the run before it" not in err


def test_different_scan_file_does_not_warn(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    rc, out, err = _run(monkeypatch, capsys, "--no-colour", "verify", str(SAMPLE_AFTER))
    assert rc == 0
    assert "WARNING" not in err + out


def test_terminal_warning_goes_to_stderr_after_report(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    rc, out, err = _run(monkeypatch, capsys, "--no-colour", "verify", str(SAMPLE))
    assert rc == 0
    assert "Remediation Verification" in out
    assert "WARNING" not in out
    assert "baseline (history run 1) was recorded from this same scan file" in err
    assert "--exclude-run 1 skips only run 1" in err


@pytest.mark.parametrize("fail_on_breach, expected", [(False, 0), (True, 2)])
def test_self_comparison_does_not_change_exit_codes(tmp_path, monkeypatch, capsys,
                                                    fail_on_breach, expected):
    scan = _two_on_one_host(tmp_path)
    _seed_breached(scan, scan_file=scan)  # same file, so verify self-compares
    argv = ["verify", str(scan), "--json"] + (["--fail-on-breach"] if fail_on_breach else [])
    rc, out, err = _run(monkeypatch, capsys, *argv)
    assert rc == expected
    assert json.loads(out)["governance"]["audit_findings"] == 2
    assert "same scan file" in err


def test_v110_rows_without_hash_never_warn(monkeypatch, capsys):
    _v110_db(history.DB_PATH, SAMPLE_AFTER, file_hash=None)
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json")
    assert rc == 0
    assert "WARNING" not in err
    data = json.loads(out)
    assert data["baseline_run_id"] == 1 and data["history_id"] == 2


def test_v110_row_with_matching_hash_warns(monkeypatch, capsys):
    _v110_db(history.DB_PATH, SAMPLE_AFTER, file_hash=history.file_sha256(SAMPLE_AFTER))
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json")
    assert rc == 0
    assert "history run 1" in err


def test_history_without_hash_column_loads_and_does_not_warn(monkeypatch, capsys):
    history.DB_PATH.parent.mkdir(parents=True)
    conn = sqlite3.connect(history.DB_PATH)
    conn.execute("CREATE TABLE scan_history (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "timestamp_utc TEXT NOT NULL, findings_json TEXT)")
    keys = [history._finding_key(f) for f in parse_nessus_csv(SAMPLE_AFTER)]
    conn.execute("INSERT INTO scan_history (timestamp_utc, findings_json) VALUES (?, ?)",
                 ("2026-01-01T09:00:00+00:00", json.dumps(keys)))
    conn.commit()
    conn.close()
    assert history.load_rows()[0]["scan_file_hash"] is None
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json")
    assert "WARNING" not in err


def test_self_comparison_respects_workspace_isolation(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER), "--workspace", "acme")
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--workspace", "globex")
    # acme's copy of SAMPLE_AFTER must not trigger a warning in globex
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json",
                        "--workspace", "globex")
    assert rc == 0
    assert "WARNING" not in err
    assert json.loads(out)["baseline_run_id"] == 1
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json",
                        "--workspace", "acme")
    assert "history run 1" in err


# ── B. unreadable exception expiry fails closed ─────────────────────────────

def _one_exception(tmp_path, expiry):
    p = _exceptions(tmp_path, [{"host": "10.0.0.1", "plugin_id": "33850", "port": "443",
                                "ticket_ref": "SEC-1", "expiry_date": expiry}])
    return load_exceptions(p)[("10.0.0.1", "33850", "443")]


@pytest.mark.parametrize("expiry", ["2026-02-30", "31st Dec", "not a date", "2026-13-01"])
def test_unreadable_expiry_is_not_valid(tmp_path, caplog, expiry):
    rec = _one_exception(tmp_path, expiry)
    assert rec.expiry_date is None and rec.expiry_unreadable
    assert rec.is_valid(date(2026, 1, 1)) is False
    assert "unrecognised expiry_date" in caplog.text
    assert "treated as expired" in caplog.text


def test_blank_expiry_still_means_no_expiry(tmp_path, caplog):
    rec = _one_exception(tmp_path, "")
    assert rec.expiry_date is None and not rec.expiry_unreadable
    assert rec.is_valid(date(2099, 1, 1)) is True
    assert "expiry_date" not in caplog.text


def test_valid_expiry_behaviour_unchanged(tmp_path):
    rec = _one_exception(tmp_path, "2026-12-31")
    assert not rec.expiry_unreadable
    assert rec.is_valid(date(2026, 12, 31)) is True
    assert rec.is_valid(date(2027, 1, 1)) is False


def test_dd_mm_reading_preserved(tmp_path):
    rec = _one_exception(tmp_path, "03/04/2099")
    assert rec.expiry_date == date(2099, 4, 3) and not rec.expiry_unreadable


def test_unreadable_approved_date_is_still_just_not_set(tmp_path, caplog):
    p = _exceptions(tmp_path, [{"host": "10.0.0.1", "plugin_id": "33850", "port": "443",
                                "ticket_ref": "SEC-1", "approved_date": "yesterday",
                                "expiry_date": ""}])
    rec = load_exceptions(p)[("10.0.0.1", "33850", "443")]
    assert rec.approved_date is None and rec.is_valid()
    assert "unrecognised approved_date 'yesterday' — treated as not set" in caplog.text


def test_unreadable_expiry_classifies_as_breached_expired():
    rec = ExceptionRecord(host="10.0.0.1", plugin_id="1", port="443", ticket_ref="SEC-1",
                          approver="CISO", approved_date=None, expiry_date=None, reason="",
                          expiry_unreadable=True)
    sla = SLAStatus(finding_key=("10.0.0.1", "1", "443"), risk="high", first_seen="2026-01-01",
                    days_open=60, sla_days=30, pct_elapsed=2.0, status="breached")
    g = classify_finding(sla, {rec.key: rec})
    assert (g.governance_status, g.audit_finding) == ("breached_expired", True)


def _covering_exceptions(tmp_path, expiry):
    return _exceptions(tmp_path, [{"host": "10.0.0.5", "plugin_id": "*", "port": "*",
                                   "ticket_ref": "SEC-9", "expiry_date": expiry}])


@pytest.mark.parametrize("expiry, rc_expected, status, audit", [
    ("2026-02-30", 2, "breached_expired", 2),    # impossible date → not valid
    ("31st Dec", 2, "breached_expired", 2),      # unreadable → not valid
    ("", 0, "breached_approved", 0),             # blank → no expiry, valid
    ("2099-12-31", 0, "breached_approved", 0),   # valid future expiry
])
def test_fail_on_breach_and_ticket_export_follow_expiry(tmp_path, monkeypatch, capsys,
                                                        expiry, rc_expected, status, audit):
    scan = _two_on_one_host(tmp_path)
    _seed_breached(scan)
    exc = _covering_exceptions(tmp_path, expiry)
    tickets = tmp_path / "tickets.json"
    rc, out, err = _run(monkeypatch, capsys, "verify", str(scan), "--json", "--fail-on-breach",
                        "--exceptions", str(exc), "--export-tickets", str(tickets),
                        "--ticket-format", "json")
    assert rc == rc_expected
    assert json.loads(out)["governance"]["audit_findings"] == audit
    records = json.loads(tickets.read_text())["records"]
    assert len(records) == audit
    for r in records:
        assert r["governance_status"] == status
        assert r["exception_ticket_ref"] == "SEC-9"
        assert r["exception_expiry"] == ""  # unreadable date is not invented


def test_terminal_marks_unreadable_expiry(tmp_path, monkeypatch, capsys):
    scan = _two_on_one_host(tmp_path)
    _seed_breached(scan)
    exc = _covering_exceptions(tmp_path, "2026-02-30")
    rc, out, err = _run(monkeypatch, capsys, "--no-colour", "verify", str(scan),
                        "--exceptions", str(exc))
    assert rc == 0
    assert out.count("SEC-9 ✗ expired (unreadable expiry date)") == 2


def test_iso_datetime_expiry_is_unreadable_and_expired(tmp_path, caplog):
    # Documents 1.2.1 behaviour: ISO datetimes are not an accepted expiry format
    # (dates only), so under fail-closed handling such an exception is expired.
    rec = _one_exception(tmp_path, "2026-12-31T00:00:00")
    assert rec.expiry_date is None and rec.expiry_unreadable
    assert rec.is_valid(date(2026, 1, 1)) is False
    assert "unrecognised expiry_date '2026-12-31T00:00:00'" in caplog.text


def test_exact_row_with_unreadable_expiry_beats_valid_wildcard(tmp_path, monkeypatch, capsys):
    # Precedence is unchanged: the exact row still applies (as an expired exact
    # row always has), so it does not fall through to the broader valid wildcard.
    scan = _two_on_one_host(tmp_path)
    _seed_breached(scan)
    exc = _exceptions(tmp_path, [
        {"host": "10.0.0.5", "plugin_id": "111", "port": "443",
         "ticket_ref": "SEC-EXACT", "expiry_date": "2026-02-30"},
        {"host": "10.0.0.5", "plugin_id": "*", "port": "*",
         "ticket_ref": "SEC-WILD", "expiry_date": "2099-12-31"},
    ])
    tickets = tmp_path / "tickets.json"
    rc, out, err = _run(monkeypatch, capsys, "verify", str(scan), "--json", "--fail-on-breach",
                        "--exceptions", str(exc), "--export-tickets", str(tickets),
                        "--ticket-format", "json")
    assert rc == 2
    gov = json.loads(out)["governance"]
    assert (gov["breached_expired"], gov["breached_approved"], gov["audit_findings"]) == (1, 1, 1)
    records = json.loads(tickets.read_text())["records"]
    assert [(r["plugin_id"], r["exception_ticket_ref"], r["governance_status"])
            for r in records] == [("111", "SEC-EXACT", "breached_expired")]


# ── C. breach detail identifies the finding ─────────────────────────────────

def _finding(plugin_id, port, cve, name):
    return Finding(plugin_id=plugin_id, cve=cve, host="10.0.0.5", port=port, protocol="tcp",
                   risk="High", cvss_v3=7.5, cvss_v2=None, name=name, synopsis="",
                   description="", solution="", references="", plugin_output="")


def _breach(plugin_id, port):
    sla = SLAStatus(finding_key=("10.0.0.5", plugin_id, port), risk="high",
                    first_seen="2026-01-01", days_open=60, sla_days=30, pct_elapsed=2.0,
                    status="breached")
    return FindingGovernance(finding_key=sla.finding_key, sla_status=sla, exception=None,
                             governance_status="breached_no_exception", audit_finding=True)


def _breach_detail(out):
    return [r.strip() for r in out.split("Breach detail:")[1].strip().splitlines()]


def test_two_same_host_same_severity_breaches_are_distinguishable():
    findings = [_finding("111", "443", "CVE-2024-0001", LONG_NAME),
                _finding("222", "8443", "", "Web Server Example Misconfiguration")]
    out = render_verify(VerifyResult(baseline_date="2026-01-01"),
                        governance=[_breach("111", "443"), _breach("222", "8443")],
                        use_colour=False, findings=findings)
    rows = _breach_detail(out)
    # the host/severity/days rows are identical — the label lines tell them apart
    assert rows[0] == rows[2]
    assert rows[1].split()[:3] == ["port", "443", "CVE-2024-0001"]
    assert rows[3].split()[:3] == ["port", "8443", "-"]
    assert "Web Server Example Misconfiguration" in rows[3]
    assert LONG_NAME not in out and LONG_NAME[:49] + "…" in rows[1]


def test_breach_label_without_findings_still_shows_port():
    out = render_verify(VerifyResult(baseline_date="2026-01-01"),
                        governance=[_breach("111", "443")], use_colour=False)
    assert _breach_detail(out)[1] == "port 443"


def test_cli_breach_detail_shows_both_findings(tmp_path, monkeypatch, capsys):
    scan = _two_on_one_host(tmp_path)
    _seed_breached(scan)
    rc, out, err = _run(monkeypatch, capsys, "--no-colour", "verify", str(scan))
    rows = _breach_detail(out)
    labels = [r for r in rows if r.startswith("port ")]
    assert len(labels) == 2
    assert any("CVE-2024-0001" in r and "443" in r for r in labels)
    assert any("Web Server Example Misconfiguration" in r and "8443" in r for r in labels)


# ── D. output write errors ──────────────────────────────────────────────────

def _assert_write_error(rc, out, err, what, json_mode):
    assert rc == 1
    assert f"ERROR: Could not write {what}" in err
    assert "Traceback" not in out + err
    if json_mode:
        assert out == ""


@pytest.mark.parametrize("json_mode", [True, False])
def test_verify_unwritable_ticket_export(tmp_path, monkeypatch, capsys, json_mode):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    target = tmp_path / "missing" / "tickets.csv"
    rc, out, err = _run(monkeypatch, capsys, "--no-colour", "verify", str(SAMPLE_AFTER),
                        "--export-tickets", str(target), *(["--json"] if json_mode else []))
    _assert_write_error(rc, out, err, "ticket export", json_mode)
    assert str(target) in err
    assert "already recorded to history as run 2" in err  # history semantics unchanged
    assert [r["id"] for r in history.load_rows()] == [1, 2]


@pytest.mark.parametrize("json_mode", [True, False])
def test_verify_unwritable_evidence_out(tmp_path, monkeypatch, capsys, json_mode):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    target = tmp_path / "missing" / "pack.md"
    rc, out, err = _run(monkeypatch, capsys, "--no-colour", "verify", str(SAMPLE_AFTER),
                        "--evidence", "soc2", "--evidence-out", str(target),
                        *(["--json"] if json_mode else []))
    _assert_write_error(rc, out, err, "evidence pack", json_mode)
    assert str(target) in err


@pytest.mark.parametrize("json_mode", [True, False])
def test_analyze_unwritable_evidence_out(tmp_path, monkeypatch, capsys, json_mode):
    target = tmp_path / "missing" / "pack.md"
    rc, out, err = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--evidence", "soc2",
                        "--evidence-out", str(target), *(["--json"] if json_mode else []))
    _assert_write_error(rc, out, err, "evidence pack", json_mode)
    assert "already recorded to history as run 1" in err


@pytest.mark.parametrize("json_mode", [True, False])
def test_analyze_unwritable_html(tmp_path, monkeypatch, capsys, json_mode):
    target = tmp_path / "missing" / "report.html"
    rc, out, err = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--html", str(target),
                        *(["--json"] if json_mode else []))
    _assert_write_error(rc, out, err, "HTML report", json_mode)
    assert str(target) in err


def test_output_path_that_is_a_directory(tmp_path, monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json",
                        "--export-tickets", str(tmp_path))
    _assert_write_error(rc, out, err, "ticket export", True)


def test_fail_on_breach_write_error_is_exit_1(tmp_path, monkeypatch, capsys):
    scan = _two_on_one_host(tmp_path)
    _seed_breached(scan)
    rc, out, err = _run(monkeypatch, capsys, "verify", str(scan), "--json", "--fail-on-breach",
                        "--export-tickets", str(tmp_path / "missing" / "t.csv"))
    _assert_write_error(rc, out, err, "ticket export", True)


def test_later_write_failure_keeps_earlier_output_and_history(tmp_path, monkeypatch, capsys):
    # History is recorded before outputs, and outputs are written in order: a
    # failed evidence write leaves the ticket export already written.
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    tickets = tmp_path / "tickets.csv"
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json",
                        "--export-tickets", str(tickets), "--evidence", "soc2",
                        "--evidence-out", str(tmp_path / "missing" / "pack.md"))
    _assert_write_error(rc, out, err, "evidence pack", True)
    assert tickets.is_file()
    assert "already recorded to history as run 2" in err
    assert [r["id"] for r in history.load_rows()] == [1, 2]


@pytest.mark.parametrize("fail_on_breach, expected", [(False, 0), (True, 2)])
def test_verify_json_when_history_cannot_be_recorded(tmp_path, monkeypatch, capsys, caplog,
                                                     fail_on_breach, expected):
    scan = _two_on_one_host(tmp_path)
    _seed_breached(scan)

    def broken_schema(conn):
        raise sqlite3.OperationalError("database is locked")
    # record_scan() swallows the failure (history must never break verify)
    monkeypatch.setattr(history, "_ensure_schema", broken_schema)
    argv = ["verify", str(scan), "--json"] + (["--fail-on-breach"] if fail_on_breach else [])
    rc, out, err = _run(monkeypatch, capsys, *argv)
    assert rc == expected  # exit codes unchanged: recording failure is not a tool error
    data = json.loads(out)
    assert data["history_id"] is None
    assert data["baseline_run_id"] == 1
    assert data["governance"]["audit_findings"] == 2
    assert "Scan was not recorded to history" in caplog.text
    assert [r["id"] for r in history.load_rows()] == [1]


# ── E. evidence metadata renders as separate lines ──────────────────────────

_META = ("Framework", "Control", "Generated", "Generated by", "Source scan file")


def _metadata_block(text):
    return text.split("\n---\n")[0].split("\n\n", 1)[1].strip().splitlines()


def test_evidence_metadata_is_one_list_item_per_field(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--evidence", "soc2",
         "--evidence-out", "pack.md")
    lines = _metadata_block(Path("pack.md").read_text())
    assert [line.split(":**")[0] for line in lines] == [f"- **{m}" for m in _META]


def test_imported_evidence_metadata_is_one_list_item_per_field(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2026-01-15",
         "--evidence", "iso27001", "--evidence-out", "pack.md")
    text = Path("pack.md").read_text()
    lines = _metadata_block(text)
    assert [line.split(":**")[0] for line in lines] == [
        f"- **{m}" for m in _META + ("Scan date (stated at import)",
                                     "Imported into VulnPilot history")]
    # the list is closed by a blank line before the rule, so '---' is not a heading underline
    assert "\n\n---\n" in text


def test_verify_evidence_metadata_is_one_list_item_per_field(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--evidence", "soc2",
         "--evidence-out", "pack.md")
    lines = _metadata_block(Path("pack.md").read_text())
    assert [line.split(":**")[0] for line in lines] == [f"- **{m}" for m in _META]


# ── F. verify colour follows the terminal ───────────────────────────────────

def _verify_out(monkeypatch, capsys, *extra, tty):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)
    rc, out, err = _run(monkeypatch, capsys, *extra, "verify", str(SAMPLE_AFTER))
    assert rc == 0
    return out


def test_verify_no_colour_when_stdout_is_not_a_tty(monkeypatch, capsys):
    assert ANSI not in _verify_out(monkeypatch, capsys, tty=False)


def test_verify_keeps_colour_on_a_tty(monkeypatch, capsys):
    assert ANSI in _verify_out(monkeypatch, capsys, tty=True)


def test_verify_no_colour_flag_still_wins_on_a_tty(monkeypatch, capsys):
    assert ANSI not in _verify_out(monkeypatch, capsys, "--no-colour", tty=True)


def test_verify_json_has_no_colour_even_on_a_tty(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json")
    assert ANSI not in out
    json.loads(out)
