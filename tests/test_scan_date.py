"""Tests for analyze --scan-date, the scan_date/recorded_at history columns and
migration of history databases written by v1.1.0."""
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnpilot import history
from vulnpilot.cli import main
from vulnpilot.parser.nessus import parse_nessus_csv
from vulnpilot.scoring import score_all

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"
SAMPLE_AFTER = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus_after.csv"
TODAY = datetime.now(timezone.utc).date().isoformat()

# Verbatim schema from v1.1.0 (vulnpilot/history.py at the v1.1.0 tag).
V110_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc   TEXT NOT NULL,
    scan_file_name  TEXT,
    scan_file_hash  TEXT,
    total_findings  INTEGER,
    kev_count       INTEGER,
    critical_count  INTEGER,
    high_count      INTEGER,
    findings_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_ts ON scan_history (timestamp_utc);
"""


@pytest.fixture(autouse=True)
def _paths(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "default" / "history.db")
    monkeypatch.setattr(history, "WORKSPACES_DIR", tmp_path / "workspaces")
    monkeypatch.setattr(history, "WORKSPACE", None)


def _run(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["vulnpilot", *argv])
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()
    return exc.value.code, captured.out, captured.err


def _rows(db=None):
    conn = sqlite3.connect(db or history.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM scan_history ORDER BY id")]
    conn.close()
    return rows


def _v110_db(path, n_rows=2):
    """A history DB exactly as v1.1.0 wrote it, with `n_rows` recorded scans."""
    path.parent.mkdir(parents=True, exist_ok=True)
    findings = score_all(parse_nessus_csv(SAMPLE))
    conn = sqlite3.connect(path)
    conn.executescript(V110_SCHEMA)
    for i in range(n_rows):
        ts = (datetime.now(timezone.utc) - timedelta(days=30 - i)).isoformat()
        conn.execute(
            "INSERT INTO scan_history (timestamp_utc, scan_file_name, scan_file_hash,"
            " total_findings, kev_count, critical_count, high_count, findings_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, "sample_nessus.csv", "ab" * 32, len(findings), 0, 4, 0,
             json.dumps([history._finding_key(f) for f in findings])))
    conn.commit()
    conn.close()
    return _rows(path)


# ── --scan-date storage ─────────────────────────────────────────────────────

def test_scan_date_stored_and_recorded_at_is_separate(monkeypatch, capsys):
    rc, out, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json",
                      "--scan-date", "2026-01-15")
    assert rc == 0
    [row] = _rows()
    assert row["scan_date"] == "2026-01-15"           # when the scanner ran
    assert row["recorded_at"][:10] == TODAY           # when VulnPilot wrote it
    assert row["timestamp_utc"] == row["recorded_at"]  # recording time, never the scan date
    data = json.loads(out)
    assert data["history_id"] == row["id"]
    assert data["scan_date"] == "2026-01-15"
    assert data["recorded_at"] == row["recorded_at"]


def test_without_scan_date_behaviour_unchanged(monkeypatch, capsys):
    rc, out, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json")
    assert rc == 0
    [row] = _rows()
    assert row["scan_date"] is None                   # never inferred
    assert row["recorded_at"] == row["timestamp_utc"]
    assert row["timestamp_utc"][:10] == TODAY
    data = json.loads(out)
    assert data["scan_date"] is None and data["recorded_at"] == row["recorded_at"]
    for key in ("command", "scan_file", "total_findings", "findings", "history_id"):
        assert key in data
    rc, out, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    assert f"History run ID: {row['id'] + 1}\n" in out  # no "imported" suffix


def test_terminal_output_marks_imported_run(monkeypatch, capsys):
    rc, out, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2026-01-15")
    assert f"History run ID: 1 (imported; scan date 2026-01-15, recorded {TODAY})" in out


@pytest.mark.parametrize("bad", [
    "2026/01/15", "15-01-2026", "yesterday", "2026-1-5", "20260115", "2026-01-15T00:00",
    "2026-02-30", "2026-13-01", "2025-02-29",
    (datetime.now(timezone.utc).date() + timedelta(days=2)).isoformat(),
])
def test_invalid_scan_date_rejected_without_history_row(tmp_path, monkeypatch, capsys, bad):
    rc, out, err = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json",
                        f"--scan-date={bad}")
    assert rc == 1
    assert out == ""
    assert "ERROR: --scan-date" in err
    assert not history.DB_PATH.exists()


def test_scan_date_is_not_a_verify_option(monkeypatch, capsys):
    rc, _, err = _run(monkeypatch, capsys, "verify", str(SAMPLE), "--scan-date", "2026-01-15")
    assert rc == 1 and "unrecognized arguments" in err  # usage error = tool error


def _verify_json(monkeypatch, capsys, csv):
    rc, out, _ = _run(monkeypatch, capsys, "verify", str(csv), "--json")
    assert rc == 0
    return json.loads(out)


def test_import_is_ordered_as_a_newly_recorded_run(monkeypatch, capsys):
    # A scan recorded normally, then an older scan imported today: the import is
    # the most recent run, so it is the next verify baseline — by recording
    # order, not because of its scan date.
    _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER))
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2026-01-15")
    assert [r["id"] for r in history.load_rows()] == [1, 2]
    data = _verify_json(monkeypatch, capsys, SAMPLE_AFTER)
    assert data["baseline_date"] == TODAY               # recording date of run 2
    assert data["summary"]["fixed"] == 1                # compared against the import


def test_scan_date_does_not_affect_order_or_baseline(monkeypatch, capsys):
    # Imported in the order later-scan-date, earlier-scan-date: insertion order wins.
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2026-03-01")
    _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER), "--scan-date", "2026-02-01")
    rows = history.load_rows()
    assert [(r["id"], r["scan_date"]) for r in rows] == [(1, "2026-03-01"), (2, "2026-02-01")]
    data = _verify_json(monkeypatch, capsys, SAMPLE_AFTER)
    assert data["summary"] == {"fixed": 0, "still_open": 5, "new": 0,
                               "out_of_scope_hosts": 0}  # baseline = run 2


def test_same_scan_date_imports_are_deterministically_ordered(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER), "--scan-date", "2026-01-15")
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2026-01-15")
    assert [r["id"] for r in history.load_rows()] == [1, 2]
    data = _verify_json(monkeypatch, capsys, SAMPLE_AFTER)
    assert data["summary"]["fixed"] == 1  # always run 2 (SAMPLE), never ambiguous


def test_order_is_by_id_even_if_timestamps_disagree(monkeypatch, capsys):
    # e.g. a clock set backwards between runs: id (insertion) order is authoritative
    _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER))
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    conn = sqlite3.connect(history.DB_PATH)
    conn.execute("UPDATE scan_history SET timestamp_utc = '2020-01-01T00:00:00+00:00' "
                 "WHERE id = 2")
    conn.commit()
    conn.close()
    assert [r["id"] for r in history.load_rows()] == [1, 2]
    assert _verify_json(monkeypatch, capsys, SAMPLE_AFTER)["summary"]["fixed"] == 1


def test_sla_first_seen_is_recording_time_not_scan_date(monkeypatch, capsys):
    # Product decision (unchanged from v1.1.0): an SLA clock starts when VulnPilot
    # first records a finding. Importing a January scan does not backdate clocks
    # or create breaches.
    from vulnpilot.sla import compute_all_sla
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2025-01-15")
    [row] = history.load_rows()
    statuses = compute_all_sla(score_all(parse_nessus_csv(SAMPLE)), {"critical": 7,
                               "high": 30, "medium": 90, "low": 180})
    assert statuses and all(st.first_seen == row["recorded_at"][:10] == TODAY
                            for st in statuses)
    assert all(st.status == "within" for st in statuses)
    data = _verify_json(monkeypatch, capsys, SAMPLE)
    assert data["governance"]["breached_no_exception"] == 0
    assert data["governance"]["within_sla"] == data["summary"]["still_open"]


# ── workspaces ──────────────────────────────────────────────────────────────

def test_scan_date_in_workspace_is_isolated(tmp_path, monkeypatch, capsys):
    rc, _, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--workspace", "client-a",
                    "--scan-date", "2026-01-15")
    assert rc == 0
    [row] = _rows(tmp_path / "workspaces" / "client-a" / "history.db")
    assert row["scan_date"] == "2026-01-15"
    assert not (tmp_path / "workspaces" / "client-b").exists()
    assert not (tmp_path / "default" / "history.db").exists()


def test_workspace_no_history_messages_include_workspace(monkeypatch, capsys):
    rc, _, err = _run(monkeypatch, capsys, "verify", str(SAMPLE), "--workspace", "client-a")
    assert rc == 1
    assert "'vulnpilot analyze <scan.csv> --workspace client-a'" in err
    rc, out, _ = _run(monkeypatch, capsys, "trend", "--workspace", "client-a")
    assert "'vulnpilot analyze <scan.csv> --workspace client-a'" in out


def test_default_no_history_messages_unchanged(monkeypatch, capsys):
    rc, _, err = _run(monkeypatch, capsys, "verify", str(SAMPLE))
    assert "'vulnpilot analyze <scan.csv>' at least once" in err


# ── migration of v1.1.0 databases ───────────────────────────────────────────

def test_v110_database_migrates_on_first_write(monkeypatch, capsys):
    before = _v110_db(history.DB_PATH)
    rc, out, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER), "--json",
                      "--scan-date", "2026-01-15")
    assert rc == 0
    after = _rows()
    # existing rows, IDs and findings untouched; new columns NULL, not back-filled
    for old, new in zip(before, after):
        assert {k: new[k] for k in old} == old
        assert new["scan_date"] is None and new["recorded_at"] is None
    assert [r["id"] for r in after] == [1, 2, 3]
    assert json.loads(out)["history_id"] == 3


def test_readers_work_on_unmigrated_v110_database_without_writing(monkeypatch, capsys):
    before = _v110_db(history.DB_PATH)
    rows = history.load_rows()
    assert [r["id"] for r in rows] == [1, 2]
    assert all(r["scan_date"] is None and r["recorded_at"] is None for r in rows)
    assert len(history.get_trend_rows()) == 2
    assert history.imported_count() == 0
    rc, out, _ = _run(monkeypatch, capsys, "trend")
    assert rc == 0 and "imported" not in out
    conn = sqlite3.connect(history.DB_PATH)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(scan_history)")]
    conn.close()
    assert "scan_date" not in cols  # reading never alters the schema
    assert _rows() == before


def test_migration_is_idempotent(tmp_path):
    for db in (tmp_path / "old.db", tmp_path / "new.db"):
        if db.name == "old.db":
            _v110_db(db)
        conn = sqlite3.connect(db)
        history._ensure_schema(conn)
        history._ensure_schema(conn)  # second run must not fail
        cols = [r[1] for r in conn.execute("PRAGMA table_info(scan_history)")]
        conn.close()
        assert cols.count("scan_date") == 1 and cols.count("recorded_at") == 1


def test_workspace_v110_database_migrates(tmp_path, monkeypatch, capsys):
    db = tmp_path / "workspaces" / "client-a" / "history.db"
    before = _v110_db(db)
    rc, _, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--workspace", "client-a")
    assert rc == 0
    after = _rows(db)
    assert [r["id"] for r in after] == [1, 2, 3]
    assert {k: after[0][k] for k in before[0]} == before[0]


def test_legacy_rows_still_serve_as_verify_baseline(monkeypatch, capsys):
    _v110_db(history.DB_PATH)
    rc, out, _ = _run(monkeypatch, capsys, "--no-colour", "verify", str(SAMPLE_AFTER))
    assert rc == 0
    assert "Verified fixed" in out
    assert "(imported" not in out


# ── provenance in trend, verify and evidence ────────────────────────────────

def test_trend_shows_recording_date_and_scan_date_separately(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER))
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2026-01-15")
    rc, out, _ = _run(monkeypatch, capsys, "trend")
    lines = [ln for ln in out.splitlines() if ln.startswith("  20")]
    # recording order; Date column is the recording date for both rows
    assert lines[0].startswith(f"  {TODAY}") and "imported" not in lines[0]
    assert lines[1].startswith(f"  {TODAY}")
    assert lines[1].endswith("imported; scan date 2026-01-15")
    assert "2026-01-15" not in lines[1][:12]
    assert "Date is when VulnPilot recorded each run" in out


def test_verify_labels_an_imported_baseline(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2026-01-15")
    rc, out, _ = _run(monkeypatch, capsys, "--no-colour", "verify", str(SAMPLE_AFTER))
    assert f"Baseline scan: {TODAY} (imported; scan date 2026-01-15)" in out


def test_evidence_distinguishes_scan_date_from_import_time(tmp_path, monkeypatch, capsys):
    pack = tmp_path / "pack.md"
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2026-01-15",
         "--evidence", "soc2", "--evidence-out", str(pack))
    text = pack.read_text()
    assert "**Scan date (stated at import):** 2026-01-15" in text
    assert f"**Imported into VulnPilot history:** {TODAY}" in text
    assert "1 of these run(s) were imported later with a stated scan date" in text

    pack2 = tmp_path / "pack2.md"
    _run(monkeypatch, capsys, "--no-colour", "verify", str(SAMPLE_AFTER),
         "--evidence", "soc2", "--evidence-out", str(pack2))
    text2 = pack2.read_text()
    assert f"against baseline scan {TODAY}; imported, stated scan date 2026-01-15" in text2
    assert "Scan date (stated at import)" not in text2  # this scan was not imported


def test_evidence_without_scan_date_has_no_import_lines(tmp_path, monkeypatch, capsys):
    pack = tmp_path / "pack.md"
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--evidence", "soc2",
         "--evidence-out", str(pack))
    text = pack.read_text()
    assert "stated at import" not in text and "imported" not in text


# ── invariant: --scan-date never backdates SLA first-seen ───────────────────

def test_verify_days_open_ignores_imported_scan_date(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2024-06-01")
    data = _verify_json(monkeypatch, capsys, SAMPLE)
    assert data["still_open"] and all(d["days_open"] == 0 for d in data["still_open"])


def test_first_seen_follows_recording_order_across_normal_and_imported_runs(monkeypatch, capsys):
    from vulnpilot.sla import compute_all_sla
    # A normal run recorded 10 days ago, then an import stating a much older scan date.
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    conn = sqlite3.connect(history.DB_PATH)
    conn.execute("UPDATE scan_history SET timestamp_utc = ?, recorded_at = ? WHERE id = 1",
                 (ten_days_ago, ten_days_ago))
    conn.commit()
    conn.close()
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2020-01-01")
    statuses = compute_all_sla(score_all(parse_nessus_csv(SAMPLE)),
                               {"critical": 7, "high": 30, "medium": 90, "low": 180})
    # first seen = the earlier *recording* (10 days ago), not the 2020 scan date
    assert all(st.first_seen == ten_days_ago[:10] and st.days_open == 10 for st in statuses)



# ── --scan-date "future" is judged by the local date, not UTC ───────────────

def test_local_today_accepted_while_utc_is_still_yesterday(monkeypatch):
    import datetime as dt
    import vulnpilot.cli as cli

    class UtcStillYesterday(dt.datetime):
        @classmethod
        def now(cls, tz=None):  # 21:30 UTC on 25 Sep = 03:00 on 26 Sep in IST
            return dt.datetime(2026, 9, 25, 21, 30, tzinfo=dt.timezone.utc)

    monkeypatch.setattr(dt, "datetime", UtcStillYesterday)
    monkeypatch.setattr(cli, "_local_today", lambda: dt.date(2026, 9, 26))
    assert cli._parse_scan_date("2026-09-26") == "2026-09-26"   # local today: accepted
    with pytest.raises(ValueError, match="2026-09-27 is in the future"):
        cli._parse_scan_date("2026-09-27")                      # local tomorrow: rejected


def test_scan_date_future_check_through_cli(tmp_path, monkeypatch, capsys):
    import datetime as dt
    import vulnpilot.cli as cli
    monkeypatch.setattr(cli, "_local_today", lambda: dt.date(2026, 9, 26))
    rc, out, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json",
                      "--scan-date", "2026-09-26")
    assert rc == 0 and json.loads(out)["scan_date"] == "2026-09-26"
    rc, out, err = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json",
                        "--scan-date", "2026-09-27")
    assert rc == 1 and out == "" and "is in the future" in err
