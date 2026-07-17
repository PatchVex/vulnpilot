"""Tests for --fail-on-breach exit codes on the verify command.

Exit code contract:
  0 — ran successfully, no audit findings
  1 — tool error (bad file, no history, parse failure)
  2 — ran successfully, audit findings present (--fail-on-breach only)
"""
import argparse
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vulnpilot import history
from vulnpilot.cli import cmd_verify

SAMPLE_AFTER = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus_after.csv"


def _seed_history_with_breach(tmp_path):
    """Seed history with a finding that will be breached (opened >30 days ago, high severity)."""
    db = tmp_path / "history.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            scan_file_name TEXT,
            scan_file_hash TEXT,
            total_findings INTEGER,
            kev_count INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            findings_json TEXT
        );
    """)
    ts = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    finding = {"host": "192.168.1.25", "plugin_id": "64786", "port": "443",
                "cve": "", "name": "breached finding", "risk": "high",
                "score": 80.0, "kev": False, "priority": "HIGH"}
    conn.execute(
        "INSERT INTO scan_history (timestamp_utc, findings_json, "
        "total_findings, kev_count, critical_count, high_count) "
        "VALUES (?, ?, 1, 0, 0, 1)",
        (ts, json.dumps([finding]))
    )
    conn.commit()
    conn.close()
    return db


def _seed_history_clean(tmp_path):
    """Seed history with a finding that will appear resolved in the new scan."""
    db = tmp_path / "history.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            scan_file_name TEXT,
            scan_file_hash TEXT,
            total_findings INTEGER,
            kev_count INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            findings_json TEXT
        );
    """)
    ts = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    # A finding on a host not in sample_nessus_after so it doesn't create a breach
    finding = {"host": "10.255.255.1", "plugin_id": "99999", "port": "22",
                "cve": "", "name": "old resolved", "risk": "low",
                "score": 5.0, "kev": False, "priority": "LOW"}
    conn.execute(
        "INSERT INTO scan_history (timestamp_utc, findings_json, "
        "total_findings, kev_count, critical_count, high_count) "
        "VALUES (?, ?, 1, 0, 0, 0)",
        (ts, json.dumps([finding]))
    )
    conn.commit()
    conn.close()
    return db


def _args(csv, fail_on_breach=False, as_json=False):
    return argparse.Namespace(
        csv=str(csv), kev=None, epss=None,
        no_colour=True, evidence=None, evidence_out=None,
        exceptions=None, json=as_json,
        sla_config=None, fail_on_breach=fail_on_breach,
    )


class TestFailOnBreachExitCodes:
    def test_exit_1_on_missing_file(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        rc = cmd_verify(_args("/nonexistent/scan.csv", fail_on_breach=True))
        assert rc == 1

    def test_exit_1_on_no_history(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "empty.db")
        rc = cmd_verify(_args(SAMPLE_AFTER, fail_on_breach=True))
        assert rc == 1

    def test_exit_2_when_audit_findings_and_flag_set(self, tmp_path, monkeypatch, capsys):
        db = _seed_history_with_breach(tmp_path)
        monkeypatch.setattr(history, "DB_PATH", db)
        rc = cmd_verify(_args(SAMPLE_AFTER, fail_on_breach=True))
        assert rc == 2

    def test_exit_0_when_audit_findings_but_flag_not_set(self, tmp_path, monkeypatch, capsys):
        """Without --fail-on-breach, breaches do NOT change the exit code."""
        db = _seed_history_with_breach(tmp_path)
        monkeypatch.setattr(history, "DB_PATH", db)
        rc = cmd_verify(_args(SAMPLE_AFTER, fail_on_breach=False))
        assert rc == 0

    def test_exit_2_with_json_flag_and_breach(self, tmp_path, monkeypatch, capsys):
        """--fail-on-breach must also work when combined with --json."""
        db = _seed_history_with_breach(tmp_path)
        monkeypatch.setattr(history, "DB_PATH", db)
        rc = cmd_verify(_args(SAMPLE_AFTER, fail_on_breach=True, as_json=True))
        out = capsys.readouterr().out
        assert rc == 2
        data = json.loads(out)
        assert data["command"] == "verify"

    def test_exit_0_with_json_flag_no_breach(self, tmp_path, monkeypatch, capsys):
        db = _seed_history_clean(tmp_path)
        monkeypatch.setattr(history, "DB_PATH", db)
        rc = cmd_verify(_args(SAMPLE_AFTER, fail_on_breach=True, as_json=True))
        assert rc == 0
