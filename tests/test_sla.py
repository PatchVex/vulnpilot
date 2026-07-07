"""Tests for the SLA engine."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnpilot import history
from vulnpilot.sla import (
    DEFAULT_SLA, compute_sla_status, compute_all_sla,
    load_sla_config, write_default_config, SLAStatus,
)
from vulnpilot.parser.nessus import parse_nessus_csv

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"


def _make_db_with_finding(tmp_path, host, plugin_id, port, days_ago):
    """Seed a history DB with one finding seen N days ago."""
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
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    finding = {"host": host, "plugin_id": plugin_id, "port": port,
                "cve": "", "name": "test", "risk": "critical",
                "score": 100.0, "kev": True, "priority": "CRITICAL NOW"}
    conn.execute(
        "INSERT INTO scan_history (timestamp_utc, findings_json, "
        "total_findings, kev_count, critical_count, high_count) "
        "VALUES (?, ?, 1, 1, 1, 0)",
        (ts, json.dumps([finding]))
    )
    conn.commit()
    conn.close()
    return db


class FakeFinding:
    def __init__(self, host, plugin_id, port, risk):
        self.host = host
        self.plugin_id = plugin_id
        self.port = port
        self.risk = risk


def test_default_config_loads():
    cfg = load_sla_config()
    assert cfg["critical"] == 7
    assert cfg["high"] == 30


def test_write_default_config(tmp_path, monkeypatch):
    from vulnpilot import sla as sla_mod
    monkeypatch.setattr(sla_mod, "CONFIG_PATH", tmp_path / "sla.yaml")
    p = write_default_config()
    assert p.exists()
    cfg = load_sla_config()
    assert cfg["critical"] == 7


def test_within_sla(tmp_path, monkeypatch):
    from vulnpilot import sla as sla_mod
    db = _make_db_with_finding(tmp_path, "10.0.0.1", "33850", "443", 3)
    monkeypatch.setattr(history, "DB_PATH", db)
    f = FakeFinding("10.0.0.1", "33850", "443", "critical")
    result = compute_sla_status(f, {"critical": 7})
    assert result.status == "within"
    assert result.days_open == 3


def test_approaching_sla(tmp_path, monkeypatch):
    from vulnpilot import sla as sla_mod
    db = _make_db_with_finding(tmp_path, "10.0.0.1", "33850", "443", 6)
    monkeypatch.setattr(history, "DB_PATH", db)
    f = FakeFinding("10.0.0.1", "33850", "443", "critical")
    result = compute_sla_status(f, {"critical": 7})
    assert result.status == "approaching"


def test_breached_sla(tmp_path, monkeypatch):
    db = _make_db_with_finding(tmp_path, "10.0.0.1", "33850", "443", 10)
    monkeypatch.setattr(history, "DB_PATH", db)
    f = FakeFinding("10.0.0.1", "33850", "443", "critical")
    result = compute_sla_status(f, {"critical": 7})
    assert result.status == "breached"
    assert result.days_open == 10


def test_unknown_when_no_history(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "empty.db")
    f = FakeFinding("10.0.0.1", "33850", "443", "critical")
    result = compute_sla_status(f)
    assert result.status == "unknown"


def test_compute_all_sla_returns_aligned_list(tmp_path, monkeypatch):
    db = _make_db_with_finding(tmp_path, "10.0.0.1", "33850", "443", 3)
    monkeypatch.setattr(history, "DB_PATH", db)
    findings = [
        FakeFinding("10.0.0.1", "33850", "443", "critical"),
        FakeFinding("10.0.0.2", "99999", "80", "high"),
    ]
    results = compute_all_sla(findings, {"critical": 7, "high": 30})
    assert len(results) == 2
    assert results[0].status == "within"
    assert results[1].status == "unknown"
