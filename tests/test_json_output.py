"""Tests for --json output flag on analyze and verify commands."""
import argparse
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vulnpilot import history
from vulnpilot.cli import cmd_analyze, cmd_verify

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"
SAMPLE_AFTER = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus_after.csv"


def _seed_history(tmp_path, scan_file):
    """Seed a minimal history DB so verify has a baseline."""
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
    ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    # one finding that will appear in sample_nessus_after.csv as still_open
    finding = {"host": "192.168.1.25", "plugin_id": "64786", "port": "443",
                "cve": "", "name": "test", "risk": "critical",
                "score": 100.0, "kev": False, "priority": "HIGH"}
    conn.execute(
        "INSERT INTO scan_history (timestamp_utc, findings_json, "
        "total_findings, kev_count, critical_count, high_count) "
        "VALUES (?, ?, 1, 0, 1, 0)",
        (ts, json.dumps([finding]))
    )
    conn.commit()
    conn.close()
    return db


class TestAnalyzeJson:
    def _args(self, **kwargs):
        defaults = dict(
            csv=str(SAMPLE), kev=None, epss=None,
            no_colour=True, evidence=None, evidence_out=None,
            html=None, all=False, license=None,
            top_hosts=10, json=True, sla_config=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_json_flag_produces_valid_json(self, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        rc = cmd_analyze(self._args())
        captured = capsys.readouterr()
        assert rc == 0
        data = json.loads(captured.out)
        assert data["command"] == "analyze"

    def test_json_contains_findings_list(self, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        cmd_analyze(self._args())
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) > 0

    def test_json_finding_has_required_fields(self, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        cmd_analyze(self._args())
        finding = json.loads(capsys.readouterr().out)["findings"][0]
        for field in ("plugin_id", "name", "host", "risk", "priority_score",
                      "priority_label", "kev_match"):
            assert field in finding, f"missing field: {field}"

    def test_json_sorted_by_priority_score(self, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        cmd_analyze(self._args())
        findings = json.loads(capsys.readouterr().out)["findings"]
        scores = [f["priority_score"] for f in findings]
        assert scores == sorted(scores, reverse=True)

    def test_json_suppresses_terminal_output(self, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        cmd_analyze(self._args())
        out = capsys.readouterr().out
        # terminal renderer uses box-drawing chars; JSON must not contain them
        assert "━" not in out
        assert "VulnPilot" not in out

    def test_no_json_flag_produces_terminal_output(self, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        args = self._args(json=False)
        cmd_analyze(args)
        out = capsys.readouterr().out
        assert "VulnPilot" in out


class TestVerifyJson:
    def _args(self, tmp_path, **kwargs):
        db = _seed_history(tmp_path, SAMPLE)
        defaults = dict(
            csv=str(SAMPLE_AFTER), kev=None, epss=None,
            no_colour=True, evidence=None, evidence_out=None,
            exceptions=None, json=True, sla_config=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults), db

    def test_json_flag_produces_valid_json(self, capsys, tmp_path, monkeypatch):
        args, db = self._args(tmp_path)
        monkeypatch.setattr(history, "DB_PATH", db)
        rc = cmd_verify(args)
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["command"] == "verify"

    def test_json_contains_summary(self, capsys, tmp_path, monkeypatch):
        args, db = self._args(tmp_path)
        monkeypatch.setattr(history, "DB_PATH", db)
        cmd_verify(args)
        data = json.loads(capsys.readouterr().out)
        for key in ("fixed", "still_open", "new", "out_of_scope_hosts"):
            assert key in data["summary"]

    def test_json_contains_governance(self, capsys, tmp_path, monkeypatch):
        args, db = self._args(tmp_path)
        monkeypatch.setattr(history, "DB_PATH", db)
        cmd_verify(args)
        data = json.loads(capsys.readouterr().out)
        assert "governance" in data
        assert "audit_findings" in data["governance"]

    def test_json_contains_findings(self, capsys, tmp_path, monkeypatch):
        args, db = self._args(tmp_path)
        monkeypatch.setattr(history, "DB_PATH", db)
        cmd_verify(args)
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) > 0

    def test_json_suppresses_terminal_output(self, capsys, tmp_path, monkeypatch):
        args, db = self._args(tmp_path)
        monkeypatch.setattr(history, "DB_PATH", db)
        cmd_verify(args)
        out = capsys.readouterr().out
        assert "━" not in out
        assert "Remediation Verification" not in out


class TestSlaConfig:
    def _analyze_args(self, sla_config_path, tmp_path):
        return argparse.Namespace(
            csv=str(SAMPLE), kev=None, epss=None,
            no_colour=True, evidence=None, evidence_out=None,
            html=None, all=False, license=None,
            top_hosts=10, json=True, sla_config=str(sla_config_path),
        )

    def test_custom_sla_config_loaded(self, tmp_path, capsys, monkeypatch):
        """A tighter SLA config file should be used when --sla-config is passed."""
        cfg = tmp_path / "custom_sla.yaml"
        cfg.write_text("critical: 1\nhigh: 7\nmedium: 30\nlow: 60\n")
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        rc = cmd_analyze(self._analyze_args(cfg, tmp_path))
        assert rc == 0  # config loads without error, analyze completes

    def test_missing_sla_config_falls_back_to_defaults(self, tmp_path, capsys, monkeypatch):
        """A nonexistent --sla-config path should fall back to defaults, not crash."""
        from vulnpilot.sla import load_sla_config, DEFAULT_SLA
        result = load_sla_config(tmp_path / "nonexistent.yaml")
        assert result == DEFAULT_SLA

    def test_partial_sla_config_merges_with_defaults(self, tmp_path):
        """A config with only some keys should merge, not replace, defaults."""
        from vulnpilot.sla import load_sla_config, DEFAULT_SLA
        cfg = tmp_path / "partial.yaml"
        cfg.write_text("critical: 3\n")
        result = load_sla_config(cfg)
        assert result["critical"] == 3
        assert result["high"] == DEFAULT_SLA["high"]
        assert result["medium"] == DEFAULT_SLA["medium"]


class TestJsonDoesNotSkipOutputFiles:
    def test_analyze_json_still_writes_html(self, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        out = tmp_path / "report.html"
        rc = cmd_analyze(TestAnalyzeJson()._args(html=str(out)))
        captured = capsys.readouterr()
        assert rc == 0
        assert out.exists()
        json.loads(captured.out)  # stdout stays pure JSON
        assert "HTML report saved" in captured.err

    def test_verify_json_still_writes_evidence(self, capsys, tmp_path, monkeypatch):
        args, db = TestVerifyJson()._args(
            tmp_path, evidence="soc2", evidence_out=str(tmp_path / "ev.md"))
        monkeypatch.setattr(history, "DB_PATH", db)
        rc = cmd_verify(args)
        captured = capsys.readouterr()
        assert rc == 0
        assert (tmp_path / "ev.md").exists()
        json.loads(captured.out)
        assert "Evidence pack" in captured.err

    def test_verify_missing_exceptions_file_is_an_error(self, capsys, tmp_path, monkeypatch):
        args, db = TestVerifyJson()._args(
            tmp_path, exceptions=str(tmp_path / "nope.csv"))
        monkeypatch.setattr(history, "DB_PATH", db)
        assert cmd_verify(args) == 1
        assert "Exceptions file not found" in capsys.readouterr().err

    def test_verify_invalid_exceptions_file_is_an_error(self, capsys, tmp_path, monkeypatch):
        bad = tmp_path / "bad.csv"
        bad.write_text("hostname,ticket\n10.0.0.1,JIRA-1\n")
        args, db = TestVerifyJson()._args(tmp_path, exceptions=str(bad))
        monkeypatch.setattr(history, "DB_PATH", db)
        assert cmd_verify(args) == 1
        assert "missing required column" in capsys.readouterr().err


class TestAnalyzeNoActionableFindings:
    CSV = ("Plugin ID,CVE,Risk,Host,Protocol,Port,Name\n"
           "19506,,None,10.0.0.1,tcp,0,Nessus Scan Information\n")

    def test_json_stdout_is_valid_json_and_diagnostic_on_stderr(self, capsys, tmp_path,
                                                                monkeypatch):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        info_only = tmp_path / "info.csv"
        info_only.write_text(self.CSV)
        rc = cmd_analyze(TestAnalyzeJson()._args(csv=str(info_only)))
        captured = capsys.readouterr()
        assert rc == 0
        data = json.loads(captured.out)
        assert data == {"command": "analyze", "scan_file": str(info_only),
                        "total_findings": 0, "findings": [], "history_id": None,
                        "scan_date": None, "recorded_at": None}
        assert "No actionable findings" in captured.err

    def test_terminal_mode_unchanged(self, capsys, tmp_path, monkeypatch):
        monkeypatch.setattr(history, "DB_PATH", tmp_path / "h.db")
        info_only = tmp_path / "info.csv"
        info_only.write_text(self.CSV)
        rc = cmd_analyze(TestAnalyzeJson()._args(csv=str(info_only), json=False))
        captured = capsys.readouterr()
        assert rc == 0
        assert captured.out == "\n  No actionable findings in this CSV.\n"
        assert captured.err == ""
