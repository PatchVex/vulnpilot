import json
from pathlib import Path

import pytest

from vulnpilot.parser.nessus import parse_nessus_csv
from vulnpilot.scoring import score_all
from vulnpilot import history
from vulnpilot.verify import verify_scan

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
