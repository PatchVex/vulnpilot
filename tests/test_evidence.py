import sqlite3
from pathlib import Path

import pytest

from vulnpilot.parser.nessus import parse_nessus_csv
from vulnpilot.scoring import score_all
from vulnpilot import history
from vulnpilot.evidence import generate_evidence_pack

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"


def _scored():
    findings = parse_nessus_csv(SAMPLE)
    # simulate enrichment for the two KEV CVEs so tests don't need network
    for f in findings:
        f.kev_match = f.cve in ("CVE-2021-44228", "CVE-2020-1472")
        f.epss_score = 0.95 if f.kev_match else 0.01
    return score_all(findings)


def test_evidence_pack_generates(tmp_path):
    out = generate_evidence_pack(_scored(), "soc2",
                                 scan_file=SAMPLE,
                                 output_path=tmp_path / "pack.md")
    text = out.read_text()
    assert "CC7.1" in text
    assert "CISA KEV matches (confirmed exploited in the wild) | 2" in text
    assert "YES" in text
    assert "sign-off" in text.lower()


def test_evidence_rejects_unknown_framework(tmp_path):
    with pytest.raises(ValueError):
        generate_evidence_pack(_scored(), "pci", output_path=tmp_path / "x.md")


def test_history_records_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "history.db")
    row_id = history.record_scan(_scored(), scan_file=SAMPLE)
    assert row_id == 1
    conn = sqlite3.connect(tmp_path / "history.db")
    total, kev = conn.execute(
        "SELECT total_findings, kev_count FROM scan_history").fetchone()
    assert total == 6 and kev == 2
    assert history.scan_count() == 1


def test_history_never_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", Path("/nonexistent/dir/x.db"))
    assert history.record_scan(_scored()) is None


def test_evidence_pack_with_verification(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "history.db")
    from vulnpilot.verify import verify_scan

    history.record_scan(_scored(), scan_file=SAMPLE)
    # remediate one finding, drop one host entirely
    new = [f for f in _scored()
           if f.cve != "CVE-2021-44228" and f.host != "192.168.1.15"]
    result = verify_scan(new)

    out = generate_evidence_pack(new, "soc2", scan_file=SAMPLE,
                                 output_path=tmp_path / "p.md",
                                 verify_result=result)
    text = out.read_text()
    assert "4b. Remediation verification" in text
    assert "CVE-2021-44228" in text            # in verified-fixed table
    assert "192.168.1.15" in text              # scope note
    assert "never counted as remediated" in text
