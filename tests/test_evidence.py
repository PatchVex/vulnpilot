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
    with pytest.raises(ValueError, match="pci"):
        generate_evidence_pack(_scored(), "pci", output_path=tmp_path / "x.md")


def test_iso27001_evidence_pack_generates(tmp_path):
    out = generate_evidence_pack(_scored(), "iso27001",
                                 scan_file=SAMPLE,
                                 output_path=tmp_path / "iso_pack.md")
    text = out.read_text()
    assert "Annex A 8.8" in text
    assert "ISO/IEC 27001:2022" in text
    assert "Management of Technical Vulnerabilities" in text
    assert "CISA KEV matches (confirmed exploited in the wild) | 2" in text
    assert "sign-off" in text.lower()


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


def test_governance_section_appears_when_summary_provided(tmp_path):
    gs = {
        "within_sla": 41,
        "breached_approved": 1,
        "breached_expired": 1,
        "breached_no_exception": 2,
        "unknown": 3,
        "audit_findings": 3,
    }
    out = generate_evidence_pack(_scored(), "soc2",
                                 scan_file=SAMPLE,
                                 output_path=tmp_path / "gov.md",
                                 governance_summary=gs)
    text = out.read_text()
    assert "4c. SLA compliance and exception register" in text
    assert "Within SLA | 41" in text
    assert "Breached — approved exception | 1" in text
    assert "Breached — no exception on file | 2" in text
    assert "No history data" in text        # unknown row shown when non-zero
    assert "Audit findings requiring action: 3" in text
    # must not contain framework-specific wording inside the governance block
    assert "SOC 2"      not in text.split("4c.")[1].split("## 5.")[0]
    assert "ISO 27001"  not in text.split("4c.")[1].split("## 5.")[0]


def test_governance_section_absent_when_not_provided(tmp_path):
    out = generate_evidence_pack(_scored(), "soc2",
                                 scan_file=SAMPLE,
                                 output_path=tmp_path / "nogov.md")
    text = out.read_text()
    assert "4c. SLA compliance" not in text


def test_governance_section_no_audit_findings_message(tmp_path):
    gs = {
        "within_sla": 10,
        "breached_approved": 1,
        "breached_expired": 0,
        "breached_no_exception": 0,
        "unknown": 0,
        "audit_findings": 0,
    }
    out = generate_evidence_pack(_scored(), "iso27001",
                                 scan_file=SAMPLE,
                                 output_path=tmp_path / "clean.md",
                                 governance_summary=gs)
    text = out.read_text()
    assert "No audit findings" in text
    assert "No history data"   not in text   # unknown=0, row suppressed


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
