"""
tests/test_core.py
Run with: python -m pytest tests/ -v
"""
import sys
import tempfile
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnpilot.parser.nessus import parse_nessus_csv, Finding
from vulnpilot.scoring.engine import score_finding, score_all, ScoringConfig

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"


class TestParser:
    def test_parses_sample(self):
        assert len(parse_nessus_csv(SAMPLE)) > 0

    def test_skips_none_risk(self):
        for f in parse_nessus_csv(SAMPLE):
            assert f.risk.lower() != "none"

    def test_has_host(self):
        for f in parse_nessus_csv(SAMPLE):
            assert f.host != ""

    def test_cve_parsed(self):
        findings = parse_nessus_csv(SAMPLE)
        log4shell = [f for f in findings if "44228" in f.cve]
        assert len(log4shell) > 0
        assert "CVE-2021-44228" in log4shell[0].cve_list

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_nessus_csv(Path("/nonexistent/path.csv"))

    def test_invalid_csv(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
            f.write("col1,col2\nval1,val2\n")
            tmp = Path(f.name)
        with pytest.raises(ValueError):
            parse_nessus_csv(tmp)
        tmp.unlink()


class TestScoring:
    def _f(self, **kw) -> Finding:
        d = dict(plugin_id="1", cve="CVE-2021-44228", cvss_v3=9.8, cvss_v2=None,
                 risk="Critical", host="10.0.0.1", port="443", protocol="tcp",
                 name="Test", synopsis="", description="", solution="", references="", plugin_output="")
        d.update(kw)
        return Finding(**d)

    def test_kev_raises_score(self):
        assert score_finding(self._f(kev_match=True, epss_score=0.0)) > score_finding(self._f(kev_match=False, epss_score=0.0))

    def test_kev_floor(self):
        assert score_finding(self._f(kev_match=True, epss_score=0.0, cvss_v3=0.0, risk="Low")) >= 75.0

    def test_score_capped(self):
        assert score_finding(self._f(kev_match=True, epss_score=1.0, cvss_v3=10.0)) <= 100.0

    def test_sorted_descending(self):
        findings = parse_nessus_csv(SAMPLE)
        scored = score_all(findings)
        scores = [f.priority_score for f in scored]
        assert scores == sorted(scores, reverse=True)

    def test_free_tier_limit(self):
        assert len(score_all(parse_nessus_csv(SAMPLE), limit=3)) <= 3

    def test_deterministic(self):
        r1 = [f.name for f in score_all(parse_nessus_csv(SAMPLE))]
        r2 = [f.name for f in score_all(parse_nessus_csv(SAMPLE))]
        assert r1 == r2
