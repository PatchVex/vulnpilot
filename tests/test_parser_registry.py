"""The CLI parses through the scanner registry (vulnpilot.parser.parse), and
Nessus CSV behaviour through the registry matches parse_nessus_csv()."""
import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

import pytest

import vulnpilot.cli as cli
import vulnpilot.parser as parser_pkg
from vulnpilot import history
from vulnpilot.parser import Finding, Scanner, parse, parse_nessus_csv
from vulnpilot.parser.nessus import NessusScanner

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"
SAMPLE_AFTER = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus_after.csv"


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "history.db")


def _analyze_args(csv, tmp_path, **kw):
    d = dict(csv=str(csv), kev=str(tmp_path / "no_kev.json"), epss=str(tmp_path / "no_epss.gz"),
             no_colour=True, evidence=None, evidence_out=None, html=None, all=False,
             license=None, top_hosts=10, json=True, sla_config=None, scan_date=None)
    d.update(kw)
    return argparse.Namespace(**d)


def _verify_args(csv, tmp_path, **kw):
    d = dict(csv=str(csv), kev=str(tmp_path / "no_kev.json"), epss=str(tmp_path / "no_epss.gz"),
             no_colour=True, evidence=None, evidence_out=None, exceptions=None, json=True,
             sla_config=None, fail_on_breach=False, export_tickets=None,
             ticket_format="generic-csv", exclude_run=None)
    d.update(kw)
    return argparse.Namespace(**d)


# ── A / E: Nessus through the registry is identical ────────────────────────

@pytest.mark.parametrize("csv", [SAMPLE, SAMPLE_AFTER])
def test_parse_matches_direct_nessus_parser(csv):
    assert [vars(f) for f in parse(csv)] == [vars(f) for f in parse_nessus_csv(csv)]


@pytest.mark.parametrize("name,prefix", [
    ("scan.txt", b""),                  # extension is not required
    ("scan", b""),                      # no extension
    ("scan.CSV", b""),
    ("bom.csv", b"\xef\xbb\xbf"),       # Excel BOM
    ("preamble.csv", b"x" * 5000 + b"\n"),  # header beyond the first 4 KB
])
def test_every_file_the_nessus_parser_reads_is_accepted(tmp_path, name, prefix):
    p = tmp_path / name
    p.write_bytes(prefix + SAMPLE.read_bytes())
    assert NessusScanner().accepts(p)
    assert [vars(f) for f in parse(p)] == [vars(f) for f in parse_nessus_csv(p)]


# ── H: error behaviour ──────────────────────────────────────────────────────

def test_parse_missing_file_raises_file_not_found_like_direct_parser(tmp_path):
    missing = tmp_path / "missing.csv"
    with pytest.raises(FileNotFoundError, match=f"CSV not found: {missing}"):
        parse(missing)
    with pytest.raises(FileNotFoundError, match=f"CSV not found: {missing}"):
        parse_nessus_csv(missing)


@pytest.mark.parametrize("content", [b"a,b,c\n1,2,3\n", b""])
def test_unrecognised_file_error_keeps_expected_columns_hint(tmp_path, content):
    p = tmp_path / "other.csv"
    p.write_bytes(content)
    assert not NessusScanner().accepts(p)
    with pytest.raises(ValueError) as exc:
        parse(p)
    assert "No supported scanner can parse" in str(exc.value)
    assert "expected columns: Plugin ID, Risk, Host, CVE" in str(exc.value)


def test_undecodable_file_raises_same_error_as_direct_parser(tmp_path):
    p = tmp_path / "latin.csv"
    p.write_bytes(SAMPLE.read_bytes().replace(b"Log4j", b"Log\xe94j", 1))
    with pytest.raises(UnicodeDecodeError) as via_registry:
        parse(p)
    with pytest.raises(UnicodeDecodeError) as direct:
        parse_nessus_csv(p)
    assert str(via_registry.value) == str(direct.value)


@pytest.mark.parametrize("command", ["analyze", "verify"])
def test_cli_errors_stay_clean(tmp_path, capsys, command):
    run = cli.cmd_analyze if command == "analyze" else cli.cmd_verify
    make = _analyze_args if command == "analyze" else _verify_args
    (tmp_path / "dir.csv").mkdir()
    (tmp_path / "other.csv").write_text("a,b,c\n1,2,3\n")
    cases = {"missing.csv": "ERROR: CSV not found:",
             "other.csv": "ERROR: No supported scanner can parse:",
             "dir.csv": "ERROR: Cannot read"}  # was a traceback before Phase 1
    for name, expected in cases.items():
        rc = run(make(tmp_path / name, tmp_path))
        captured = capsys.readouterr()
        assert rc == 1, name
        assert expected in captured.err, name
        assert captured.out == "", name


# ── B / C / D: the CLI goes through the registry ────────────────────────────

class _FakeScanner(Scanner):
    """Test-only scanner: accepts *.fake files and returns one fixed finding."""

    def accepts(self, path: Path) -> bool:
        return path.suffix == ".fake"

    def parse(self, path: Path) -> List[Finding]:
        return [Finding(plugin_id="999001", cve="", host="10.9.9.9", port="8443",
                        protocol="tcp", risk="High", cvss_v3=7.5, cvss_v2=None,
                        name="Fake scanner finding", synopsis="", description="",
                        solution="", references="", plugin_output="")]


@pytest.fixture
def fake_registry(monkeypatch):
    monkeypatch.setattr(parser_pkg, "_SCANNERS", [_FakeScanner(), NessusScanner()])


def test_analyze_uses_the_registry(tmp_path, capsys, fake_registry):
    scan = tmp_path / "scan.fake"
    scan.write_text("not a Nessus file")
    assert cli.cmd_analyze(_analyze_args(scan, tmp_path)) == 0
    data = json.loads(capsys.readouterr().out)
    assert [f["name"] for f in data["findings"]] == ["Fake scanner finding"]


def test_verify_uses_the_registry(tmp_path, capsys, fake_registry):
    scan = tmp_path / "scan.fake"
    scan.write_text("not a Nessus file")
    history.record_scan(parse_nessus_csv(SAMPLE))  # a baseline to compare against
    assert cli.cmd_verify(_verify_args(scan, tmp_path)) == 0
    data = json.loads(capsys.readouterr().out)
    assert [f["name"] for f in data["findings"]] == ["Fake scanner finding"]
    assert [d["host"] for d in data["new"]] == ["10.9.9.9"]


def test_cli_is_not_hard_wired_to_nessus(tmp_path, capsys, monkeypatch):
    # With Nessus removed from the registry, a Nessus CSV is no longer parseable.
    monkeypatch.setattr(parser_pkg, "_SCANNERS", [_FakeScanner()])
    rc = cli.cmd_analyze(_analyze_args(SAMPLE, tmp_path))
    captured = capsys.readouterr()
    assert rc == 1
    assert "No supported scanner can parse" in captured.err


# ── F / G: CLI output identical to the previous hard-wired Nessus path ──────

def _strip_run_fields(data):
    data = dict(data)
    data.pop("recorded_at", None)  # wall-clock time of the run
    return data


def test_analyze_json_unchanged(tmp_path, capsys, monkeypatch):
    assert cli.cmd_analyze(_analyze_args(SAMPLE, tmp_path)) == 0
    via_registry = json.loads(capsys.readouterr().out)
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "old_path.db")
    monkeypatch.setattr(cli, "parse", parse_nessus_csv)  # previous code path
    assert cli.cmd_analyze(_analyze_args(SAMPLE, tmp_path)) == 0
    direct = json.loads(capsys.readouterr().out)
    assert _strip_run_fields(via_registry) == _strip_run_fields(direct)


def test_verify_json_unchanged(tmp_path, capsys, monkeypatch):
    def run():
        history.record_scan(parse_nessus_csv(SAMPLE))
        assert cli.cmd_verify(_verify_args(SAMPLE_AFTER, tmp_path)) == 0
        return json.loads(capsys.readouterr().out)
    via_registry = run()
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "old_path.db")
    monkeypatch.setattr(cli, "parse", parse_nessus_csv)  # previous code path
    direct = run()
    assert via_registry == direct


def test_terminal_output_unchanged(tmp_path, capsys, monkeypatch):
    assert cli.cmd_analyze(_analyze_args(SAMPLE, tmp_path, json=False)) == 0
    via_registry = capsys.readouterr().out
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "old_path.db")
    monkeypatch.setattr(cli, "parse", parse_nessus_csv)
    assert cli.cmd_analyze(_analyze_args(SAMPLE, tmp_path, json=False)) == 0
    assert via_registry == capsys.readouterr().out


# ── Registry contract (applies to every future scanner) ─────────────────────

class _Recorder(Scanner):
    """Test-only scanner that records calls and accepts a given suffix."""

    def __init__(self, suffix, name, calls, raise_on_parse=None, raise_on_accepts=None):
        self.suffix, self.name, self.calls = suffix, name, calls
        self.raise_on_parse, self.raise_on_accepts = raise_on_parse, raise_on_accepts

    def accepts(self, path):
        self.calls.append(("accepts", self.name))
        if self.raise_on_accepts:
            raise self.raise_on_accepts
        return path.suffix == self.suffix

    def parse(self, path):
        self.calls.append(("parse", self.name))
        if self.raise_on_parse:
            raise self.raise_on_parse
        return _FakeScanner().parse(path)


def test_default_registry_is_nessus_only():
    assert [type(s) for s in parser_pkg._SCANNERS] == [NessusScanner]
    assert all(isinstance(s, Scanner) for s in parser_pkg._SCANNERS)


def test_first_matching_scanner_wins_and_later_ones_are_not_tried(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(parser_pkg, "_SCANNERS", [
        _Recorder(".other", "a", calls), _Recorder(".x", "b", calls),
        _Recorder(".x", "c", calls)])
    f = tmp_path / "scan.x"
    f.write_text("anything")
    parse(f)
    assert calls == [("accepts", "a"), ("accepts", "b"), ("parse", "b")]


def test_registration_order_decides_between_overlapping_scanners(tmp_path, monkeypatch):
    calls = []
    f = tmp_path / "scan.x"
    f.write_text("anything")
    monkeypatch.setattr(parser_pkg, "_SCANNERS", [_Recorder(".x", "c", calls),
                                                  _Recorder(".x", "b", calls)])
    parse(f)
    assert ("parse", "c") in calls and ("parse", "b") not in calls


def test_scanner_parse_exceptions_propagate_unchanged(tmp_path, monkeypatch):
    calls = []
    boom = RuntimeError("scanner bug")
    monkeypatch.setattr(parser_pkg, "_SCANNERS", [
        _Recorder(".x", "a", calls, raise_on_parse=boom), _Recorder(".x", "b", calls)])
    f = tmp_path / "scan.x"
    f.write_text("anything")
    with pytest.raises(RuntimeError) as exc:
        parse(f)
    assert exc.value is boom
    assert ("accepts", "b") not in calls  # not swallowed, no fallback to the next scanner


def test_scanner_accepts_exceptions_propagate_unchanged(tmp_path, monkeypatch):
    calls = []
    boom = UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "invalid")
    monkeypatch.setattr(parser_pkg, "_SCANNERS", [
        _Recorder(".x", "a", calls, raise_on_accepts=boom), _Recorder(".x", "b", calls)])
    f = tmp_path / "scan.x"
    f.write_text("anything")
    with pytest.raises(UnicodeDecodeError):
        parse(f)
    assert calls == [("accepts", "a")]


def test_no_matching_scanner_is_a_value_error_naming_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(parser_pkg, "_SCANNERS", [_Recorder(".x", "a", [])])
    f = tmp_path / "scan.y"
    f.write_text("anything")
    with pytest.raises(ValueError, match=f"No supported scanner can parse: {f}"):
        parse(f)


def test_missing_file_is_checked_before_any_scanner(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(parser_pkg, "_SCANNERS", [_Recorder(".x", "a", calls)])
    with pytest.raises(FileNotFoundError):
        parse(tmp_path / "missing.x")
    assert calls == []


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0,
                    reason="needs POSIX permissions and a non-root user")
def test_unreadable_file_is_reported_as_unreadable(tmp_path):
    f = tmp_path / "locked.csv"
    f.write_bytes(SAMPLE.read_bytes())
    f.chmod(0)
    try:
        with pytest.raises(ValueError, match="Cannot read .*locked.csv: Permission denied"):
            parse(f)
    finally:
        f.chmod(0o600)


def _assert_finding_contract(findings):
    """What every scanner's Finding must satisfy for history/verify/SLA/export."""
    assert findings and all(isinstance(f, Finding) for f in findings)
    for f in findings:
        for name in ("plugin_id", "cve", "host", "port", "protocol", "risk", "name",
                     "synopsis", "description", "solution", "references", "plugin_output"):
            assert isinstance(getattr(f, name), str), name
        assert f.host, "host is part of finding identity and must be non-empty"
        assert f.risk.lower() in ("critical", "high", "medium", "low"), f.risk
        assert f.cvss_v3 is None or isinstance(f.cvss_v3, float)
        assert f.cvss_v2 is None or isinstance(f.cvss_v2, float)
        assert all(c.startswith("CVE-") for c in f.cve_list)


@pytest.mark.parametrize("csv", [SAMPLE, SAMPLE_AFTER])
def test_nessus_findings_satisfy_the_finding_contract(csv):
    _assert_finding_contract(parse(csv))


def test_findings_from_any_registered_scanner_reach_history(tmp_path, capsys, fake_registry):
    scan = tmp_path / "scan.fake"
    scan.write_text("not a Nessus file")
    assert cli.cmd_analyze(_analyze_args(scan, tmp_path)) == 0
    capsys.readouterr()
    [row] = history.load_rows()
    assert [(d["host"], d["plugin_id"], d["port"]) for d in row["findings"]] == \
        [("10.9.9.9", "999001", "8443")]


# ── Registration-order safety: registered scanners must not overlap ─────────

# Every scanner in the production registry, mapped to real sample files it must
# accept. Registering a new scanner without adding its samples here fails the
# test below; so does any sample being accepted by more than one scanner, which
# would make the result depend on registration order.
REGISTERED_SCANNER_SAMPLES = {
    NessusScanner: [SAMPLE, SAMPLE_AFTER],
}


def test_every_registered_scanner_has_samples():
    registered = {type(s) for s in parser_pkg._SCANNERS}
    assert registered == set(REGISTERED_SCANNER_SAMPLES), \
        "add real sample files for each registered scanner to REGISTERED_SCANNER_SAMPLES"


@pytest.mark.parametrize("owner,sample", [
    (owner, sample) for owner, samples in REGISTERED_SCANNER_SAMPLES.items()
    for sample in samples])
def test_each_sample_is_accepted_by_exactly_its_own_scanner(owner, sample):
    accepted_by = [type(s) for s in parser_pkg._SCANNERS if s.accepts(sample)]
    assert accepted_by == [owner]
