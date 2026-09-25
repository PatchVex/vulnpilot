"""CLI contract: exit codes for usage errors, and --json on trend / update-feeds."""
import json
import sys
from pathlib import Path

import pytest

import vulnpilot.cli as cli
from vulnpilot import history
from vulnpilot.cli import main

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"


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


# ── exit codes: 2 is reserved for audit findings ────────────────────────────

@pytest.mark.parametrize("argv", [
    ["analyze", str(SAMPLE), "--bogus"],                      # unknown flag
    ["analyze"],                                              # missing argument
    ["verify", str(SAMPLE), "--ticket-format", "nope"],       # invalid choice
    ["verify", str(SAMPLE), "--evidence", "pci"],
    ["frobnicate"],                                           # unknown command
    ["trend", "--workspace"],                                 # missing value
    ["--no-such-global-flag"],
])
def test_usage_errors_exit_1_not_2(monkeypatch, capsys, argv):
    rc, out, err = _run(monkeypatch, capsys, *argv)
    assert rc == 1
    assert out == ""
    assert "error:" in err and "usage:" in err


@pytest.mark.parametrize("argv", [["--version"], ["--help"], ["verify", "--help"], []])
def test_help_and_version_exit_0(monkeypatch, capsys, argv):
    rc, out, _ = _run(monkeypatch, capsys, *argv)
    assert rc == 0 and out


# ── trend --json ────────────────────────────────────────────────────────────

def test_trend_json_empty_history(monkeypatch, capsys):
    rc, out, err = _run(monkeypatch, capsys, "trend", "--json")
    assert rc == 0
    assert json.loads(out) == {"command": "trend", "runs": []}
    assert "No scan history yet" in err


def test_trend_json_lists_runs_with_scan_date(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--scan-date", "2026-01-15")
    rc, out, err = _run(monkeypatch, capsys, "trend", "--json")
    assert rc == 0 and err == ""
    data = json.loads(out)
    rows = history.load_rows()
    assert data["command"] == "trend"
    assert [r["timestamp_utc"] for r in data["runs"]] == [r["timestamp"] for r in rows]
    assert [r["scan_date"] for r in data["runs"]] == [None, "2026-01-15"]
    assert data["runs"][0] == {"timestamp_utc": rows[0]["timestamp"], "total_findings": 6,
                               "kev_count": data["runs"][0]["kev_count"],
                               "critical_count": 4, "scan_date": None}


def test_trend_json_respects_workspace(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--workspace", "acme")
    rc, out, _ = _run(monkeypatch, capsys, "trend", "--json", "--workspace", "acme")
    assert len(json.loads(out)["runs"]) == 1
    rc, out, err = _run(monkeypatch, capsys, "trend", "--json", "--workspace", "globex")
    assert json.loads(out)["runs"] == []
    assert "--workspace globex" in err


def test_trend_terminal_output_unchanged_without_json(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    rc, out, _ = _run(monkeypatch, capsys, "trend")
    assert "VulnPilot — Posture Trend" in out and not out.lstrip().startswith("{")


# ── update-feeds --json (download replaced; no network) ─────────────────────

def _fake_update_feeds(cache_dir=None):
    print("Downloading CISA KEV feed...")
    print("Feeds updated successfully.")


def test_update_feeds_json_stdout_is_json_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "update_feeds", _fake_update_feeds)
    rc, out, err = _run(monkeypatch, capsys, "update-feeds", "--json", "--cache", str(tmp_path))
    assert rc == 0
    assert json.loads(out) == {"command": "update-feeds", "cache_dir": str(tmp_path)}
    assert "Downloading CISA KEV feed" in err


def test_update_feeds_json_default_cache_dir(monkeypatch, capsys):
    from vulnpilot.enrich.feeds import DEFAULT_CACHE
    monkeypatch.setattr(cli, "update_feeds", _fake_update_feeds)
    rc, out, _ = _run(monkeypatch, capsys, "update-feeds", "--json")
    assert json.loads(out)["cache_dir"] == str(DEFAULT_CACHE)


def test_update_feeds_json_error_keeps_stdout_empty(monkeypatch, capsys):
    def boom(cache_dir=None):
        print("Downloading CISA KEV feed...")
        raise OSError("network unreachable")
    monkeypatch.setattr(cli, "update_feeds", boom)
    rc, out, err = _run(monkeypatch, capsys, "update-feeds", "--json")
    assert rc == 1 and out == ""
    assert "ERROR: network unreachable" in err


def test_update_feeds_terminal_output_unchanged_without_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "update_feeds", _fake_update_feeds)
    rc, out, err = _run(monkeypatch, capsys, "update-feeds")
    assert rc == 0
    assert out == "Downloading CISA KEV feed...\nFeeds updated successfully.\n" and err == ""



# ── legacy abbreviations kept after --exclude-run / --scan-date were added ──

from vulnpilot.cli import build_parser


@pytest.mark.parametrize("argv", [["--exc", "x.csv"], ["--exc=x.csv"]])
def test_verify_exc_still_means_exceptions(argv):
    args = build_parser().parse_args(["verify", "scan.csv", *argv])
    assert args.exceptions == "x.csv" and args.exclude_run is None


@pytest.mark.parametrize("argv", [["--s", "sla.yaml"], ["--s=sla.yaml"]])
def test_analyze_s_still_means_sla_config(argv):
    args = build_parser().parse_args(["analyze", "scan.csv", *argv])
    assert args.sla_config == "sla.yaml" and args.scan_date is None


def test_new_full_flags_unaffected():
    v = build_parser().parse_args(["verify", "scan.csv", "--exclude-run", "3",
                                   "--exceptions", "x.csv"])
    assert (v.exclude_run, v.exceptions) == ("3", "x.csv")
    a = build_parser().parse_args(["analyze", "scan.csv", "--scan-date", "2026-01-15",
                                   "--sla-config", "sla.yaml"])
    assert (a.scan_date, a.sla_config) == ("2026-01-15", "sla.yaml")


def test_other_abbreviations_still_work():
    v = build_parser().parse_args(["verify", "scan.csv", "--excl", "4", "--fail"])
    assert v.exclude_run == "4" and v.fail_on_breach is True
    a = build_parser().parse_args(["analyze", "scan.csv", "--sc", "2026-01-15"])
    assert a.scan_date == "2026-01-15"


def test_legacy_aliases_hidden_from_help(monkeypatch, capsys):
    for cmd in ("verify", "analyze"):
        rc, out, _ = _run(monkeypatch, capsys, cmd, "--help")
        assert rc == 0 and "--exc " not in out and "--s " not in out


def test_verify_exc_applies_the_exceptions_file_end_to_end(tmp_path, monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE))
    rc, _, err = _run(monkeypatch, capsys, "verify", str(SAMPLE), "--json",
                      "--exc", str(tmp_path / "missing.csv"))
    assert rc == 1 and "Exceptions file not found" in err  # --exc reached --exceptions



def test_hidden_aliases_not_listed_in_ambiguity_errors(monkeypatch, capsys):
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE), "--ex", "x.csv")
    assert rc == 1 and out == ""
    assert "ambiguous option: --ex could match --exceptions, --exclude-run, --export-tickets" in err
    assert "--exc," not in err and "--exc\n" not in err


def test_ambiguity_errors_without_aliases_are_unchanged(monkeypatch, capsys):
    rc, _, err = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--h", "r.html")
    assert rc == 1
    assert "ambiguous option: --h could match --help, --html" in err
