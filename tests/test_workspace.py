"""Tests for --workspace: separate scan history per client/environment."""
import json
import sys
from pathlib import Path

import pytest

from vulnpilot import history
from vulnpilot.cli import main

SAMPLE = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus.csv"
SAMPLE_AFTER = Path(__file__).parent.parent / "data" / "sample" / "sample_nessus_after.csv"


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


def test_workspace_history_is_separate(tmp_path, monkeypatch, capsys):
    rc, out, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json",
                      "--workspace", "acme")
    assert rc == 0
    assert json.loads(out)["history_id"] == 1
    assert (tmp_path / "workspaces" / "acme" / "history.db").exists()
    assert not (tmp_path / "default" / "history.db").exists()

    # another client's workspace has no baseline
    rc, out, err = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json",
                        "--workspace", "globex")
    assert rc == 1
    assert out == ""
    assert "No scan history found" in err

    # the same client's workspace does
    rc, out, _ = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json",
                      "--workspace", "acme")
    assert rc == 0
    assert json.loads(out)["summary"]["fixed"] == 1


def test_default_history_unchanged_without_workspace(tmp_path, monkeypatch, capsys):
    rc, _, _ = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json")
    assert rc == 0
    assert (tmp_path / "default" / "history.db").exists()
    assert not (tmp_path / "workspaces").exists()


def test_trend_reads_only_its_workspace(monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json", "--workspace", "acme")
    _run(monkeypatch, capsys, "analyze", str(SAMPLE_AFTER), "--json", "--workspace", "acme")
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json", "--workspace", "globex")
    rc, out, _ = _run(monkeypatch, capsys, "trend", "--workspace", "acme")
    assert rc == 0
    assert out.count("\n  20") == 2  # two dated rows
    rc, out, _ = _run(monkeypatch, capsys, "trend", "--workspace", "globex")
    assert out.count("\n  20") == 1


@pytest.mark.parametrize("bad", ["../escape", "a/b", "", ".hidden", "-x", "x" * 65,
                                 "a..b", "sp ace"])
def test_invalid_workspace_name_is_rejected(tmp_path, monkeypatch, capsys, bad):
    rc, out, err = _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--json",
                        f"--workspace={bad}")
    assert rc == 1
    assert out == ""
    assert "Invalid workspace name" in err
    assert not (tmp_path / "workspaces").exists()
    assert not (tmp_path / "escape").exists()



# ── workspace names are case-insensitive (canonical lowercase) ──────────────

def test_workspace_names_are_case_insensitive(tmp_path, monkeypatch, capsys):
    _run(monkeypatch, capsys, "analyze", str(SAMPLE), "--workspace", "Acme")
    assert (tmp_path / "workspaces" / "acme" / "history.db").is_file()
    assert [p.name for p in (tmp_path / "workspaces").iterdir()] == ["acme"]
    rc, out, _ = _run(monkeypatch, capsys, "verify", str(SAMPLE_AFTER), "--json",
                      "--workspace", "ACME")
    assert rc == 0 and json.loads(out)["summary"]["fixed"] == 1  # same history


def test_workspace_hint_shows_canonical_name(monkeypatch, capsys):
    rc, _, err = _run(monkeypatch, capsys, "verify", str(SAMPLE), "--workspace", "Globex")
    assert "--workspace globex" in err


def test_workspace_name_canonicalisation_keeps_validation():
    assert history.workspace_name("Client-A.prod_1") == "client-a.prod_1"
    for bad in ("../Acme", "A/B", "..", ".Hidden"):
        with pytest.raises(ValueError):
            history.workspace_name(bad)


# ── new history files and directories are owner-only ────────────────────────

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")


@pytest.fixture
def permissive_umask():
    import os
    old = os.umask(0)  # prove the modes do not depend on the caller's umask
    yield
    os.umask(old)


@posix_only
def test_new_history_db_and_dirs_are_owner_only(tmp_path, monkeypatch, permissive_umask):
    import stat
    db = tmp_path / "home" / ".vulnpilot" / "workspaces" / "acme" / "history.db"
    monkeypatch.setattr(history, "DB_PATH", db)
    from vulnpilot.parser import parse
    before = stat.S_IMODE(tmp_path.stat().st_mode)
    assert history.record_scan(parse(SAMPLE)) == 1
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    for d in (db.parent, db.parent.parent, db.parent.parent.parent, db.parent.parent.parent.parent):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700, d   # every directory created here
    assert stat.S_IMODE(tmp_path.stat().st_mode) == before  # pre-existing parent untouched


@posix_only
def test_existing_db_and_dirs_keep_their_permissions(tmp_path, monkeypatch):
    import stat
    d = tmp_path / "shared"
    d.mkdir(mode=0o755)
    d.chmod(0o755)
    db = d / "history.db"
    db.touch()
    db.chmod(0o644)
    monkeypatch.setattr(history, "DB_PATH", db)
    from vulnpilot.parser import parse
    assert history.record_scan(parse(SAMPLE)) == 1
    assert stat.S_IMODE(db.stat().st_mode) == 0o644
    assert stat.S_IMODE(d.stat().st_mode) == 0o755


def test_readers_never_create_the_history_db(tmp_path, monkeypatch, capsys):
    db = tmp_path / "default" / "history.db"
    db.parent.mkdir()
    monkeypatch.setattr(history, "DB_PATH", db)
    assert history.load_rows() == [] and history.get_trend_rows() == []
    assert history.scan_count() == 0 and history.imported_count() == 0
    assert history.first_scan_date() is None
    _run(monkeypatch, capsys, "trend")
    _run(monkeypatch, capsys, "verify", str(SAMPLE))
    assert not db.exists()
