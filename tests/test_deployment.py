"""Deployment readiness checks — run before every push/release.

Catches: version drift, broken CLI entry points, missing package data,
build breakage. These test the *package*, not the logic.
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SAMPLE = ROOT / "data" / "sample" / "sample_nessus.csv"


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    return re.search(r'version\s*=\s*"([^"]+)"', text).group(1)


def _init_version() -> str:
    text = (ROOT / "vulnpilot" / "__init__.py").read_text()
    return re.search(r'__version__\s*=\s*"([^"]+)"', text).group(1)


def test_versions_match():
    """pyproject.toml and __init__.py must agree — PyPI rejects drift late."""
    assert _pyproject_version() == _init_version()


def test_cli_help_works():
    """Entry point must not crash on --help (catches import errors)."""
    r = subprocess.run([sys.executable, "-m", "vulnpilot.cli", "--help"],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0
    for cmd in ("analyze", "verify", "trend", "update-feeds"):
        assert cmd in r.stdout


def test_cli_analyze_smoke(tmp_path, monkeypatch):
    """End-to-end: analyze the sample CSV with evidence flag, offline."""
    monkeypatch.setenv("HOME", str(tmp_path))  # isolate history db
    out = tmp_path / "ev.md"
    r = subprocess.run(
        [sys.executable, "-m", "vulnpilot.cli", "analyze", str(SAMPLE),
         "--evidence", "soc2", "--evidence-out", str(out)],
        capture_output=True, text=True, cwd=ROOT,
        env={**__import__("os").environ, "HOME": str(tmp_path)},
    )
    assert r.returncode == 0, r.stderr
    assert "Prioritization" in r.stdout or "VulnPilot" in r.stdout
    assert out.exists() and "CC7.1" in out.read_text()


def test_sample_data_ships():
    """Sample CSV referenced by docs must exist."""
    assert SAMPLE.exists()


def test_docs_exist():
    """docs/ files referenced from README must exist."""
    for f in ("quickstart.md", "evidence-packs.md", "scoring.md", "faq.md"):
        assert (ROOT / "docs" / f).exists(), f"missing docs/{f}"


def test_package_builds():
    """python -m build must succeed (catches packaging config errors)."""
    import importlib.util
    if importlib.util.find_spec("build") is None:
        pytest.skip("'build' package not installed")
    r = subprocess.run([sys.executable, "-m", "build", "--wheel", "--no-isolation"],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr[-2000:]


def test_no_identity_leaks():
    """No sensitive identifiers in tracked files.

    Terms are read from a local file OUTSIDE the repo so the list itself
    is never published. Test skips silently if the file doesn't exist
    (e.g., in CI or on contributor machines).
    """
    import subprocess
    terms_file = Path.home() / ".patchvex" / "banned-terms.txt"
    if not terms_file.exists():
        pytest.skip("no local banned-terms file")
    banned = [t.strip().lower() for t in terms_file.read_text().splitlines()
              if t.strip()]
    tracked = subprocess.run(["git", "ls-files"], capture_output=True,
                             text=True, cwd=ROOT).stdout.splitlines()
    hits = []
    for rel in tracked:
        fp = ROOT / rel
        if fp.suffix in (".png", ".ico", ".gz", ".pyc") or not fp.exists():
            continue
        text = fp.read_text(errors="ignore").lower()
        hits += [f"{rel}: <term {i}>" for i, t in enumerate(banned) if t in text]
    assert not hits, f"Identity leak in tracked files: {hits}"
