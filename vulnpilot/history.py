"""Silent local scan history — the Type II evidence trail.

Every analyze run is recorded automatically at ~/.vulnpilot/history.db.
No flags, no output, never crashes the main flow. History cannot be
backfilled later, so capture starts from the first run.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

DB_PATH = Path.home() / ".vulnpilot" / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc   TEXT NOT NULL,
    scan_file_name  TEXT,
    scan_file_hash  TEXT,
    total_findings  INTEGER,
    kev_count       INTEGER,
    critical_count  INTEGER,
    high_count      INTEGER,
    findings_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_ts ON scan_history (timestamp_utc);
"""


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _finding_key(f) -> dict:
    """Minimal identity of a finding — enough to diff scans later (verify)."""
    return {
        "plugin_id": f.plugin_id,
        "cve": f.cve,
        "host": f.host,
        "port": f.port,
        "name": f.name,
        "risk": f.risk,
        "score": getattr(f, "priority_score", None),
        "kev": bool(getattr(f, "kev_match", False)),
        "epss": getattr(f, "epss_score", None),
        "priority": getattr(f, "priority_label", None),
    }


def record_scan(findings: List, scan_file: Optional[Path] = None) -> Optional[int]:
    """Record an analysis run. Returns row id, or None on any failure.

    Deliberately swallows all exceptions — history must never break analyze.
    """
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.executescript(_SCHEMA)

        kev_count = sum(1 for f in findings if getattr(f, "kev_match", False))
        critical = sum(1 for f in findings if (f.risk or "").lower() == "critical")
        high = sum(1 for f in findings if (f.risk or "").lower() == "high")

        cur = conn.execute(
            "INSERT INTO scan_history (timestamp_utc, scan_file_name, scan_file_hash,"
            " total_findings, kev_count, critical_count, high_count, findings_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                scan_file.name if scan_file else None,
                _file_sha256(scan_file) if scan_file and scan_file.exists() else None,
                len(findings),
                kev_count,
                critical,
                high,
                json.dumps([_finding_key(f) for f in findings]),
            ),
        )
        conn.commit()
        row_id = cur.lastrowid
        conn.close()
        return row_id
    except Exception:
        return None


def scan_count() -> int:
    """Number of recorded scans (used by evidence pack for history context)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        n = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        conn.close()
        return int(n)
    except Exception:
        return 0


def get_trend_rows() -> list:
    """Return (timestamp_utc, total_findings, kev_count, critical_count) rows, oldest first."""
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT timestamp_utc, total_findings, kev_count, critical_count"
            " FROM scan_history ORDER BY timestamp_utc"
        ).fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def first_scan_date() -> Optional[str]:
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT MIN(timestamp_utc) FROM scan_history"
        ).fetchone()
        conn.close()
        return row[0][:10] if row and row[0] else None
    except Exception:
        return None
