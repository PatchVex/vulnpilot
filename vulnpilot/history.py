"""Silent local scan history — the Type II evidence trail.

Every analyze run is recorded automatically at ~/.vulnpilot/history.db.
No flags, never crashes the main flow; a failed save is logged as a
warning so the gap in the evidence trail is visible. Older scans can be
imported with `analyze --scan-date`; such rows keep their scan_date and the
real recorded_at, so they stay distinguishable from runs recorded at the time.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DB_PATH = Path.home() / ".vulnpilot" / "history.db"
WORKSPACES_DIR = Path.home() / ".vulnpilot" / "workspaces"
_WORKSPACE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

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
    findings_json   TEXT,
    scan_date       TEXT,
    recorded_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_ts ON scan_history (timestamp_utc);
"""

# Columns added after v1.1.0. Databases created by older versions get them via
# ALTER TABLE ... ADD COLUMN (non-destructive; existing rows read as NULL).
#   scan_date   — date the scanner ran, when stated with `analyze --scan-date`
#                 (NULL for scans recorded at the time they were analyzed)
#   recorded_at — when VulnPilot wrote the row (NULL for rows written before
#                 this column existed; never back-filled)
#
# timestamp_utc keeps its v1.1.0 meaning: when VulnPilot recorded the row. For
# rows written by this version it equals recorded_at; recorded_at is the
# explicit provenance field, timestamp_utc the legacy one. Neither is ever set
# to scan_date. History order is insertion order (the primary key `id`).
_ADDED_COLUMNS = (("scan_date", "TEXT"), ("recorded_at", "TEXT"))

# Workspace name when --workspace is in use (for user-facing hints only).
WORKSPACE: Optional[str] = None


def _make_private_dirs(path: Path) -> None:
    """Create `path` and any missing parents owner-only (0700).

    Only directories created here get that mode; existing directories are
    never chmod-ed. The mode is ignored on platforms without POSIX permissions.
    """
    missing = []
    p = path
    while not p.exists():
        missing.append(p)
        if p.parent == p:
            break
        p = p.parent
    for d in reversed(missing):
        d.mkdir(mode=0o700, exist_ok=True)


def _create_private_file(path: Path) -> None:
    """Create an empty `path` owner-only (0600) if it does not exist, so SQLite
    opens it instead of creating it with the process umask. An existing file is
    left untouched."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    os.close(fd)


def _connect_existing() -> Optional[sqlite3.Connection]:
    """Open the history DB for reading; None if it does not exist.

    sqlite3.connect() would otherwise create an empty file with default
    permissions, which record_scan() would then keep.
    """
    if not DB_PATH.is_file():
        return None
    return sqlite3.connect(DB_PATH)


def _columns(conn: sqlite3.Connection) -> set:
    return {r[1] for r in conn.execute("PRAGMA table_info(scan_history)")}


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the table if needed and add any missing columns. Idempotent."""
    conn.executescript(_SCHEMA)
    existing = _columns(conn)
    for name, sql_type in _ADDED_COLUMNS:
        if name not in existing:
            try:
                conn.execute(f"ALTER TABLE scan_history ADD COLUMN {name} {sql_type}")
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e).lower():  # concurrent writer
                    raise
    conn.commit()


def _optional_col(conn: sqlite3.Connection, name: str) -> str:
    """Select expression for an added column; NULL if this DB predates it.

    Readers never migrate — only record_scan() writes to the database.
    """
    return name if name in _columns(conn) else f"NULL AS {name}"


def command_hint() -> str:
    """The ' --workspace NAME' suffix to add to suggested commands, if any."""
    return f" --workspace {WORKSPACE}" if WORKSPACE else ""


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


def record_scan(findings: List, scan_file: Optional[Path] = None,
                scan_date: Optional[str] = None,
                recorded_at: Optional[str] = None) -> Optional[int]:
    """Record an analysis run. Returns row id, or None on any failure.

    `scan_date` (YYYY-MM-DD) marks an imported scan: it is stored as the date
    the scanner ran and does not affect ordering, baselines or SLA first-seen
    dates — the row is a new run recorded now. timestamp_utc and recorded_at
    are both the recording time.

    Deliberately swallows all exceptions — history must never break analyze.
    """
    try:
        # History holds hosts and findings: new directories and the DB file are
        # created owner-only; existing ones keep their permissions.
        _make_private_dirs(DB_PATH.parent)
        _create_private_file(DB_PATH)
        conn = sqlite3.connect(DB_PATH)
        _ensure_schema(conn)

        recorded = recorded_at or datetime.now(timezone.utc).isoformat()

        kev_count = sum(1 for f in findings if getattr(f, "kev_match", False))
        critical = sum(1 for f in findings if (f.risk or "").lower() == "critical")
        high = sum(1 for f in findings if (f.risk or "").lower() == "high")

        cur = conn.execute(
            "INSERT INTO scan_history (timestamp_utc, scan_file_name, scan_file_hash,"
            " total_findings, kev_count, critical_count, high_count, findings_json,"
            " scan_date, recorded_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                recorded,
                scan_file.name if scan_file else None,
                _file_sha256(scan_file) if scan_file and scan_file.exists() else None,
                len(findings),
                kev_count,
                critical,
                high,
                json.dumps([_finding_key(f) for f in findings]),
                scan_date,
                recorded,
            ),
        )
        conn.commit()
        row_id = cur.lastrowid
        conn.close()
        return row_id
    except Exception as e:
        # Never break the main flow, but never lose the evidence trail silently.
        logger.warning("Scan was not recorded to history at %s: %s", DB_PATH, e)
        return None


def scan_count() -> int:
    """Number of recorded scans (used by evidence pack for history context)."""
    try:
        conn = _connect_existing()
        if conn is None:
            return 0
        n = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        conn.close()
        return int(n)
    except Exception:
        return 0


def get_trend_rows() -> list:
    """Return (timestamp_utc, total_findings, kev_count, critical_count,
    scan_date, recorded_at) rows in recording order. scan_date/recorded_at are
    None for rows that predate those columns."""
    try:
        conn = _connect_existing()
        if conn is None:
            return []
        rows = conn.execute(
            "SELECT timestamp_utc, total_findings, kev_count, critical_count, "
            f"{_optional_col(conn, 'scan_date')}, {_optional_col(conn, 'recorded_at')}"
            " FROM scan_history ORDER BY id"
        ).fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def imported_count() -> int:
    """Rows imported with a stated scan date (analyze --scan-date)."""
    try:
        conn = _connect_existing()
        if conn is None:
            return 0
        if "scan_date" not in _columns(conn):
            conn.close()
            return 0
        n = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE scan_date IS NOT NULL"
        ).fetchone()[0]
        conn.close()
        return int(n)
    except Exception:
        return 0


def first_scan_date() -> Optional[str]:
    try:
        conn = _connect_existing()
        if conn is None:
            return None
        row = conn.execute(
            "SELECT MIN(timestamp_utc) FROM scan_history"
        ).fetchone()
        conn.close()
        return row[0][:10] if row and row[0] else None
    except Exception:
        return None


def load_rows() -> List[dict]:
    """All recorded scans in recording (insertion) order, in a single read.

    Each row: {"id", "timestamp", "findings", "scan_date", "recorded_at"},
    where "id" is the history table's primary key (the value record_scan()
    returns). Returns [] if the database is missing or unreadable.
    """
    try:
        conn = _connect_existing()
        if conn is None:
            return []
        rows = conn.execute(
            "SELECT id, timestamp_utc, findings_json, "
            f"{_optional_col(conn, 'scan_date')}, {_optional_col(conn, 'recorded_at')}"
            " FROM scan_history ORDER BY id"
        ).fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    out = []
    for row_id, ts, blob, scan_date, recorded_at in rows:
        try:
            findings = json.loads(blob or "[]")
        except ValueError:
            findings = []
        out.append({"id": row_id, "timestamp": ts, "findings": findings,
                    "scan_date": scan_date, "recorded_at": recorded_at})
    return out


def first_seen_map(rows: List[dict]) -> Dict[Tuple[str, str, str], str]:
    """Recording time of the first run (in `rows` order) containing each
    (host, plugin_id, port). This is the SLA first-seen date: when VulnPilot
    first recorded the finding — an imported scan's scan_date is not used."""
    seen: Dict[Tuple[str, str, str], str] = {}
    for row in rows:
        for d in row["findings"]:
            key = (d.get("host", ""), d.get("plugin_id", ""), d.get("port", ""))
            if key not in seen:
                seen[key] = row["timestamp"]
    return seen


def workspace_name(name: str) -> str:
    """Validate a workspace name and return its canonical (lowercase) form.

    Names are case-insensitive: on case-insensitive filesystems (macOS,
    Windows) `Acme` and `acme` would share one directory anyway, so every
    platform treats them as the same workspace, stored under the lowercase name.
    Raises ValueError for names that are not a simple identifier, so a
    workspace can never resolve outside WORKSPACES_DIR.
    """
    if not _WORKSPACE_NAME.fullmatch(name) or ".." in name:
        raise ValueError(
            f"Invalid workspace name {name!r}: use 1-64 letters, digits, '.', '_' "
            "or '-', starting with a letter or digit."
        )
    return name.lower()


def workspace_db_path(name: str) -> Path:
    """History DB for a named workspace (one per client/environment)."""
    return WORKSPACES_DIR / workspace_name(name) / "history.db"
