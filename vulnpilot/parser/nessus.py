"""
vulnpilot/parser/nessus.py
Parses Nessus CSV exports into normalized Finding objects.
"""
from __future__ import annotations
import csv
import logging
from pathlib import Path
from typing import List, Optional

from vulnpilot.parser.base import Finding, Scanner

logger = logging.getLogger(__name__)

NESSUS_COLUMNS = {
    "plugin id":             "plugin_id",
    "cve":                   "cve",
    "cvss v3.0 base score":  "cvss_v3",
    "cvss v2.0 base score":  "cvss_v2",
    "risk":                  "risk",
    "host":                  "host",
    "protocol":              "protocol",
    "port":                  "port",
    "name":                  "name",
    "synopsis":              "synopsis",
    "description":           "description",
    "solution":              "solution",
    "see also":              "references",
    "plugin output":         "plugin_output",
}


def _safe_float(value: str):
    try:
        return float(value.strip()) if value.strip() else None
    except ValueError:
        return None


def _read_lines(path: Path) -> List[str]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return fh.read().splitlines()


def _find_header(lines: List[str]) -> Optional[int]:
    """Index of the Nessus header row (any preamble before it is skipped)."""
    for i, line in enumerate(lines):
        lower = line.lower()
        if "plugin id" in lower and "risk" in lower and "host" in lower:
            return i
    return None


def parse_nessus_csv(path: Path) -> List[Finding]:
    """Parse a Nessus CSV export. Kept for backward compatibility; prefer parse()."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {path}")

    lines = _read_lines(path)
    header_idx = _find_header(lines)

    if header_idx is None:
        raise ValueError(
            "This does not look like a Nessus CSV export. "
            "Expected columns: Plugin ID, Risk, Host, CVE."
        )

    body = "\n".join(lines[header_idx:])
    reader = csv.DictReader(body.splitlines())

    col_map = {}
    for raw_col in (reader.fieldnames or []):
        normalized = NESSUS_COLUMNS.get(raw_col.strip().lower())
        if normalized:
            col_map[raw_col] = normalized

    findings: List[Finding] = []
    skipped = 0

    for row in reader:
        mapped = {v: row.get(k, "").strip() for k, v in col_map.items()}
        if mapped.get("risk", "").lower() in ("none", ""):
            skipped += 1
            continue
        host = mapped.get("host", "")
        if not host:
            skipped += 1
            continue
        findings.append(Finding(
            plugin_id=mapped.get("plugin_id", ""),
            cve=mapped.get("cve", ""),
            cvss_v3=_safe_float(mapped.get("cvss_v3", "")),
            cvss_v2=_safe_float(mapped.get("cvss_v2", "")),
            risk=mapped.get("risk", ""),
            host=host,
            port=mapped.get("port", ""),
            protocol=mapped.get("protocol", ""),
            name=mapped.get("name", ""),
            synopsis=mapped.get("synopsis", ""),
            description=mapped.get("description", ""),
            solution=mapped.get("solution", ""),
            references=mapped.get("references", ""),
            plugin_output=mapped.get("plugin_output", ""),
        ))

    logger.info("Parsed %d findings (%d informational skipped)", len(findings), skipped)
    return findings


class NessusScanner(Scanner):
    """Scanner plugin for Nessus CSV exports."""

    def accepts(self, path: Path) -> bool:
        # Same file reading and header search as parse_nessus_csv(), so every
        # file that parser can read is accepted (any extension, any preamble
        # length). A decode error propagates exactly as it would from parsing.
        try:
            return _find_header(_read_lines(path)) is not None
        except OSError:
            return False

    def parse(self, path: Path) -> List[Finding]:
        return parse_nessus_csv(path)
