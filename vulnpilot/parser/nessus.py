"""
vulnpilot/parser/nessus.py
Parses Nessus CSV exports into normalized Finding objects.
"""
from __future__ import annotations
import csv
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

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

RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "": 0}


@dataclass
class Finding:
    plugin_id: str
    cve: str
    cvss_v3: Optional[float]
    cvss_v2: Optional[float]
    risk: str
    host: str
    port: str
    protocol: str
    name: str
    synopsis: str
    description: str
    solution: str
    references: str
    plugin_output: str
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev_match: bool = False
    priority_score: Optional[float] = None
    priority_label: Optional[str] = None

    @property
    def cve_list(self) -> List[str]:
        if not self.cve:
            return []
        return [c.strip().upper() for c in self.cve.split(",") if c.strip().startswith("CVE-")]

    @property
    def cvss(self) -> float:
        return self.cvss_v3 or self.cvss_v2 or 0.0

    @property
    def risk_value(self) -> int:
        return RISK_ORDER.get(self.risk.lower(), 0)


def _safe_float(value: str) -> Optional[float]:
    try:
        return float(value.strip()) if value.strip() else None
    except ValueError:
        return None


def parse_nessus_csv(path: Path) -> List[Finding]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {path}")

    with open(path, newline="", encoding="utf-8-sig") as fh:
        raw = fh.read()

    lines = raw.splitlines()
    header_idx = None
    for i, line in enumerate(lines):
        lower = line.lower()
        if "plugin id" in lower and "risk" in lower and "host" in lower:
            header_idx = i
            break

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
