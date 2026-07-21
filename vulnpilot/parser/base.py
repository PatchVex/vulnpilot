"""
vulnpilot/parser/base.py

Canonical Finding dataclass and Scanner plugin interface.

All scanner parsers (nessus, trivy, qualys, …) must produce Finding objects
and implement the Scanner ABC. Consumers import Finding from here, not from
scanner-specific modules, so the import path never changes as new scanners
are added.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


RISK_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "": 0}


@dataclass
class Finding:
    """A normalized vulnerability finding produced by any supported scanner.

    Identity fields are set by the parser.
    Enriched fields (epss_*, kev_match) are set by enrich/.
    Scored fields (priority_*) are set by scoring/.
    """
    # Identity
    plugin_id: str
    cve: str
    host: str
    port: str
    protocol: str

    # Scanner-provided severity
    risk: str            # "Critical" | "High" | "Medium" | "Low"
    cvss_v3: Optional[float]
    cvss_v2: Optional[float]

    # Scanner metadata
    name: str
    synopsis: str
    description: str
    solution: str
    references: str
    plugin_output: str

    # Enriched by enrich/enricher.py
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev_match: bool = False

    # Scored by scoring/engine.py
    priority_score: Optional[float] = None
    priority_label: Optional[str] = None

    @property
    def cve_list(self) -> List[str]:
        if not self.cve:
            return []
        return [c.strip().upper() for c in self.cve.split(",") if c.strip().startswith("CVE-")]

    @property
    def cvss(self) -> float:
        """Best available CVSS score; v3 preferred, falls back to v2."""
        return self.cvss_v3 or self.cvss_v2 or 0.0

    @property
    def risk_value(self) -> int:
        """Numeric severity rank for sorting (critical=4 … none=0)."""
        return RISK_ORDER.get(self.risk.lower(), 0)


class Scanner(ABC):
    """Plugin interface for scanner-specific parsers.

    To add a new scanner:
    1. Create vulnpilot/parser/<name>.py
    2. Subclass Scanner and implement accepts() and parse()
    3. Register in vulnpilot/parser/__init__.py
    """

    @abstractmethod
    def accepts(self, path: Path) -> bool:
        """Return True if this scanner can parse the given file."""

    @abstractmethod
    def parse(self, path: Path) -> List[Finding]:
        """Parse the scan file and return normalized Finding objects.

        Raises:
            FileNotFoundError: if path does not exist
            ValueError: if the file format is unrecognized or invalid
        """
