"""
vulnpilot/parser

Public API for scanner parsing. Import Finding and parse() from here.
Do NOT import Finding from scanner-specific modules (parser.nessus, etc.).

Adding a new scanner:
    1. Create vulnpilot/parser/<name>.py implementing Scanner ABC
    2. Register an instance in _SCANNERS below
    3. parse() auto-detects format via accepts()
"""
from pathlib import Path
from typing import List

from vulnpilot.parser.base import Finding, Scanner
from vulnpilot.parser.nessus import NessusScanner, parse_nessus_csv

_SCANNERS = [
    NessusScanner(),
    # TrivyScanner(),   # add when trivy.py is implemented
]


def parse(path: Path) -> List[Finding]:
    """Auto-detect scanner format and return normalized Finding objects.

    Tries each registered scanner in order; first accepts() match wins.

    Raises:
        FileNotFoundError: if path does not exist
        ValueError: if no registered scanner can parse the file
    """
    path = Path(path)
    for scanner in _SCANNERS:
        if scanner.accepts(path):
            return scanner.parse(path)
    raise ValueError(
        f"No supported scanner can parse: {path}\n"
        "Supported formats: Nessus CSV\n"
        "Run 'vulnpilot --help' for usage."
    )


__all__ = ["Finding", "Scanner", "parse", "parse_nessus_csv"]
