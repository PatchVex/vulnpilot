# PatchVex — Architecture Reference

**Version:** Community v1.2.1  
**Status:** Source of truth for all future development decisions  
**Last updated:** 2026-09-25

---

## Table of Contents

1. [Product Positioning](#1-product-positioning)
2. [Current Architecture](#2-current-architecture)
3. [Desired Architecture](#3-desired-architecture)
4. [Edition Boundaries](#4-edition-boundaries)
5. [Plugin Architecture](#5-plugin-architecture)
6. [Public Interfaces](#6-public-interfaces)
7. [Internal Interfaces](#7-internal-interfaces)
8. [Stable APIs](#8-stable-apis)
9. [Extension Points](#9-extension-points)
10. [Data & Storage](#10-data--storage)
11. [Technical Constraints](#11-technical-constraints)

---

## 1. Product Positioning

PatchVex is **the open-source, local-first vulnerability operations platform**.

It begins where scanners end.

```
[Scanner]  →  discovers vulnerabilities
[PatchVex] →  prioritizes, tracks, verifies, and proves remediation
```

PatchVex is NOT a scanner. NOT a SIEM. NOT a GRC platform. NOT a CNAPP.

### Core Principles (non-negotiable)

| Principle | Implication |
|---|---|
| Open Source / MIT | No license gates on the CLI |
| Local-first | All data stays on the user's machine |
| Privacy-first | No telemetry. No cloud calls except explicit `update-feeds` |
| CLI-first | Terminal is the primary interface forever |
| Zero external dependencies | Pure Python stdlib only |
| Automation-first | Machine-readable output (`--json`, exit codes) on every command |

---

## 2. Current Architecture

### Package layout (current)

```
vulnpilot/
├── __init__.py              # version, package docstring
├── cli.py                   # command dispatcher + all command handlers
├── evidence.py              # audit evidence pack generation
├── exceptions.py            # exception register + governance classification
├── export.py                # actionable remediation ticket export
├── history.py               # SQLite scan history (Type II audit trail)
├── sla.py                   # SLA compliance engine
├── verify.py                # remediation verification (scan diff)
├── enrich/
│   ├── __init__.py
│   ├── enricher.py          # cross-references findings against KEV + EPSS
│   └── feeds.py             # feed download (KEV JSON, EPSS CSV.GZ) + loading
├── parser/
│   ├── __init__.py          # scanner registry + parse(path) dispatch
│   ├── base.py              # Finding dataclass + Scanner ABC
│   └── nessus.py            # Nessus CSV → Finding objects
├── reports/
│   ├── __init__.py
│   ├── html.py              # self-contained HTML report
│   └── terminal.py          # coloured terminal output
└── scoring/
    ├── __init__.py
    └── engine.py            # composite risk scoring (KEV+EPSS+CVSS+Severity)
```

### Data flow (current)

```
scan.csv
   │
   ▼
parser/__init__.py       parse()               → List[Finding]  (first registered scanner whose accepts() matches; Nessus today)
   │
   ▼
enrich/enricher.py       enrich()              → List[Finding]  (mutates in-place)
   │
   ▼
scoring/engine.py        score_all()           → List[Finding]  (mutates priority_score, priority_label)
   │
   ├──▶ history.py       record_scan()         → SQLite (~/.vulnpilot/history.db, or a --workspace DB)
   │
   ├──▶ reports/         render_summary()
   │    terminal.py      render_findings()
   │                     render_top_hosts()
   │
   ├──▶ reports/         generate_html_report()
   │    html.py
   │
   ├──▶ evidence.py      generate_evidence_pack()
   │
   └──▶ verify.py        verify_scan()         ← reads history.db
        sla.py           compute_all_sla()     ← reads history.db
        exceptions.py    classify_all()
```

### Known issues in current architecture

The issues listed here in v1.0.0 (license gate, `~/.patchvex/` SLA path, N+1 history reads in `sla.py`, Nessus-coupled `Finding` imports, no scanner interface, SQL inlined in `cmd_trend()`) have all been resolved, as have three later ones: `--json` missing on `trend`/`update-feeds`, argparse usage errors exiting `2`, and the mypy errors in `scoring/engine.py`. Open items:

| Issue | Location | Impact |
|---|---|---|
| `NessusScanner.accepts()` reads the whole file | `parser/nessus.py` | A matching file is read twice (detection + parse) so detection matches the parser exactly. Measured: 0.16 s of 3.3 s total on a 75 MB / 360k-finding export |
| `parse()`'s "no supported scanner" message hard-codes "Supported formats: Nessus CSV" | `parser/__init__.py` | Must be updated when a second scanner is registered |
| A non-UTF-8 file stops dispatch at `NessusScanner.accepts()` | `parser/nessus.py` | Harmless today; a later-registered scanner for such files would never be tried (register it before Nessus) |
| `write_default_config()` is never called | `sla.py` | `~/.vulnpilot/sla.yaml` is only created if the user writes it |

---

## 3. Desired Architecture

### Package layout (v1.0 target)

```
vulnpilot/
├── __init__.py
├── cli.py                   # command dispatcher + command handlers (no business logic)
├── evidence.py              # audit evidence generation
├── exceptions.py            # exception register + governance classification
├── history.py               # SQLite scan history
├── sla.py                   # SLA compliance engine
├── verify.py                # remediation verification
├── enrich/
│   ├── __init__.py
│   ├── enricher.py
│   └── feeds.py
├── parser/
│   ├── __init__.py          # public dispatch: parse(path) → List[Finding]
│   ├── base.py              # abstract Scanner interface + Finding dataclass
│   ├── nessus.py            # Nessus CSV implementation
│   └── trivy.py             # Trivy JSON implementation  [Phase 1 addition]
├── reports/
│   ├── __init__.py
│   ├── html.py
│   └── terminal.py
└── scoring/
    ├── __init__.py
    └── engine.py
```

The structure is deliberately conservative. Modules are renamed or moved only where alignment demands it. All current functionality is preserved.

**Status:** `parser/base.py` and the `parse(path)` dispatch are implemented, and the CLI uses them. `parser/trivy.py` is not implemented.

### Data flow (v1.0 target)

```
scan file (any supported format)
   │
   ▼
parser/__init__.py       parse(path)           → List[Finding]
   │                     (dispatches to nessus.py or trivy.py by file type)
   ▼
enrich/enricher.py       enrich()              → List[Finding]
   │
   ▼
scoring/engine.py        score_all()           → List[Finding]
   │
   ├──▶ history.py       record_scan()         → SQLite
   │
   ├──▶ reports/terminal.py   render_summary/findings/top_hosts()
   ├──▶ reports/html.py       generate_html_report()
   ├──▶ evidence.py           generate_evidence_pack()
   └──▶ verify.py + sla.py + exceptions.py   (verify workflow)
```

---

## 4. Edition Boundaries

### Community Edition (current CLI — always free, always open source)

Everything in this boundary ships in the open-source CLI with no gates.

| Capability | Module | Status |
|---|---|---|
| Scanner parsing (Nessus) | `parser/nessus.py` | Stable |
| Scanner parsing (Trivy) | `parser/trivy.py` | Planned — not implemented |
| KEV + EPSS feed management | `enrich/feeds.py` | Stable |
| Threat enrichment | `enrich/enricher.py` | Stable |
| Composite risk scoring | `scoring/engine.py` | Stable |
| Terminal output | `reports/terminal.py` | Stable |
| HTML visual report | `reports/html.py` | Stable |
| Basic evidence generation | `evidence.py` | Stable |
| Scan history (Type II trail) | `history.py` | Stable |
| SLA tracking | `sla.py` | Stable |
| Exception register | `exceptions.py` | Stable |
| Remediation verification | `verify.py` | Stable |
| Posture trend view | `cli.cmd_trend()` | Stable |
| JSON output (`--json`) | all commands | Stable |
| Exit code contract (0/1/2) | all commands | Stable |
| CI/CD integration (`--fail-on-breach`) | `verify` command | Stable |
| Per-client history (`--workspace`) | `history.py` | Stable |
| Importing older scans (`analyze --scan-date`) | `history.py` | Stable |

**Community edition rule:** If it helps one engineer understand, prioritize, verify, or document vulnerabilities, it belongs here and is free.

### Workflow Edition (future paid tier — not yet implemented)

The Workflow edition is built on top of the Community engine. It does not restrict Community features. It adds team-level automation.

| Capability | Notes |
|---|---|
| Jira integration | Create/update/close tickets from findings |
| GitHub Issues integration | Same model as Jira |
| Versioned evidence bundles | Automated historical evidence with diffs |
| Policy enforcement | Configurable rules with enforcement reporting |
| Exception lifecycle management | Approval workflows, notifications |
| Historical trend reporting | Cross-team posture dashboards |

**Workflow edition rule:** If it removes repetitive manual work for a team, it belongs here and companies pay for it.

**Note:** Community's local, credential-free ticket export (`verify --export-tickets`, see `export.py`) is the free precursor to the "Jira integration" row above — it produces the same underlying record set but writes a file rather than calling an API. Direct authenticated push stays Workflow edition.

**Implementation constraint:** Workflow edition code must live outside the `vulnpilot/` core package. It should import from `vulnpilot` as a library but add no changes to the core engine.

### Governance Edition (future — do not build yet)

Reserved for future org-level policy, RBAC, and enterprise approval workflows. No design decisions locked yet. Build only after Workflow edition has paying customers and they request it.

---

## 5. Plugin Architecture

### Scanner plugins

Scanner plugins are the primary extension point for adding new input formats.

**Interface contract** (`parser/base.py`):

```python
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List
from vulnpilot.parser.base import Finding

class Scanner(ABC):
    @abstractmethod
    def accepts(self, path: Path) -> bool:
        """Return True if this scanner can parse the given file."""

    @abstractmethod
    def parse(self, path: Path) -> List[Finding]:
        """Parse the scan file and return normalized Finding objects.

        Raises:
            FileNotFoundError: if path does not exist
            ValueError: if the file format is invalid
        """
```

**Dispatch mechanism** (`parser/__init__.py`):

```python
def parse(path: Path) -> List[Finding]:
    """Auto-detect scanner format and parse to Finding objects."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {path}")
    # unreadable path (directory, no permission) → ValueError("Cannot read ...")
    for scanner in _SCANNERS:
        if scanner.accepts(path):
            return scanner.parse(path)
    raise ValueError(f"No supported scanner can parse: {path} ...")  # message lists supported formats
```

`cli.py` calls `parse()` for both `analyze` and `verify`, so registering a scanner in `_SCANNERS` is all the CLI needs.

**Registration order:** Nessus is the only registered scanner. First `accepts()` match wins; future scanners (e.g. Trivy) are added to `_SCANNERS` in the order they should be tried. `NessusScanner.accepts()` claims any file with a line containing `plugin id`, `risk` and `host` (case-insensitive), so a scanner whose files could contain such a line must be registered **before** Nessus.

**Error contract:** exceptions raised by a scanner's `accepts()` or `parse()` propagate unchanged and stop dispatch — no later scanner is tried. `NessusScanner.accepts()` returns `False` for unreadable files but lets a UTF-8 decode error propagate (the same error the Nessus parser raises). Contract tests: `tests/test_parser_registry.py`. First match is the explicit contract; to keep it from silently depending on order, `REGISTERED_SCANNER_SAMPLES` in that file must list real sample files for every registered scanner, and each sample must be accepted by exactly one registered scanner.

**Format detection strategy:**

| Scanner | Detection method |
|---|---|
| Nessus | A header row containing `Plugin ID`, `Risk`, `Host` anywhere in the file (same search as `parse_nessus_csv()`; any file extension) |
| Trivy (planned) | JSON with top-level `SchemaVersion` + `Results` keys |
| Future (Qualys, Defender, OpenVAS) | Same `accepts()` pattern |

### Framework plugins (evidence)

Evidence frameworks are registered in `evidence.py:FRAMEWORKS` dict. Adding a new compliance framework is a dict entry plus a template — no structural change required.

```python
FRAMEWORKS = {
    "soc2":     { "title": ..., "control": ..., "objective": ... },
    "iso27001": { "title": ..., "control": ..., "objective": ... },
    # Adding dpdp, hipaa, pci-dss: add entry here only
}
```

---

## 6. Public Interfaces

These are the interfaces that users, scripts, and CI/CD systems depend on. They must not change without a major version bump and a deprecation period.

### CLI commands

```
vulnpilot [--no-colour] analyze <scan.csv>
                                      [--html FILE] [--evidence FRAMEWORK]
                                      [--evidence-out FILE] [--json]
                                      [--kev FILE] [--epss FILE]
                                      [--top-hosts N] [--sla-config FILE]
                                      [--workspace NAME] [--scan-date YYYY-MM-DD]
                                      [--all] [--license KEY]   (no-ops, kept for compatibility)

vulnpilot [--no-colour] verify <scan.csv>
                                      [--exceptions FILE] [--evidence FRAMEWORK]
                                      [--evidence-out FILE] [--json]
                                      [--kev FILE] [--epss FILE]
                                      [--sla-config FILE] [--fail-on-breach]
                                      [--workspace NAME] [--exclude-run ID]
                                      [--export-tickets FILE] [--ticket-format FORMAT]

vulnpilot update-feeds               [--cache DIR] [--json]

vulnpilot trend                      [--workspace NAME] [--json]

vulnpilot --version
vulnpilot --help
```

`--no-colour` (alias `--no-color`) is a global flag and goes before the command. `analyze --sla-config` is accepted but unused (SLA applies to `verify` only). Hidden aliases `verify --exc` (= `--exceptions`) and `analyze --s` (= `--sla-config`) keep two abbreviations from v1.1.0 unambiguous now that `--exclude-run` and `--scan-date` exist. `--scan-date` is validated against the local date.

### Exit code contract

| Code | Meaning |
|---|---|
| `0` | Success — no audit findings |
| `1` | Tool error: file not found or unreadable, parse failure, network error, invalid flag or argument (argparse usage errors), invalid `--exclude-run` / `--scan-date` / `--workspace` / exceptions file, or `verify` with no baseline |
| `2` | Audit findings exist (only returned when `--fail-on-breach` is set) |

This contract is stable. CI/CD pipelines depend on it. `2` is never used for anything else: argparse's default exit code `2` for usage errors is overridden to `1` (`cli._ArgumentParser`). `--help` and `--version` exit `0`.

### JSON output schema (`--json`)

**`vulnpilot analyze --json`**

```json
{
  "command": "analyze",
  "scan_file": "<filename>",
  "total_findings": 42,
  "findings": [
    {
      "plugin_id": "...",
      "name": "...",
      "cve": "...",
      "host": "...",
      "port": "...",
      "protocol": "...",
      "risk": "High",
      "cvss_v3": 8.1,
      "cvss_v2": null,
      "epss_score": 0.042,
      "epss_percentile": 0.91,
      "kev_match": false,
      "priority_score": 47.3,
      "priority_label": "HIGH",
      "synopsis": "...",
      "solution": "..."
    }
  ],
  "history_id": 7,
  "scan_date": null,
  "recorded_at": "2026-09-25T09:20:36.102786+00:00"
}
```

`history_id` is the history row ID (use with `verify --exclude-run`); `scan_date` is set only with `--scan-date`; `history_id` and `recorded_at` are `null` if the run could not be recorded. With no actionable findings the same shape is printed with `total_findings: 0`, `findings: []` and nothing recorded.

**`vulnpilot verify --json`**

```json
{
  "command": "verify",
  "scan_file": "<filename>",
  "baseline_date": "2026-07-10",
  "summary": {
    "fixed": 5,
    "still_open": 12,
    "new": 3,
    "out_of_scope_hosts": 0
  },
  "governance": {
    "within_sla": 8,
    "breached_approved": 1,
    "breached_expired": 1,
    "breached_no_exception": 2,
    "unknown": 0,
    "audit_findings": 3
  },
  "fixed": [...],
  "still_open": [...],
  "new": [...],
  "out_of_scope_hosts": [...],
  "findings": [...],
  "baseline_run_id": 7,
  "history_id": 8
}
```

`baseline_run_id` (added in v1.2.1) is the history run ID selected as the verification baseline. `history_id` (added in v1.2.1) is the history run ID this `verify` recorded for the current scan, or `null` if the scan could not be recorded. Both are appended after the v1.2.0 fields; no existing field changed. With no actionable findings the same shape is printed with `baseline_date: null`, `baseline_run_id: null`, `history_id: null` (no baseline is loaded and nothing is recorded), zero counts and empty lists.

**`vulnpilot trend --json`**

```json
{
  "command": "trend",
  "runs": [
    {"timestamp_utc": "2026-09-25T09:20:34.173253+00:00", "total_findings": 6,
     "kev_count": 4, "critical_count": 4, "scan_date": null}
  ]
}
```

Runs are in recording order; `scan_date` is set only for imported scans. With no history, `runs` is `[]` (exit `0`) and the hint goes to stderr.

**`vulnpilot update-feeds --json`**

```json
{"command": "update-feeds", "cache_dir": "/home/user/.vulnpilot/feeds"}
```

Download progress goes to stderr. On failure stdout is empty and the command exits `1`. On any error stdout is empty and the message goes to stderr — stdout only ever contains JSON.

Fields marked with `null` may be absent when data is unavailable. New fields may be added in minor versions. Fields will not be removed without a major version bump.

### Evidence pack output

Evidence packs are Markdown files. The filename pattern is stable:

```
evidence_<framework>_<YYYY-MM-DD>.md
```

Example: `evidence_soc2_2026-07-20.md`

The document structure (framework header, scan summary, findings table, governance section, verification section) is stable. New sections may be appended in minor versions.

### SLA policy file

Location: `~/.vulnpilot/sla.yaml` (default, overridable with `--sla-config`)

```yaml
# Days to remediate by severity
critical: 7
high: 30
medium: 90
low: 180
```

### Exception register file

CSV with columns: `host, plugin_id, port, ticket_ref, approver, approved_date, expiry_date, reason` (`host`, `plugin_id`, `port` required; a UTF-8 BOM is accepted)

- `host`, `plugin_id` and `port` may be `*`; `host` may be a CIDR range. An exact row wins over a pattern, otherwise the most specific matching row applies (exact field 2, CIDR host 1, `*` 0; between equal-scoring CIDR rows the longer prefix wins; remaining ties → first row in the file). A row matching everything is rejected. Duplicate `host, plugin_id, port` rows: the later row replaces the earlier one, with a warning.
- A row that leaves off trailing optional columns is accepted with them empty; a row missing a required field or with extra fields is skipped with a warning; a file missing required columns, or a missing `--exceptions` path, is an error (exit `1`).
- Date formats accepted: `YYYY-MM-DD`, `DD/MM/YYYY`, `MM/DD/YYYY`, `DD-MM-YYYY` (ambiguous dates read as DD/MM). Full format: `docs/evidence.md`.
- `expiry_date` (fail-closed since v1.2.1): blank means no expiry; a date in an accepted format expires the exception after that date; a non-blank value that cannot be read in an accepted format (e.g. `31st Dec`, `2026-02-30`, `2026-12-31T00:00:00`) makes the exception invalid — it is treated as expired rather than as "no expiry", so a breached finding it matches is `breached_expired` (an audit finding), with a warning naming the line. Matching and precedence are unchanged: such a row still applies wherever it would otherwise win.

---

## 7. Internal Interfaces

These interfaces are used between modules within the package. They may change across minor versions but changes should be coordinated across all callers.

### `Finding` dataclass (`parser/base.py`)

```python
@dataclass
class Finding:
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

    # Enriched fields (set by enrich/)
    epss_score: Optional[float]       = None
    epss_percentile: Optional[float]  = None
    kev_match: bool                   = False

    # Scored fields (set by scoring/)
    priority_score: Optional[float]   = None
    priority_label: Optional[str]     = None

    # Computed properties
    @property def cve_list(self) -> List[str]: ...
    @property def cvss(self) -> float: ...         # v3 preferred, falls back to v2
    @property def risk_value(self) -> int: ...     # numeric rank for sorting
```

All scanner parsers must produce `Finding` objects with these fields. Fields not available from a scanner output default to `""` (strings) or `None` (optional numerics).

### `SLAStatus` dataclass (`sla.py`)

```python
@dataclass
class SLAStatus:
    finding_key: Tuple[str, str, str]   # (host, plugin_id, port)
    risk: str
    first_seen: Optional[str]
    days_open: Optional[int]
    sla_days: Optional[int]
    pct_elapsed: Optional[float]
    status: str                          # "within" | "approaching" | "breached" | "unknown"
    exception_ref: Optional[str]
```

### `FindingGovernance` dataclass (`exceptions.py`)

```python
@dataclass
class FindingGovernance:
    finding_key: Tuple[str, str, str]
    sla_status: SLAStatus
    exception: Optional[ExceptionRecord]
    governance_status: str              # "within_sla" | "breached_approved" |
                                        # "breached_expired" | "breached_no_exception" | "unknown"
    audit_finding: bool
```

### `VerifyResult` dataclass (`verify.py`)

```python
@dataclass
class VerifyResult:
    baseline_date: str                   # date the baseline run was recorded
    fixed: List[dict]
    still_open: List[dict]
    new: List[dict]
    out_of_scope_hosts: List[str]
    baseline_scan_date: Optional[str]    # set only if the baseline was imported with --scan-date
    baseline_run_id: Optional[int]       # history row id of the baseline run
    baseline_file_hash: Optional[str]    # SHA-256 of the scan file the baseline was recorded from;
                                         # None for runs recorded without a scan file hash

    @property
    def summary(self) -> dict: ...      # counts of each category
```

### Module call rules

| Caller | May import from | Must NOT import from |
|---|---|---|
| `cli.py` | all modules | (no restriction — it is the top) |
| `evidence.py` | `history`, `parser.base` | `cli`, `reports` |
| `verify.py` | `history`, `parser.base`, `sla`, `exceptions` | `cli`, `evidence`, `reports` |
| `sla.py` | `history` | `cli`, `evidence`, `verify`, `exceptions` |
| `exceptions.py` | `sla` | `cli`, `evidence`, `verify`, `history` |
| `export.py` | `exceptions`, `sla` | `cli`, `evidence`, `verify`, `reports` |
| `scoring/` | `parser.base` | everything else |
| `enrich/` | `parser.base` | everything else |
| `reports/` | `parser.base` | `cli`, `evidence`, `verify`, `sla`, `exceptions` |
| `parser/` | nothing from `vulnpilot` | all other modules |
| `history.py` | nothing from `vulnpilot` | all other modules |

`parser/` and `history.py` are the foundation. They have no inward dependencies.

---

## 8. Stable APIs

These Python APIs are considered stable for external consumers (scripts, wrappers, future Workflow edition code).

### Parsing

```python
from vulnpilot.parser import parse, Finding

findings = parse(Path("scan.csv"))   # format auto-detected via the scanner registry
# Returns List[Finding]; raises FileNotFoundError or ValueError on failure
```

`parse_nessus_csv(path)` remains exported and stable for callers that want the Nessus parser directly; for Nessus files it returns the same findings as `parse()`.

### Scoring

```python
from vulnpilot.scoring import score_all, score_finding, ScoringConfig

scored = score_all(findings)
# or with custom weights:
cfg = ScoringConfig(kev_weight=40, epss_weight=35, cvss_weight=15, severity_weight=10)
score = score_finding(finding, cfg)
```

**The scoring formula is stable and documented:**

```
score = KEV(40) + EPSS×35 + CVSS×1.5 + Severity×10
KEV hard floor: score = max(score, 75) when kev_match is True
Final: min(round(score, 2), 100.0)
```

### Enrichment

```python
from vulnpilot.enrich import enrich

enrich(findings, kev_path=Path("kev.json"), epss_path=Path("epss.csv.gz"))
# Mutates findings in-place; returns the same list
```

### Evidence generation

```python
from vulnpilot.evidence import generate_evidence_pack

path = generate_evidence_pack(
    findings=scored,
    framework="soc2",          # or "iso27001"
    scan_file=Path("scan.csv"),
    output_path=None,          # auto-named if None
    verify_result=None,        # optional: include remediation verification
    governance_summary=None,   # optional: include governance posture
    scan_date=None,            # optional: stated scan date of an imported scan
    recorded_at=None,          # optional: when that scan was recorded to history
)
```

### Ticket export

```python
from vulnpilot.export import build_ticket_records, render

# findings = scored findings (same list passed to compute_all_sla)
# governance = FindingGovernance list from exceptions.classify_all()
records = build_ticket_records(findings, governance)   # only audit_finding=True records
output = render(records, "generic-csv")   # or "json", "jira-csv"
```

`build_ticket_records` reuses `FindingGovernance.audit_finding` as the sole
definition of "actionable" — it introduces no competing classification
logic. See README § Ticket Export for the full field schema.

### History

```python
from vulnpilot import history

run_id = history.record_scan(findings, scan_file=Path("scan.csv"),
                             scan_date=None)   # "YYYY-MM-DD" marks an imported scan
count = history.scan_count()
first = history.first_scan_date()
imported = history.imported_count()
rows = history.load_rows()        # recording order (by id); dicts with id, timestamp,
                                  # findings, scan_date, recorded_at
```

```python
from vulnpilot.verify import verify_scan

result = verify_scan(scored, exclude_run=run_id)   # exclude_run optional
```

### SLA + Governance

```python
from vulnpilot.sla import compute_all_sla, load_sla_config
from vulnpilot.exceptions import load_exceptions, classify_all, governance_summary

config = load_sla_config()                        # or load_sla_config(Path("sla.yaml"))
sla_statuses = compute_all_sla(findings, config)
exceptions = load_exceptions(Path("exceptions.csv"))
governance = classify_all(sla_statuses, exceptions)
summary = governance_summary(governance)
# summary["audit_findings"] → int count of findings auditors will flag
```

---

## 9. Extension Points

These are the documented ways to extend PatchVex without modifying core modules.

### Adding a scanner parser

1. Create `vulnpilot/parser/<scanner_name>.py`
2. Implement the `Scanner` abstract class from `parser/base.py`
3. Register in `parser/__init__.py` (before `NessusScanner` if its files could match Nessus detection — see Registration order), and add its real sample files to `REGISTERED_SCANNER_SAMPLES` in `tests/test_parser_registry.py`
4. All outputs must produce `Finding` objects with the standard field contract
5. Add test file `tests/test_parser_<scanner_name>.py`
6. Add sample data to `data/sample/`

No changes to `cli.py`, `scoring/`, `enrich/`, or `evidence.py` are required.

### Adding an evidence framework

1. Add an entry to `FRAMEWORKS` dict in `evidence.py`
2. Add the framework key to the `--evidence` choices in `cli.py:build_parser()`
3. No structural changes required

Example entry:

```python
"dpdp": {
    "title": "DPDP Act 2023 — Data Security",
    "control": "Section 8(4)",
    "control_name": "Security Safeguards",
    "objective": "...",
},
```

### Adding a CLI command

1. Add a subparser in `cli.py:build_parser()`
2. Add a `cmd_<name>(args) -> int` handler function in `cli.py`
3. Add dispatch in `cli.py:main()`
4. The handler must return an int exit code and never call `sys.exit()` itself
5. If the command needs new business logic, it goes in a dedicated module — not in `cli.py`

### Adding output formats

New output formats that render an already-assembled finding list (e.g. SARIF) should be added to `reports/` as new files. Existing `terminal.py` and `html.py` are not modified.

Formats that require new selection/business logic *before* rendering (deciding which findings qualify, not just how to print them) follow the `evidence.py` precedent instead: a dedicated top-level module. `export.py` (ticket export) is one — it reuses `FindingGovernance.audit_finding` to select records, then renders in multiple formats. Don't add new selection logic to `reports/`; don't add new pure-rendering formats to `export.py` or `evidence.py`.

### Workflow Edition integration

The Workflow edition imports `vulnpilot` as a library. It must not patch or monkey-patch core modules. The stable APIs in Section 8 are its only permitted entry points.

---

## 10. Data & Storage

### File locations

| Data | Path | Notes |
|---|---|---|
| Scan history | `~/.vulnpilot/history.db` | SQLite; created automatically on first recorded run |
| Workspace history | `~/.vulnpilot/workspaces/<name>/history.db` | Used instead of the above with `--workspace <name>`; names are case-insensitive and stored lowercase |
| SLA policy | `~/.vulnpilot/sla.yaml` | Optional; written by the user (defaults apply if absent) |
| KEV feed cache | `~/.vulnpilot/feeds/known_exploited_vulnerabilities.json` | Updated by `update-feeds` |
| EPSS feed cache | `~/.vulnpilot/feeds/epss_scores-current.csv.gz` | Updated by `update-feeds` |

All data lives under `~/.vulnpilot/`. No other home directory paths are used. History databases, and directories `record_scan()` has to create for them, are created owner-only (`0600` / `0700`) on POSIX; existing files and directories keep their permissions. Reading history never creates a database file.

### History database schema

```sql
CREATE TABLE scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc   TEXT NOT NULL,
    scan_file_name  TEXT,
    scan_file_hash  TEXT,
    total_findings  INTEGER,
    kev_count       INTEGER,
    critical_count  INTEGER,
    high_count      INTEGER,
    findings_json   TEXT,
    scan_date       TEXT,     -- added after v1.1.0
    recorded_at     TEXT      -- added after v1.1.0
);
CREATE INDEX idx_history_ts ON scan_history (timestamp_utc);
```

`findings_json` stores a JSON array of minimal finding identity dicts `{plugin_id, cve, host, port, name, risk, score, kev, epss, priority}`. This is the source for `verify`, `sla`, and `trend`.

- `timestamp_utc` — when VulnPilot recorded the row (v1.1.0 meaning, unchanged). Never set to a scan date.
- `recorded_at` — explicit recording time; equals `timestamp_utc` for new rows, `NULL` for rows written by v1.1.0 (never back-filled).
- `scan_date` — date the scanner ran, only for scans imported with `analyze --scan-date`; otherwise `NULL`.
- History order is insertion order (`id`). The `verify` baseline is the highest `id` (minus `--exclude-run`); SLA first-seen is the recording time of the first run containing the finding. `scan_date` is displayed but never used for ordering, baselines or SLA.

**Migration:** `record_scan()` (the only writer) creates the table and adds any missing column with `ALTER TABLE ... ADD COLUMN`; idempotent and non-destructive. Readers never alter the schema and read `NULL` for columns an older database lacks. v1.1.0 can still read a migrated database.

### Offline operation

VulnPilot operates fully offline. The only network calls are:

- `vulnpilot update-feeds` — downloads KEV from CISA and EPSS from FIRST into `~/.vulnpilot/feeds/` (or `--cache DIR`)

There is no automated feed synchronization: the former GitHub Actions `update-feeds.yml` workflow never completed a run and nothing read its output, so it was removed. Feeds are refreshed only when a user runs `update-feeds`.

No other network activity occurs.

---

## 11. Technical Constraints

These constraints must be preserved across all future development.

| Constraint | Reason |
|---|---|
| Python ≥ 3.10, ≤ 3.12 (tested) | Stdlib `match`, `dataclasses`, `datetime.fromisoformat` compatibility |
| Zero external dependencies | Supply chain safety; `pip install vulnpilot` must work anywhere |
| Pure stdlib only | `csv`, `json`, `sqlite3`, `argparse`, `urllib`, `hashlib`, `dataclasses` |
| No telemetry | Privacy-first principle |
| No mandatory cloud | Local-first principle |
| Exit codes 0/1/2 only | CI/CD pipeline compatibility |
| `--json` on every command | Automation-first principle |
| Scoring formula immutable without major version bump | Audit evidence reproducibility — changing weights invalidates historical evidence |
| No breaking CLI changes without deprecation | Users and pipelines depend on flag names and output structure |
| `history.record_scan()` must never raise | History capture must not interrupt the main analysis flow |

---

*This document is the source of truth. All architecture decisions, module additions, and refactors must be validated against it before implementation.*
