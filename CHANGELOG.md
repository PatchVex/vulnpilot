# Changelog

All notable changes to VulnPilot will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.2.1] — 2026-09-26

Patch release: workflow and output fixes. Scoring, SLA, baseline selection and history recording are
unchanged.

### Changed
- **An unreadable exception `expiry_date` now makes the exception invalid.** A non-blank expiry date
  that cannot be read (e.g. `31st Dec`, or an impossible date such as `2026-02-30`) was previously
  treated as "no expiry", so a time-limited approval silently became permanent. The finding is now
  classified `breached_expired` — an audit finding, included in `--export-tickets` and counted by
  `--fail-on-breach` (exit `2`). The warning now says so, and `verify` marks the row
  `✗ expired (unreadable expiry date)`. **Action:** only `YYYY-MM-DD`, `DD/MM/YYYY`, `MM/DD/YYYY` and
  `DD-MM-YYYY` are read, as before. Any other non-blank expiry — for example `2026/12/31`, `31.12.2026`,
  `31-Dec-2026`, a two-digit year such as `31/12/26`, a date with a time such as `2026-12-31T00:00:00`,
  or a spreadsheet serial number — previously meant "no expiry" and is now treated as expired, so registers
  containing such dates will start reporting audit findings (and `--fail-on-breach` will exit `2`) until the
  date is rewritten in a supported format (preferably `YYYY-MM-DD`). A blank `expiry_date` still means no
  expiry; valid dates, including the documented DD/MM reading of ambiguous dates, are unchanged.
- `verify` breach detail now shows each breached finding's port, CVE (or `-`) and name under its row, so
  two breaches on the same host with the same severity can be told apart.
- `verify` no longer writes ANSI colour codes when stdout is not a terminal (pipes, files, CI logs), matching
  `analyze`. `--no-colour` works as before.
- Evidence packs list their metadata (framework, control, generated, source scan file, and for imported
  scans the scan date and import time) as a Markdown list, so each field renders on its own line instead
  of running together in one paragraph.

### Added
- **Self-comparison warning.** When the `verify` baseline was recorded from the same scan file
  (identical SHA-256), `verify` warns on stderr, naming the baseline's history run ID. This catches
  `analyze` followed by `verify` on the same scan, and re-running the same `verify` (for example a CI
  retry), which compares against the run the first `verify` recorded. The warning notes that
  `--exclude-run` skips only that one run: if the same scan was recorded more than once, an earlier
  recording of it can become the baseline, so review the run history before relying on the result.
  Baseline selection and exit codes are unchanged; runs recorded without a file hash never trigger it.
- `verify --json` output gains `baseline_run_id` (history run used as the baseline) and `history_id` (run
  this `verify` recorded; `null` if it could not be recorded). Both are appended; existing fields are
  unchanged. With no actionable findings both are `null`.

### Fixed
- An unwritable `--export-tickets`, `--evidence-out` or `--html` path (missing directory, directory,
  permission denied) is now an `ERROR:` on stderr and exit `1` instead of a traceback; `--json` stdout stays
  empty. As before, the scan is recorded to history before output files are written — the error says which
  run it was recorded as — and outputs are written one after another, so if a later write fails (e.g. the
  evidence pack), an earlier one (e.g. the ticket export) may already have been written.

## [1.2.0] — 2026-09-25

Nessus CSV remains the only supported scanner format.

### Added
- **`verify --exclude-run ID`** — exclude one history run from baseline selection. Use it when
  `analyze` has already recorded the scan being verified, so the scan is not compared against itself.
- **History run IDs** — `analyze` reports the ID of the run it recorded (`History run ID: N`, and
  `history_id` in `--json` output).
- **`--workspace NAME`** on `analyze`, `verify` and `trend` — keeps a separate scan history per client
  or environment in `~/.vulnpilot/workspaces/NAME/history.db`. Without it the shared
  `~/.vulnpilot/history.db` is used as before. Names are case-insensitive (`Acme` = `acme`, stored lowercase).
- **`analyze --scan-date YYYY-MM-DD`** — import an older scan with the date the scanner ran. The import
  is recorded as a new run at the time it is imported; the stated scan date is stored alongside it and
  never replaces the recording time, so history order, `verify` baselines and SLA first-seen dates are
  unaffected by it. Imports are marked in `trend`, in `verify` when an import is the baseline, and in
  evidence packs, which state the scan date and the import time separately and count imported runs.
- **Wildcard and CIDR exceptions** — in the exception register, `host`, `plugin_id` and `port` accept
  `*`, and `host` accepts a CIDR range. Exact rows win; otherwise the most specific matching row applies,
  and between otherwise equal CIDR rows the narrower network wins (IPv4 and IPv6). A row that matches
  everything is rejected. When two rows share host, plugin_id and port, the later row still replaces the
  earlier one (as in 1.1.0), now with a warning naming both lines.
- **`--json` on `trend` and `update-feeds`**, so every command now has JSON output. `update-feeds`
  progress messages go to stderr in JSON mode.
- History database columns `scan_date` and `recorded_at`. Existing databases gain them automatically the
  next time a scan is recorded; existing rows are left unchanged (`NULL`), and v1.1.0 can still read a
  migrated database.

### Changed
- **Invalid flags or arguments now exit `1`** (tool error) instead of argparse's default `2`, so exit `2`
  always means audit findings under `--fail-on-breach`. `--help` and `--version` still exit `0`.
- **`--json` stdout is JSON only.** `verify` errors (including "No scan history found") now go to
  stderr. With no actionable findings, `analyze --json` and `verify --json` print a JSON result with the
  usual fields and empty/zero values instead of plain text.
- `analyze --json` now also writes the `--html` report, and `verify --json` also writes the `--evidence`
  pack, instead of silently skipping them (their messages go to stderr).
- `analyze --json` output gains `history_id`, `scan_date` and `recorded_at`. Existing fields are unchanged.
- A missing or invalid `--exceptions` file is now an error (exit `1`) instead of silently applying no
  exceptions. The file may carry a UTF-8 BOM (as saved by Excel). A row that leaves off trailing optional
  columns (e.g. `reason`) is accepted with those fields empty; a row missing a required field or with extra
  fields is skipped with a warning naming the line, instead of discarding the whole register; unrecognised
  dates are warned about.
- `--scan-date` is checked against the local date, so a scan dated today in your timezone is accepted even
  when the UTC date is still the previous day.
- The abbreviations `verify --exc` (for `--exceptions`) and `analyze --s` (for `--sla-config`) keep working
  despite the new `--exclude-run` and `--scan-date` flags; other abbreviations behave as before.
- `analyze` and `verify` read scans through the scanner registry (`vulnpilot.parser.parse`). Nessus
  results are unchanged; the error for an unrecognised file now reads "No supported scanner can parse"
  and lists the expected Nessus columns.
- History is ordered by recording order (row ID). For history written by earlier versions this is the
  same order as before.
- "No scan history" hints include `--workspace NAME` when a workspace is in use.

### Fixed
- A directory or unreadable file passed to `analyze` or `verify` now gives a clear error and exit `1`
  instead of a traceback.
- A failure to record a run to history is now reported as a warning instead of being silently ignored
  (the command itself still succeeds).
- SLA status no longer re-reads the whole history database once per finding, and `verify` reads history
  once for both baseline selection and SLA.
- New history databases, and any directories created for them, are owner-only (`0600`/`0700`) on POSIX
  instead of following the umask; existing files keep their permissions. Reading history (e.g. `trend`
  before any scan) no longer creates an empty, default-permission database file.

### Removed
- The GitHub Actions daily feed-sync workflow (`update-feeds.yml`). It never completed a run — every run
  failed at its commit step — and nothing read the repository copy of the feeds. Automated feed
  synchronization is not currently implemented; `vulnpilot update-feeds` is unchanged.

### Documentation
- `ARCHITECTURE.md` brought in line with the current code: scanner registry and error contract,
  registration order, CLI flags, exit codes, JSON schemas, history schema and date semantics, known issues.
- README, quickstart, FAQ, trend and evidence docs updated for the above, including a corrected CI
  example (`verify` records its own run; seed history once with `analyze`), the exception register
  format, and removal of the claim that feeds are synced automatically.
- `docs/tenable-tvm-sample-requirements.md` — the real, scrubbed Tenable Vulnerability Management export
  needed before TVM support can be designed. TVM is **not** supported.

### Internal
- Scanner registry contract tests, including a guard that every registered scanner has real sample files
  and that no sample is accepted by more than one scanner.
- `NessusScanner.accepts()` shares the Nessus parser's file reading and header detection, so detection
  matches exactly what the parser can read.
- The package-build test builds into a temporary directory instead of `dist/`.
- mypy reports no errors.
- Pre-push test hook in `.githooks/` (enable with `git config core.hooksPath .githooks`).
- 310 automated tests passing.

## [1.1.0] — 2026-08-21

### Added
- **Actionable remediation ticket export** — `vulnpilot verify --export-tickets FILE --ticket-format FORMAT`.
  Writes governance-classified audit findings (breached SLA with no valid or an expired exception —
  the same classification `verify`'s own output already computes) to a ticket-ready file.
  - `generic-csv` (default) — importable into Jira, ServiceNow, Linear, or any CSV-import tool.
  - `json` — stable, documented schema (`schema_version: 1`) for scripted integrations.
  - `jira-csv` — Jira's default CSV-import column set. Not a Jira API integration; no credentials,
    no network call.
  - New module: `vulnpilot/export.py` (`TicketRecord`, `build_ticket_records`, `render`).
  - Fully additive and backward compatible: `verify` output and exit codes are unchanged when the
    new flags are not used.

### Security
- **CSV formula injection (OWASP CSV injection) mitigated in ticket export.** `generic-csv` and
  `jira-csv` output now prefix any cell value starting with `=`, `+`, `-`, `@`, tab, or CR with a
  single quote (`'`) before writing, preventing scan-derived field values from being interpreted
  as active formulas when the exported file is opened in Excel, Google Sheets, or LibreOffice.
  `json` output is unaffected (JSON is never opened in spreadsheet software). RFC 4180 CSV escaping
  (commas, quotes, embedded newlines) is unchanged.

### Internal
- 130 automated tests passing.

## [1.0.0] — 2026-07-21

### Changed
- **Community v1.0 — production/stable release.** All findings are always shown; no tier gates.
- Removed all "Community Edition", "Upgrade to Professional", and pricing language from the
  generated HTML report and terminal output. Reports are now clean, polished, and commercial-messaging-free.
- Scanner format abstraction: `Finding` dataclass and `Scanner` ABC extracted to `vulnpilot/parser/base.py`;
  `NessusScanner` class in `parser/nessus.py`; `parse()` auto-detecting dispatcher in `parser/__init__.py`.
  Adding future scanners (Trivy, Qualys, etc.) requires only a new file + one registration line.
- All product data paths standardized to `~/.vulnpilot/` (was `~/.patchvex/` in some locations).
- `--all` flag preserved as a no-op for backward compatibility (all findings were already always shown).
- `--license KEY` flag preserved as a no-op, reserved for future Workflow edition plugins.
- `--evidence` informational message redirected to `stderr` when `--json` is active, keeping JSON
  output valid for piping to `jq` or script consumption.
- Development Status classifier updated to `5 - Production/Stable`.

### Removed
- `FREE_TIER_LIMIT` constant and `is_paid` logic removed from CLI and HTML report generator.
- `render_free_tier_gate()` terminal function removed.
- Dead upgrade CSS (`.upgrade-banner`, `.upgrade-text`, `.upgrade-sub`, `.upgrade-btn`) removed
  from HTML report template.
- Internal strategy and gap-analysis documents removed from tracked files.

### Internal
- `ARCHITECTURE.md` added at repo root as source of truth for module layout, scoring formula,
  exit codes, evidence frameworks, and scanner extension points.
- 77 automated tests passing.

---

## [0.6.0] — 2026-07-17

### Added
- **`--json` output on `analyze` and `verify`** — machine-readable JSON output; suppresses
  terminal rendering so the result can be piped to `jq` or consumed by scripts
- **`--sla-config FILE`** — per-invocation SLA policy override; pass a custom YAML file instead
  of the global `~/.patchvex/sla.yaml`, enabling per-client policies without modifying the
  default config
- **`--fail-on-breach` on `verify`** — exits with code `2` when audit findings exist (SLA
  breaches with no valid exception); exit `0` = clean, `1` = tool error, `2` = breach found;
  enables `vulnpilot verify` as a hard CI pipeline gate

### Fixed
- `vulnpilot verify` recorded the scan to history twice when `--json` was used — the
  `record_scan()` call was duplicated across the JSON and terminal output branches; consolidated
  to a single call before branching

### Internal
- 77 automated tests passing

---

## [0.5.0] — 2026-07-12

### Added
- **ISO 27001 (Annex A 8.8) evidence pack** — `vulnpilot analyze scan.csv --evidence iso27001`
  generates an audit evidence pack mapped to the ISO/IEC 27001:2022 Management of Technical
  Vulnerabilities control; identical structure to the SOC 2 pack
- **SLA compliance block in `vulnpilot verify`** — every open finding is now classified against
  a configurable per-severity remediation policy (default: Critical 7d, High 30d, Medium 90d,
  Low 180d; customisable at `~/.patchvex/sla.yaml`); terminal output shows within / approaching /
  breached counts and a breach detail table
- **Exception register integration — `vulnpilot verify --exceptions exceptions.csv`** — matches
  open SLA breaches against an approved exception register CSV; classifies each breach as
  `breached_approved` (valid exception on file), `breached_expired` (exception lapsed), or
  `breached_no_exception` (no approval — surfaced as an audit finding); exception ticket reference
  and expiry shown in breach detail
- **Governance summary in evidence packs (§ 4c)** — `vulnpilot verify --evidence <framework>`
  now includes a framework-agnostic SLA compliance and exception register table in the generated
  pack; identical content appears in both SOC 2 and ISO 27001 packs and will carry forward to
  future frameworks

### Internal
- SLA engine (`vulnpilot/sla.py`) and exceptions engine (`vulnpilot/exceptions.py`) were
  implemented in the v0.5.0 development branch; wired to the CLI in this release
- `TODO v0.5.1` marker added in `sla.py::_first_seen_from_history` documenting an N+1 DB read
  pattern to be addressed in the next patch
- 57 automated tests passing

---

## [0.4.1] — 2026-07-10

### Fixed
- `vulnpilot verify` no longer dumps a raw traceback on a missing or malformed CSV — prints a clean `ERROR:` message and exits 1, matching `analyze`'s existing behaviour
- `vulnpilot verify` and `vulnpilot trend` now return proper process exit codes (0/1) instead of always exiting 0, so they can be used as CI gates
- `vulnpilot --no-colour verify ...` — the global `--no-colour` flag was silently ignored by `verify` due to a duplicate, shadowing `--no-colour` definition on the `verify` subcommand; removed the duplicate so `verify` now honours the global flag like every other command

### Added
- `data/sample/sample_nessus_after.csv` — a second sample scan ("30 days later") for demoing `vulnpilot verify` end-to-end
- Regression test covering the missing-CSV clean-error/exit-code contract for `verify`

---

## [0.1.0] — 2026-06-30

### Added
- Nessus CSV parser — handles standard Nessus export format
- CISA KEV enrichment — matches findings against Known Exploited Vulnerabilities catalog
- FIRST EPSS enrichment — adds exploitation probability scores
- Composite risk scoring — KEV (40%) + EPSS (35%) + CVSS (15%) + Severity (10%)
- Prioritized terminal output with ANSI colour support
- Top hosts ranked by aggregate risk score
- Free tier — top 20 findings
- `vulnpilot analyze` command
- `vulnpilot update-feeds` command
- GitHub Actions daily feed automation (6am UTC) — *note: this workflow never completed a run and was removed after v1.1.0; automated feed sync is not currently implemented*
- MIT license
- 12 unit and integration tests
