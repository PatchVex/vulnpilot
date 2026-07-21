# Changelog

All notable changes to VulnPilot will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

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
- GitHub Actions daily feed automation (6am UTC)
- MIT license
- 12 unit and integration tests
