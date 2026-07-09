# Changelog

All notable changes to VulnPilot will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

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
