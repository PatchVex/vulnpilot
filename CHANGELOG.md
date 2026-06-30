# Changelog

All notable changes to VulnPilot will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

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
