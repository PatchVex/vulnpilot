# VulnPilot

**Open-source, local-first vulnerability operations for security teams.**

VulnPilot takes a Nessus export, cross-references it against CISA KEV and FIRST EPSS, and produces a deterministic priority-ranked list of what to fix first. It tracks SLA compliance, manages exceptions, generates audit evidence for SOC 2 and ISO 27001, and verifies remediation — all on your local machine. Your scan data never leaves your network.

[![CI](https://github.com/PatchVex/vulnpilot/actions/workflows/ci.yml/badge.svg)](https://github.com/PatchVex/vulnpilot/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/PatchVex/vulnpilot/blob/main/LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/vulnpilot.svg)](https://pypistats.org/packages/vulnpilot)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![PyPI version](https://img.shields.io/pypi/v/vulnpilot.svg)](https://pypi.org/project/vulnpilot/)
[![Status: v1.0 Community](https://img.shields.io/badge/status-v1.0%20community-brightgreen.svg)]()

---

## Quick Start

```bash
pip install vulnpilot
vulnpilot update-feeds
vulnpilot analyze scan.csv
```

VulnPilot downloads the latest public threat intelligence, analyzes your Nessus scan locally, and ranks findings by actual exploitation risk. No API keys. No cloud upload. No account required.

---

## What's in Community v1.0.0

The first stable release of VulnPilot. Everything below ships in the base `pip install`:

- **Composite risk scoring** — KEV (40%) + EPSS (35%) + CVSS (15%) + Severity (10%)
- **Remediation verification** — `vulnpilot verify` diffs a new scan against history; classifies findings as fixed, still open, or new
- **SLA compliance tracking** — per-severity deadlines with configurable policy; breach detection with approved/expired/unexcused classification
- **Exception register** — CSV-based approval tracking; exceptions surface as audit findings when expired or missing
- **Audit evidence packs** — one-command Markdown output mapped to SOC 2 CC7.1 and ISO 27001 A.8.8
- **HTML report** — self-contained, shareable report with executive summary and prioritized findings table
- **Posture trend** — `vulnpilot trend` shows total findings, KEV count, and critical count across all recorded scans
- **JSON output** — `--json` on `analyze` and `verify` for pipeline integration and `jq` consumption
- **CI gate** — `--fail-on-breach` exits 2 when unexcused SLA breaches exist
- **Scanner abstraction** — pluggable parser interface; Qualys, Rapid7, and OpenVAS parsers can be added without touching core logic
- **Local scan history** — every run recorded to `~/.vulnpilot/history.db`; never transmitted

**Docs:** [Quick Start](docs/quickstart.md) · [Evidence](docs/evidence.md) · [Trend & History](docs/trend.md) · [Scoring](docs/scoring.md) · [FAQ](docs/faq.md)

---

## Screenshots

**See it in action:**

<img src="https://raw.githubusercontent.com/PatchVex/vulnpilot/main/assets/demo.gif" alt="Animated demo of vulnpilot analyze scan.csv — running the command and getting back a prioritized findings table with KEV matches highlighted" width="720">

<table>
<tr>
<td width="50%">
<img src="https://raw.githubusercontent.com/PatchVex/vulnpilot/main/assets/terminal-screenshot.png" alt="VulnPilot terminal output showing prioritized findings, KEV matches, and a composite risk score table" width="100%">
<p align="center"><sub>Terminal output — <code>vulnpilot analyze scan.csv</code></sub></p>
</td>
<td width="50%">
<img src="https://raw.githubusercontent.com/PatchVex/vulnpilot/main/assets/report-screenshot.png" alt="VulnPilot self-contained HTML report with summary cards, executive summary, and a prioritized findings table" width="100%">
<p align="center"><sub>HTML report — <code>vulnpilot analyze scan.csv --html report.html</code></sub></p>
</td>
</tr>
</table>

**[View the full sample report →](https://htmlpreview.github.io/?https://github.com/PatchVex/vulnpilot/blob/main/assets/sample-report.html)** — real output from [`data/sample/sample_nessus.csv`](data/sample/sample_nessus.csv), not a mockup.

---

## The problem

Security teams often spend hours manually triaging scan results. Your Nessus export contains thousands of findings. CVSS says hundreds are Critical. The real question — which ones are actively being exploited right now?

And when the audit comes — SOC 2, ISO 27001, HIPAA, DPDP — the question changes: *can you prove how you prioritize and remediate?*

VulnPilot answers both, in seconds, using real-world exploit data.

---

## Why VulnPilot?

| Instead of | VulnPilot |
|---|---|
| Sorting by CVSS score alone | KEV + EPSS + CVSS composite scoring |
| Manual triage taking hours | Automated prioritization in seconds |
| Scrambling for audit evidence | One-command SOC 2 and ISO 27001 evidence packs |
| Spreadsheets to track SLA compliance | Per-finding SLA tracking against configurable policy |
| No documented exception process | Exception register with approval tracking and audit flags |
| Uploading scans to cloud services | Local-first — data never leaves your machine |
| Enterprise-only platforms | Open source, MIT licensed — free to use and self-host |

### CVSS-only prioritization is why triage takes hours

A typical mid-size scan flags **hundreds of findings as CVSS Critical (9.0+)**. Teams can't patch all of them this sprint, so CVSS alone gives no way to pick the first ten. It also has two structural problems:

- **It ignores exploitation.** CVSS scores severity *if* exploited — it says nothing about whether anyone actually is. A 9.8-scored bug sitting unexploited for years and a 7.5-scored bug being mass-exploited this week can score the same or backwards.
- **It doesn't move.** A CVSS score is fixed at publication. EPSS is recalculated daily as real-world exploitation activity changes, and KEV is updated the moment CISA confirms active exploitation — CVSS alone can't reflect that a quiet CVE went hot last Tuesday.

In the [sample scan](#screenshots) above, CVSS alone flags 4 of 6 findings as Critical (9.0+) — offering no way to rank them against each other. VulnPilot's composite score shows all 4 are CISA KEV — confirmed exploited in the wild — and ranks them 99.7–100, while CVSS-only triage would have you eyeballing four "Critical" rows with no tiebreaker.

**VulnPilot's answer:** blend confirmed exploitation (KEV), predicted exploitation probability (EPSS), and severity (CVSS) into one deterministic, re-runnable score — so "what's Critical" turns into "what's actually urgent, and in what order."

---

## How it works

```
vulnpilot analyze scan.csv
```

Output:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  VulnPilot by PatchVex — Vulnerability Prioritization
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total findings        : 5,482
  Unique hosts          : 47
  Critical              : 142
  KEV matches           : 19
  EPSS >= 90%           : 31
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  #    Score   Priority      Host              CVE                Finding
  ───────────────────────────────────────────────────────────────────────
  1    100.0   CRITICAL NOW  192.168.1.10      CVE-2021-44228     Log4Shell ★KEV
  2    100.0   CRITICAL NOW  192.168.1.25      CVE-2023-34362     MOVEit SQL Injection ★KEV
  3    99.8    CRITICAL NOW  192.168.1.15      CVE-2020-1472      Zerologon ★KEV
  4    99.7    CRITICAL NOW  192.168.1.11      CVE-2021-26084     Confluence RCE ★KEV
  5    11.5    LOW           192.168.1.10      N/A                SSH Weak Ciphers

  ★ KEV = CISA Known Exploited Vulnerability — highest remediation priority
        based on active exploitation in the wild.
```

VulnPilot cross-references your findings against three data sources — all processed locally:

| Source | What it tells you |
|---|---|
| **CISA KEV** | Confirmed exploited in the wild right now |
| **FIRST EPSS** | Probability of exploitation in next 30 days |
| **CVSS** | Severity context and baseline scoring |

**Composite score = KEV (40%) + EPSS (35%) + CVSS (15%) + Severity (10%)**

---

## Audit Evidence

Auditors across SOC 2, ISO 27001, HIPAA and DPDP ask for the same thing: proof of a documented, risk-based vulnerability management process. The most common audit gap is showing thousands of findings with no evidence of how they are prioritized, tracked, and resolved.

VulnPilot generates that evidence in one command:

```bash
# SOC 2 CC7.1 evidence pack
vulnpilot analyze scan.csv --evidence soc2

# ISO 27001 Annex A 8.8 evidence pack
vulnpilot analyze scan.csv --evidence iso27001
```

The evidence pack includes:
- Scan metadata — timestamped, with source file reference
- The documented prioritization methodology (KEV / EPSS / CVSS weights)
- Prioritized findings with KEV flags
- Framework control mapping statement (SOC 2 CC7.1 or ISO 27001 A.8.8)
- Management review and sign-off block
- **SLA compliance and exception register** — when run via `vulnpilot verify`

Output is a clean Markdown file — convert to PDF with your tool of choice and hand it to your auditor.

**Currently supported:** SOC 2 (CC7.1), ISO 27001 (A.8.8). DPDP and HIPAA packs are on the roadmap.

---

## SLA Policy Configuration

SLA thresholds are configurable per severity. The defaults are:

| Severity | Remediation deadline |
|---|---|
| Critical | 7 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |

To customize, create `~/.vulnpilot/sla.yaml`:

```yaml
# VulnPilot SLA policy — days to remediate by severity
critical: 7
high: 30
medium: 90
low: 180
```

VulnPilot reads this file automatically on every `verify` run. If the file does not exist, the defaults above apply. Use `--sla-config FILE` to pass a per-client policy at invocation time.

---

## Local Scan History

Every analysis run is automatically recorded to a local SQLite database at `~/.vulnpilot/history.db` — on your machine only, never transmitted.

Why this matters: SOC 2 Type II audits require evidence that your process operated consistently over a 6–12 month observation period. That history cannot be recreated retroactively. VulnPilot starts building your evidence trail from your very first scan.

Use `vulnpilot verify` to diff a new scan against history, and `vulnpilot trend` to view your posture over time.

---

## Why local-first?

Many organizations prohibit uploading vulnerability scan data to third-party cloud services. VulnPilot performs all analysis locally on your machine.

```
        Public Threat Intelligence
    +-------------------------------+
    |  CISA KEV      FIRST EPSS     |
    +---------------+---------------+
                    |
            vulnpilot update-feeds
                    |
        ~/.vulnpilot/feeds/ (local cache)
                    |
            vulnpilot analyze
                    |
    Nessus CSV (Local Machine Only)
                    |
       Composite Risk Engine
                    |
    Prioritized Findings + Evidence Pack
```

Only public threat intelligence feeds are downloaded. No API keys required. Your scan data never leaves your machine.

---

## Install

```bash
pip install vulnpilot
```

Tested on Python 3.10, 3.11, and 3.12. Zero runtime dependencies — pure stdlib.

---

## Usage

```bash
# Download latest KEV and EPSS feeds
vulnpilot update-feeds

# Analyze a Nessus CSV export
vulnpilot analyze scan.csv

# Generate a SOC 2 audit evidence pack
vulnpilot analyze scan.csv --evidence soc2

# Generate an ISO 27001 audit evidence pack
vulnpilot analyze scan.csv --evidence iso27001

# Verify remediation against your previous scan
# Requires at least one prior 'vulnpilot analyze' run to seed history
vulnpilot verify new_scan.csv

# Verify with exception register
# Classifies SLA breaches as approved, expired, or unexcused (audit finding)
vulnpilot verify new_scan.csv --exceptions exceptions.csv

# Verify + evidence pack with full governance section
vulnpilot verify new_scan.csv --exceptions exceptions.csv --evidence soc2

# Posture trend across all recorded scans
vulnpilot trend

# Evidence pack with custom output path
vulnpilot analyze scan.csv --evidence soc2 --evidence-out q3_evidence.md

# Export HTML report
vulnpilot analyze scan.csv --html report.html

# Show top N hosts by aggregate risk
vulnpilot analyze scan.csv --top-hosts 5

# Use local feed files
vulnpilot analyze scan.csv --kev ./kev.json --epss ./epss.csv.gz

# Disable colour output (for CI pipelines)
vulnpilot --no-colour analyze scan.csv

# Output findings as JSON (suppresses terminal output)
vulnpilot analyze scan.csv --json
vulnpilot verify new_scan.csv --json

# Use a per-client SLA policy instead of the default ~/.vulnpilot/sla.yaml
vulnpilot verify new_scan.csv --sla-config clients/acme_sla.yaml

# Exit 2 if audit findings exist — use as a CI pipeline gate
# Exit 0 = clean, 1 = tool error, 2 = breach found
vulnpilot verify new_scan.csv --fail-on-breach
```

---

## CI/CD integration

Use `--json` and `--fail-on-breach` to wire VulnPilot into a pipeline.

`verify` requires at least one prior `vulnpilot analyze` run to have seeded the history database.

```bash
# Step 1 — analyze the new scan; emit JSON for downstream consumers
vulnpilot analyze new_scan.csv --json | tee vulnpilot-analyze.json

# Step 2 — verify remediation; emit JSON and fail the pipeline on audit findings
# Exit 0 = clean, 1 = tool error, 2 = breach found (SLA breach with no valid exception)
vulnpilot verify new_scan.csv --json --fail-on-breach | tee vulnpilot-verify.json
```

Per-client SLA policies work with both flags:

```bash
vulnpilot verify new_scan.csv \
  --sla-config clients/acme_sla.yaml \
  --exceptions clients/acme_exceptions.csv \
  --fail-on-breach \
  --json
```

---

## HTML Report

Generate a shareable, self-contained HTML report:

```bash
vulnpilot analyze scan.csv --html report.html
```

<img src="https://raw.githubusercontent.com/PatchVex/vulnpilot/main/assets/report-screenshot.png" alt="VulnPilot HTML report" width="720">

The report includes:
- Executive summary with KEV and EPSS highlights
- Prioritized findings table with colour-coded risk scores
- Top 10 hosts by aggregate risk with visual score bars

**[View a real sample report →](https://htmlpreview.github.io/?https://github.com/PatchVex/vulnpilot/blob/main/assets/sample-report.html)**

---

## How scoring works

The scoring algorithm is deterministic, transparent, and fully documented.

| Signal | Weight | Source |
|---|---|---|
| CISA KEV match | 40% | Known exploited in the wild |
| FIRST EPSS score | 35% | Exploitation probability |
| CVSS base score | 15% | Severity context |
| Scanner risk rating | 10% | Nessus severity label |

The composite score is intentionally opinionated. Known exploited vulnerabilities receive the greatest weight because active exploitation is a stronger predictor of remediation priority than severity alone. Any KEV finding scores a minimum of 75 regardless of other factors.

The weighting model is intentionally transparent and may evolve based on community feedback and real-world usage.

> **Note**
>
> VulnPilot provides prioritization guidance to assist remediation workflows.
> Final remediation decisions should always consider asset criticality, business context,
> exploit mitigations, and organizational risk tolerance.

---

## Privacy by design

- Scan data processed entirely on your local machine
- No account required
- No cloud upload, ever
- No telemetry or analytics
- No API keys required
- Works air-gapped after initial feed download
- Scan history stored locally at `~/.vulnpilot/history.db` — your machine only, delete it anytime
- Open source — inspect every line of code

---

## Feed updates

VulnPilot pulls two public datasets:

- **CISA KEV** — Known Exploited Vulnerabilities catalog (maintained by CISA)
- **FIRST EPSS** — Exploit Prediction Scoring System (updated daily by FIRST.org)

Feeds are cached at `~/.vulnpilot/feeds/` on your machine. No API keys required.

```bash
vulnpilot update-feeds
```

The GitHub repository also runs an automated daily feed sync via GitHub Actions.

---

## Supported scanners

| Scanner | Status |
|---|---|
| Nessus (.csv export) | ✅ Supported |
| Qualys | Planned |
| Rapid7 | Planned |
| OpenVAS | Planned |
| Microsoft Defender | Planned |
| AWS Inspector | Planned |

---

## Roadmap

**v0.1.0 — Released ✅**
- [x] Nessus CSV parser
- [x] CISA KEV enrichment
- [x] FIRST EPSS enrichment
- [x] Composite risk scoring
- [x] Prioritized terminal output
- [x] GitHub Actions daily feed automation

**v0.2.0 — Released ✅**
- [x] HTML report export

**v0.3.0 — Released ✅**
- [x] SOC 2 audit evidence pack — `--evidence soc2`
- [x] Local scan history (foundation for verification and trends)

**v0.4.0 — Released ✅**
- [x] Remediation verification — `vulnpilot verify` (✓ Verified Fixed / ● Still Open / + New)
- [x] Scan-scope guard — hosts missing from a new scan are never counted as fixed
- [x] Posture trend — `vulnpilot trend`

**v0.5.0 — Released ✅**
- [x] ISO 27001 (Annex A 8.8) audit evidence pack — `--evidence iso27001`
- [x] SLA compliance tracking in `vulnpilot verify` — per-severity breach detection
- [x] Exception register integration — `verify --exceptions exceptions.csv`
- [x] Governance summary section in all evidence packs (framework-agnostic)

**v0.6.0 — Released ✅**
- [x] `--json` output on `analyze` and `verify` — machine-readable JSON, pipeable to `jq`
- [x] `--sla-config FILE` — per-invocation SLA policy override for per-client workflows
- [x] SLA breach as CI exit code gate — `verify --fail-on-breach` exits 2 when audit findings exist

**v1.0.0 — Released ✅**
- [x] Stable Community release — production/stable classifier, all findings always shown
- [x] Scanner abstraction layer — pluggable `Scanner` ABC; adding new parsers requires only a new file
- [x] All product data paths standardized to `~/.vulnpilot/`
- [x] HTML report cleaned — polished standalone output, no commercial messaging
- [x] `--evidence` messages routed to `stderr` when `--json` is active — clean JSON stream guaranteed
- [x] `ARCHITECTURE.md` — public source of truth for module layout, scoring formula, and extension points

**Later**
- [ ] DPDP and HIPAA evidence packs
- [ ] Qualys CSV support
- [ ] Weekly digest
- [ ] Jira / Slack integration

Future development priorities are driven by community feedback and real-world usage.

---

## Requirements

- Python 3.10, 3.11, or 3.12
- pip
- Internet connection for feed updates (air-gapped use supported after initial download)
- Nessus .csv export file

---

## Contributing

Issues, bug reports, and pull requests are welcome.

- **Bug reports and feature requests:** [github.com/PatchVex/vulnpilot/issues](https://github.com/PatchVex/vulnpilot/issues)
- **Discussions:** [github.com/PatchVex/vulnpilot/discussions](https://github.com/PatchVex/vulnpilot/discussions)
- **Security disclosures:** security@patchvex.com

Good first issues are labelled `good first issue` in the issue tracker. Please search existing issues before opening a new one.

---

## Acknowledgements

VulnPilot uses publicly available threat intelligence published by:

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/)

Thank you to both organizations for maintaining these community resources.

---

## License

MIT License — see [LICENSE](https://github.com/PatchVex/vulnpilot/blob/main/LICENSE) for details.

Free to use, modify, and distribute. Commercial use permitted.

---

## About PatchVex

VulnPilot is built and maintained by [PatchVex](https://patchvex.com).

PatchVex builds privacy-first workflow tools for security and DevSecOps teams. Our products help engineers spend less time managing vulnerability data and more time fixing the issues that matter.

- Website: [patchvex.com](https://patchvex.com)
- Email: hello@patchvex.com
- GitHub: [github.com/PatchVex](https://github.com/PatchVex)
