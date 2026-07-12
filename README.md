# VulnPilot

**Your scanner finds them. VulnPilot proves you managed them.**

Prioritize vulnerabilities using real-world exploit intelligence. Track SLA compliance. Generate audit evidence. Manage exceptions. Runs locally — your data never leaves your machine.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/PatchVex/vulnpilot/blob/main/LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![PyPI version](https://img.shields.io/pypi/v/vulnpilot.svg)](https://pypi.org/project/vulnpilot/)
[![Status: Community Preview](https://img.shields.io/badge/status-community%20preview-orange.svg)]()

---

## Quick Start

```bash
pip install vulnpilot
vulnpilot update-feeds
vulnpilot analyze scan.csv
```

VulnPilot downloads the latest public threat intelligence, analyzes your Nessus scan locally, and shows what should be remediated first. No API keys required.

**Docs:** [Quick Start](docs/quickstart.md) · [Evidence Packs](docs/evidence-packs.md) · [Scoring](docs/scoring.md) · [FAQ](docs/faq.md)

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

**[View the full sample report →](https://htmlpreview.github.io/?https://github.com/PatchVex/vulnpilot/blob/main/assets/sample-report.html)** — real output generated from [`data/sample/sample_nessus.csv`](data/sample/sample_nessus.csv), not a mockup.

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
| Enterprise-only platforms | Community Preview — free and open source |

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

## Audit Evidence Packs — v0.3.0+

Auditors across SOC 2, ISO 27001, HIPAA and DPDP ask for the same thing: proof of a documented, risk-based vulnerability management process. The most common audit gap is showing thousands of findings with no evidence of how they are prioritized, tracked, and resolved.

VulnPilot generates that evidence in one command:

```bash
# SOC 2 CC7.1 evidence pack
vulnpilot analyze scan.csv --evidence soc2

# ISO 27001 Annex A 8.8 evidence pack — NEW in v0.5.0
vulnpilot analyze scan.csv --evidence iso27001
```

The evidence pack includes:
- Scan metadata — timestamped, with source file reference
- The documented prioritization methodology (KEV / EPSS / CVSS weights)
- Prioritized findings with KEV flags
- Framework control mapping statement (SOC 2 CC7.1 or ISO 27001 A.8.8)
- Management review and sign-off block
- **SLA compliance and exception register** — when run via `vulnpilot verify` (see below)

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

To customize, create `~/.patchvex/sla.yaml`:

```yaml
# VulnPilot SLA policy — days to remediate by severity
critical: 7
high: 30
medium: 90
low: 180
```

VulnPilot reads this file automatically on every `verify` run. If the file does not exist, the defaults above apply.

---

## Local Scan History — NEW in v0.3.0

Every analysis run is automatically recorded to a local SQLite database at `~/.vulnpilot/history.db` — on your machine only, never transmitted.

Why this matters: SOC 2 Type II audits require evidence that your process operated consistently over a 6–12 month observation period. That history cannot be recreated retroactively. VulnPilot starts building your evidence trail from your very first scan.

Upcoming releases use this history for remediation verification (`vulnpilot verify`) and trend reporting.

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

**Docs:** [Quick Start](docs/quickstart.md) · [Evidence Packs](docs/evidence-packs.md) · [Scoring](docs/scoring.md) · [FAQ](docs/faq.md)

---

## Install

```bash
pip install vulnpilot
```

Tested on Python 3.10, 3.11, and 3.12.

---

## Usage

```bash
# Download latest KEV and EPSS feeds
vulnpilot update-feeds

# Analyze a Nessus CSV export
vulnpilot analyze scan.csv

# Generate a SOC 2 audit evidence pack
vulnpilot analyze scan.csv --evidence soc2

# Generate an ISO 27001 audit evidence pack — NEW in v0.5.0
vulnpilot analyze scan.csv --evidence iso27001

# Verify remediation against your previous scan
# — now includes SLA compliance block showing within / approaching / breached counts
vulnpilot verify new_scan.csv

# Verify with exception register — NEW in v0.5.0
# Classifies SLA breaches as approved, expired, or unexcused (audit finding)
vulnpilot verify new_scan.csv --exceptions exceptions.csv

# Verify + evidence pack with full governance section — NEW in v0.5.0
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

**Docs:** [Quick Start](docs/quickstart.md) · [Evidence Packs](docs/evidence-packs.md) · [Scoring](docs/scoring.md) · [FAQ](docs/faq.md)

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

**v0.1.0 — Community Preview ✅**
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

**Later**
- [ ] DPDP and HIPAA evidence packs
- [ ] Qualys CSV support
- [ ] SLA breach as CI exit code gate
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

## Looking for early users

If you run Nessus or Qualys and are willing to test VulnPilot on a real scan
(non-production exports welcome), your feedback directly shapes the roadmap.
Open a [GitHub issue](https://github.com/PatchVex/vulnpilot/issues), start a
[Discussion](https://github.com/PatchVex/vulnpilot/discussions), or email
hello@patchvex.com. Ten minutes of your honest reaction is worth more than
a hundred stars.

## Contributing

Issues, bug reports, and pull requests are welcome.

- **Bug reports and feature requests:** [github.com/PatchVex/vulnpilot/issues](https://github.com/PatchVex/vulnpilot/issues)
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