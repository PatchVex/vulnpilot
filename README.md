# VulnPilot

**Prioritize vulnerabilities using real-world exploit intelligence — not just severity scores.**

Runs locally. Your data never leaves your machine.

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
| Scrambling for audit evidence | One-command audit evidence pack |
| Uploading scans to cloud services | Local-first — data never leaves your machine |
| Enterprise-only platforms | Community Preview — free and open source |

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

## Audit Evidence Pack — NEW in v0.3.0

Auditors across SOC 2 (CC7.1), ISO 27001 (A.8.8), HIPAA and DPDP all ask for the same thing: proof of a documented, risk-based vulnerability management process. The most common audit gap is showing thousands of findings with no evidence of how they are prioritized.

VulnPilot generates that evidence in one command:

```bash
vulnpilot analyze scan.csv --evidence soc2
```

The evidence pack includes:
- Scan metadata — timestamped, with source file reference
- The documented prioritization methodology (KEV / EPSS / CVSS weights)
- Prioritized findings with KEV flags
- SOC 2 CC7.1 control mapping statement
- Management review and sign-off block

Output is a clean Markdown file — convert to PDF with your tool of choice and hand it to your auditor.

**Currently supported:** SOC 2 (CC7.1). ISO 27001, DPDP, and HIPAA packs are next on the roadmap.

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

# Evidence pack with custom output path
vulnpilot analyze scan.csv --evidence soc2 --evidence-out q3_evidence.md

# Export HTML report
vulnpilot analyze scan.csv --html report.html

# Show top N hosts by aggregate risk
vulnpilot analyze scan.csv --top-hosts 5

# Use local feed files
vulnpilot analyze scan.csv --kev ./kev.json --epss ./epss.csv.gz

# Disable colour output (for CI pipelines)
vulnpilot analyze scan.csv --no-colour
```

---

## HTML Report

Generate a shareable, self-contained HTML report:

```bash
vulnpilot analyze scan.csv --html report.html
```

The report includes:
- Executive summary with KEV and EPSS highlights
- Prioritized findings table with colour-coded risk scores
- Top 10 hosts by aggregate risk with visual score bars

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

**v0.4.0 — Next**
- [ ] Remediation verification — `vulnpilot verify` (prove findings were fixed)
- [ ] Trend reporting across scan history
- [ ] ISO 27001 evidence pack

**Later**
- [ ] DPDP and HIPAA evidence packs
- [ ] Plain-English remediation guidance
- [ ] Weekly digest
- [ ] Qualys CSV support
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