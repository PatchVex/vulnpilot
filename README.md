# VulnPilot

**Prioritize vulnerabilities using real-world exploit intelligence — not just severity scores.**

Runs locally. Your data never leaves your machine.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![Status: Developer Preview](https://img.shields.io/badge/status-developer%20preview-orange.svg)]()
[![Version: 0.1.0](https://img.shields.io/badge/version-0.1.0-blue.svg)]()

---

## Quick Start

```bash
pip install vulnpilot
vulnpilot update-feeds
vulnpilot analyze scan.csv
```

VulnPilot downloads the latest public threat intelligence, analyzes your Nessus scan locally, and shows what should be remediated first. No API keys required.

---

## Features

- Local-first vulnerability prioritization — scan data never leaves your machine
- CISA KEV enrichment — flags findings confirmed exploited in the wild
- FIRST EPSS enrichment — exploitation probability scoring
- Composite risk scoring — KEV + EPSS + CVSS combined
- Top vulnerable hosts ranked by aggregate risk
- Zero cloud upload, zero telemetry, zero account required
- GitHub Actions daily feed automation
- Open source Community Edition — MIT licensed

---

## The problem

Security teams often spend hours manually triaging scan results. Your Nessus export contains thousands of findings. CVSS says hundreds are Critical. The real question — which ones are actively being exploited right now?

VulnPilot automates this process in seconds on typical scan files.

---

## Why VulnPilot?

| Instead of | VulnPilot |
|---|---|
| Sorting by CVSS score alone | Uses KEV + EPSS + CVSS composite scoring |
| Manual triage taking hours | Automated prioritization in seconds |
| Uploading scans to cloud services | Local-first — data never leaves your machine |
| Enterprise-only platforms | Developer Preview — free and open source |

---

## Why local-first?

Many organizations prohibit uploading vulnerability scan data to third-party cloud services. VulnPilot performs all analysis locally on your machine.

No customer vulnerability data is transmitted outside your environment.

---

## Architecture

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
         Prioritized Findings
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

# Show top N hosts by aggregate risk
vulnpilot analyze scan.csv --top-hosts 5

# Use local feed files
vulnpilot analyze scan.csv --kev ./kev.json --epss ./epss.csv.gz

# Disable colour output (for CI pipelines)
vulnpilot analyze scan.csv --no-colour
```

---

## Example output

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

  TOP 10 HOSTS BY AGGREGATE RISK
   1. 192.168.1.10    score=122.0 [1 KEV] [1 critical]
   2. 192.168.1.25    score=100.0 [1 KEV] [1 critical]
   3. 192.168.1.15    score=99.8  [1 KEV] [1 critical]
```

---

## How scoring works

The scoring algorithm is deterministic, transparent, and fully documented.

VulnPilot uses a composite risk score that combines four signals:

| Signal | Weight | Source |
|---|---|---|
| CISA KEV match | 40% | Known exploited in the wild |
| FIRST EPSS score | 35% | Exploitation probability |
| CVSS base score | 15% | Severity context |
| Scanner risk rating | 10% | Nessus severity label |

The composite score is intentionally opinionated. Known exploited vulnerabilities receive the greatest weight because active exploitation is a stronger predictor of remediation priority than severity alone. EPSS estimates exploitation likelihood in the next 30 days, while CVSS and scanner severity provide additional context for findings without EPSS data.

Any finding confirmed in the CISA KEV catalog scores a minimum of 75 regardless of other factors. The weighting model is intentionally transparent and may evolve based on community feedback and real-world usage.

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

The GitHub repository also runs an automated daily feed sync via GitHub Actions, publishing optimized feed files for the CLI to consume.

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

**Current — v0.1.0 (Developer Preview)**
- [x] Nessus CSV parser
- [x] CISA KEV enrichment
- [x] FIRST EPSS enrichment
- [x] Composite risk scoring
- [x] Prioritized terminal output
- [x] Top hosts by aggregate risk
- [x] Free tier — top 20 findings
- [x] GitHub Actions daily feed automation

**v0.2.0**
- [ ] HTML report export
- [ ] PDF report export

**v0.3.0**
- [ ] Jira integration
- [ ] Slack notifications
- [ ] Scheduled scans

**v0.4.0**
- [ ] Qualys CSV support
- [ ] REST API

**v1.0.0**
- [ ] Rapid7 and OpenVAS support
- [ ] Self-hosted Docker edition
- [ ] Team features

Future development priorities will be driven by community feedback and real-world usage.

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

MIT License — see [LICENSE](LICENSE) for details.

Free to use, modify, and distribute. Commercial use permitted.

---

## About PatchVex

VulnPilot is built and maintained by [PatchVex](https://patchvex.com).

PatchVex builds privacy-first workflow tools for security and DevSecOps teams. Our products help engineers spend less time managing vulnerability data and more time fixing the issues that matter.

- Website: [patchvex.com](https://patchvex.com)
- Email: hello@patchvex.com
- GitHub: [github.com/PatchVex](https://github.com/PatchVex)
