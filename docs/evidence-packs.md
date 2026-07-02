# Audit Evidence Packs

## Why this exists

Auditors reviewing vulnerability management ask for the same artifacts across
frameworks: scan reports, a documented prioritization methodology, and
remediation records. The most common audit gap is presenting thousands of
findings with no proof of how they were prioritized.

VulnPilot generates that proof in one command.

## Usage

```bash
vulnpilot analyze scan.csv --evidence soc2
vulnpilot analyze scan.csv --evidence soc2 --evidence-out q3_evidence.md
```

## What the pack contains

1. **Scan metadata** — timestamp, source file, generation method
2. **Control objective** — the framework control text being evidenced
3. **Scan summary** — totals, KEV matches, critical counts, high-EPSS counts
4. **Prioritization methodology** — the documented KEV/EPSS/CVSS weighting,
   deterministic and auditor-reproducible
5. **Prioritized findings** — top findings with scores and KEV flags
6. **Control mapping statement** — how this evidence supports the control
7. **Sign-off block** — conducted-by / reviewed-by signature table

Output is Markdown. Convert to PDF with pandoc, VS Code, or any
Markdown-to-PDF tool, then route for signature.

## Supported frameworks

| Framework | Control | Status |
|---|---|---|
| SOC 2 | CC7.1 | ✅ Supported |
| ISO 27001:2022 | A.8.8 | Planned — next |
| DPDP (India) | Sec 8(5) | Planned |
| HIPAA | §164.308(a) | Planned |

## Scan history and Type II audits

Every `analyze` run is recorded locally at `~/.vulnpilot/history.db`.
SOC 2 Type II requires evidence your process operated over a 6–12 month
observation period — history that cannot be recreated retroactively.
Your evidence trail starts with your first scan.
