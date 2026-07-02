# Quick Start

Get from a Nessus export to a prioritized remediation list in under two minutes.

## 1. Install

```bash
pip install vulnpilot
```

Python 3.10, 3.11, or 3.12 required.

## 2. Download threat intelligence feeds

```bash
vulnpilot update-feeds
```

This fetches two public datasets to `~/.vulnpilot/feeds/`:
- CISA KEV — vulnerabilities confirmed exploited in the wild
- FIRST EPSS — exploitation probability scores

No API keys. No account. Re-run whenever you want fresh data.

## 3. Analyze your scan

```bash
vulnpilot analyze scan.csv
```

Where `scan.csv` is a standard Nessus CSV export
(Scans → your scan → Export → CSV).

You get a prioritized findings table: KEV-confirmed vulnerabilities first,
then high-EPSS findings, with a composite score explained in
[scoring.md](scoring.md).

## 4. Generate outputs

```bash
# Shareable HTML report
vulnpilot analyze scan.csv --html report.html

# SOC 2 audit evidence pack
vulnpilot analyze scan.csv --evidence soc2
```

## Try it without a Nessus scan

A sample export ships in the repo:

```bash
git clone https://github.com/PatchVex/vulnpilot
cd vulnpilot
vulnpilot analyze data/sample/sample_nessus.csv --evidence soc2
```

## Privacy

Everything runs locally. Your scan data never leaves your machine.
Scan history is stored at `~/.vulnpilot/history.db` — local only,
delete it anytime.
