# Quick Start

Get from a Nessus export to a prioritized, audit-ready governance report.

## 1. Install

```bash
pip install vulnpilot
```

Python 3.10, 3.11, or 3.12 required.

## 2. Download threat intelligence feeds

```bash
vulnpilot update-feeds
```

Fetches two public datasets to `~/.vulnpilot/feeds/`:
- **CISA KEV** — vulnerabilities confirmed exploited in the wild
- **FIRST EPSS** — exploitation probability scores

No API keys. No account. Re-run whenever you want fresh data.

## 3. Analyze your scan

```bash
vulnpilot analyze scan.csv
```

Where `scan.csv` is a standard Nessus CSV export
(Scans → your scan → Export → CSV).

You get a prioritized findings table — KEV-confirmed vulnerabilities first,
then high-EPSS findings — with a composite score explained in
[scoring.md](scoring.md). Every run is recorded silently to a local history
database (`~/.vulnpilot/history.db`), which powers verification and trend
reporting.

## 4. Generate audit evidence

```bash
# SOC 2 CC7.1 evidence pack
vulnpilot analyze scan.csv --evidence soc2

# ISO 27001 Annex A 8.8 evidence pack
vulnpilot analyze scan.csv --evidence iso27001
```

Output is a Markdown file — convert to PDF and hand it to your auditor.
See [evidence-packs.md](evidence-packs.md) for what each pack contains.

## 5. Verify remediation (next scan cycle)

After your team remediates findings and you have a new scan, run:

```bash
vulnpilot verify new_scan.csv
```

VulnPilot diffs against your last recorded scan and shows:
- `✓ Verified fixed` — absent from new scan, host still in scope
- `● Still open` — present in both scans, with days open
- `+ New findings` — first seen in this scan
- **SLA compliance block** — within / approaching / breached counts per finding

Findings on hosts that disappeared from the new scan are never counted as fixed.

SLA thresholds default to Critical 7d / High 30d / Medium 90d / Low 180d and are
configurable at `~/.patchvex/sla.yaml`.

## 6. Track exceptions (governance workflow)

When an SLA breach has a documented approval on file, record it in an
exception register CSV:

```csv
host,plugin_id,port,ticket_ref,approver,approved_date,expiry_date,reason
192.168.1.10,33850,443,JIRA-4521,CISO,2026-07-01,2026-12-31,vendor patch unavailable
```

Then verify with the exception register:

```bash
vulnpilot verify new_scan.csv --exceptions exceptions.csv
```

The governance block now classifies each SLA breach as:
- `✓ Breached — approved exception` (valid ticket on file)
- `✗ Breached — exception expired` ← audit finding
- `✗ Breached — no exception on file` ← audit finding

The count of audit findings is shown explicitly so nothing is missed before
your next audit cycle.

## 7. Generate a full governance evidence pack

Combine verification, exception management, and evidence generation in one
command:

```bash
vulnpilot verify new_scan.csv --exceptions exceptions.csv --evidence soc2
```

The output pack contains:
- Prioritized findings
- Remediation verification results
- SLA compliance and exception register table (§ 4c)
- Control mapping statement and sign-off block

Replace `soc2` with `iso27001` for an ISO 27001 Annex A 8.8 pack.

## Try it without a Nessus scan

Sample exports ship in the repository:

```bash
git clone https://github.com/PatchVex/vulnpilot
cd vulnpilot

# First scan
vulnpilot analyze data/sample/sample_nessus.csv

# Second scan — verify remediation
vulnpilot verify data/sample/sample_nessus_after.csv --evidence soc2
```

## Privacy

Everything runs locally. Scan data never leaves your machine.
Scan history is stored at `~/.vulnpilot/history.db` — delete it anytime.
