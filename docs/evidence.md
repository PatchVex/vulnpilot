# Audit Evidence Packs

## Why this exists

Auditors reviewing vulnerability management ask for the same artifacts across
frameworks: scan reports, a documented prioritization methodology, and
remediation records. The most common audit gap is presenting thousands of
findings with no proof of how they were prioritized or tracked.

VulnPilot generates that proof in one command.

## Usage

```bash
# SOC 2 CC7.1 — from analyze
vulnpilot analyze scan.csv --evidence soc2

# ISO 27001 A.8.8 — from analyze
vulnpilot analyze scan.csv --evidence iso27001

# Custom output path
vulnpilot analyze scan.csv --evidence iso27001 --evidence-out q3_iso_evidence.md

# With verification and governance section
vulnpilot verify new_scan.csv --evidence soc2

# Full governance pack: verification + SLA + exception register
vulnpilot verify new_scan.csv --exceptions exceptions.csv --evidence soc2
```

## What the pack contains

Every evidence pack includes the following sections:

1. **Scan metadata** — timestamp, source file, generation method
2. **Control objective** — the framework control text being evidenced
3. **Scan summary** — totals, KEV matches, critical counts, high-EPSS counts
4. **Prioritization methodology** — the documented KEV/EPSS/CVSS weighting,
   deterministic and auditor-reproducible
5. **Prioritized findings** — top 25 findings with scores and KEV flags
6. **Control mapping statement** — how this evidence supports the specific control
7. **Management review and sign-off** — blank table for signature

When generated via `vulnpilot verify`, the pack also includes:

4b. **Remediation verification** — findings verified fixed vs still open vs new,
with scope-guard methodology documented

4c. **SLA compliance and exception register** — framework-agnostic governance
posture table (see below)

Output is Markdown. Convert to PDF with pandoc, VS Code, or any
Markdown-to-PDF tool, then route for signature.

## Completing the evidence pack

VulnPilot generates the technical evidence. Before submitting to an auditor,
complete these steps:

**1. Fill in the management review table**

Open the generated `.md` file and locate the sign-off section at the bottom.
Fill in the names and dates of the people who conducted and reviewed the scan
cycle. Print or export to PDF after signing.

**2. Add remediation ownership records**

The evidence pack shows what was prioritized. Auditors for CC7.1 and A.8.8
will also ask who was assigned to fix each finding, and when. Attach your
Jira export, ServiceNow ticket list, or equivalent as an appendix.

**3. Link exceptions to formal risk acceptance**

Each exception in your register should correspond to a formally approved
risk acceptance in your risk register or GRC tool. Auditors will trace
exception ticket references (e.g. `JIRA-4521`) back to management approval.
Include the approval record or a reference to it alongside the evidence pack.

**4. Establish a regular cadence**

For SOC 2 Type II and ISO 27001 surveillance audits, a single pack is not
sufficient — auditors want evidence of consistent operation. Run
`vulnpilot analyze` or `vulnpilot verify` on a regular schedule and generate
evidence packs at least quarterly. The `vulnpilot trend` output documents
your history across the observation period.

## Supported frameworks

| Framework | Control | Status |
|---|---|---|
| SOC 2 | CC7.1 — System Operations | ✅ Supported |
| ISO 27001:2022 | Annex A 8.8 — Management of Technical Vulnerabilities | ✅ Supported |
| DPDP (India) | Section 8(5) | Planned |
| HIPAA | §164.308(a) | Planned |

## Governance section (§ 4c)

When the pack is generated via `vulnpilot verify`, a framework-agnostic
**SLA compliance and exception register** section is automatically included.
It is identical across SOC 2, ISO 27001, and all future frameworks — the same
governance evidence satisfies all of them.

The section shows:

| Status | Description |
|---|---|
| Within SLA | Findings within the remediation deadline |
| Breached — approved exception | Breach exists but a valid approved exception is on file |
| Breached — exception expired | Exception existed but has lapsed — audit finding |
| Breached — no exception on file | Breach with no documented approval — audit finding |
| No history data | Finding seen for first time in this scan; SLA clock starting |

If audit findings exist (expired or missing exceptions), the section states
the count explicitly and notes that each requires remediation or a formally
approved exception before the next audit cycle.

### Without `--exceptions`

The governance section still appears. Breached findings are classified as
`breached_no_exception` because no exception register was loaded. This is the
correct governance state — it reflects that no formal exceptions are on file.

### With `--exceptions`

```bash
vulnpilot verify new_scan.csv --exceptions exceptions.csv --evidence soc2
```

Breaches are matched against the exception register and reclassified where
valid approvals exist.

## Exception register CSV format

The exception register is a plain CSV file with the following columns:

| Column | Required | Description |
|---|---|---|
| `host` | Yes | IP address or hostname (must match scan data exactly) |
| `plugin_id` | Yes | Nessus plugin ID |
| `port` | Yes | Port number |
| `ticket_ref` | Yes | Ticket or change reference (e.g. `JIRA-4521`) |
| `approver` | Yes | Name or role of approver (e.g. `CISO`) |
| `approved_date` | No | Date approved (`YYYY-MM-DD`) |
| `expiry_date` | No | Date exception expires (`YYYY-MM-DD`); blank = no expiry |
| `reason` | No | Free-text reason |

Example:

```csv
host,plugin_id,port,ticket_ref,approver,approved_date,expiry_date,reason
192.168.1.10,33850,443,JIRA-4521,CISO,2026-07-01,2026-12-31,vendor patch unavailable
192.168.1.25,19506,0,JIRA-4522,CISO,2026-07-01,,compensating control in place
```

A finding is matched by the combination of `(host, plugin_id, port)`. An
exception is considered valid if `approver` and `ticket_ref` are non-empty
and `expiry_date` has not passed. An exception with a past `expiry_date` is
classified as `breached_expired` and treated as an audit finding.

## Scan history and Type II audits

Every `analyze` and `verify` run is recorded locally at `~/.vulnpilot/history.db`.
SOC 2 Type II audits require evidence that your process operated consistently
over a 6–12 month observation period — history that cannot be recreated
retroactively. Your evidence trail starts with your first scan.

The pack states the number of recorded runs and the date of the first scan.
