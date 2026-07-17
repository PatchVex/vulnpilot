# PatchVex — Final Thesis

> Frozen: 2026-07-17. Do not revise until real user evidence contradicts a specific claim.

---

## Who is PatchVex for?

**Primary:** Security consultants and fractional vCISOs managing vulnerability programs for multiple SMB clients (5–20 clients each), where each client is pursuing or maintaining SOC 2 Type II or ISO 27001 certification.

**Secondary:** Internal security engineers at SMBs (50–500 employees) who own the vulnerability management program and must produce audit evidence quarterly without a dedicated GRC team or expensive enterprise tooling.

**Not for:** Enterprise security teams with Tenable.io, Qualys, or Rapid7 at scale. MSSPs with formal SIEM and ticketing integrations. Organizations without Nessus.

---

## What problem does it solve?

A security consultant running quarterly vulnerability reviews for 10 SMB clients spends approximately 12–18 hours per client per quarter:

- Loading Nessus exports into spreadsheets
- Manually cross-referencing CISA KEV and calculating EPSS (or skipping it)
- Comparing current findings against last quarter to identify what was remediated vs. still open
- Calculating SLA compliance using date formulas across multiple spreadsheets
- Reviewing and classifying risk exceptions
- Assembling a structured audit evidence pack from multiple documents

**PatchVex eliminates 5–7 hours of that work per client per quarter** by automating the analysis, cross-referencing, SLA tracking, exception classification, and evidence pack generation from a single Nessus CSV export.

The output is not a dashboard. It is a structured, auditor-ready Markdown document that maps directly to SOC 2 CC7.1 and ISO 27001 Annex A 8.8 control requirements.

---

## What does it not do?

- Does not run scans. Requires a Nessus CSV export as input.
- Does not connect to ticketing systems (Jira, ServiceNow). Ticket status tracking remains manual.
- Does not manage assets or maintain an asset inventory.
- Does not replace a GRC tool (Vanta, Drata, Tugboat Logic).
- Does not generate executive narrative prose. Produces structured data and evidence, not client-facing reports.
- Does not query the Tenable.io or Tenable.sc APIs (export is manual).
- Does not filter findings by asset scope automatically (in-scope IP filtering not implemented).
- Does not approve, create, or track risk exceptions through a workflow. Records and classifies exceptions that already exist in a CSV.
- Does not produce Excel output. Output is Markdown.

---

## What makes it different?

**Local-first.** Scan data never leaves the machine. No SaaS account, no upload, no vendor access to client vulnerability data. This matters for consultants who handle confidential client infrastructure.

**Auditor-framed output.** Most tools produce dashboards for security teams. PatchVex produces evidence structured around the specific control language auditors use (CC7.1, A.8.8). The output is designed to be handed to an auditor, not interpreted by one.

**Composite prioritization.** KEV + EPSS + CVSS weighting, applied automatically, produces a defensible prioritization methodology that satisfies the "documented process" requirement most auditors check.

**Persistent history.** Every run is recorded locally. Quarter-over-quarter comparison and SOC 2 Type II operational consistency evidence are built in, not retroactively assembled.

**Free and open source.** No per-seat licensing. No procurement. A consultant can adopt it for all 10 clients with zero budget approval.

---

## What metrics will tell us we're succeeding?

These are leading indicators of genuine adoption, not vanity metrics.

| Metric | Threshold that matters | Why |
|---|---|---|
| GitHub issues filed | Any issue with a real use case described | Proves someone used it on real data |
| CLI error reports | Any error from real scan data (not sample data) | Proves production use |
| PyPI monthly downloads (non-mirror) | >100 unique IPs/month | Mirrors inflate numbers; real installs matter |
| Unsolicited GitHub stars | >50 stars without a launch event | Organic discovery |
| Email to hello@patchvex.com | Any inbound, any topic | Proves someone cared enough to reach out |
| Feature requests tied to real workflow gaps | Any request that matches a gap in this thesis | Validates the workflow model |
| Mentions in external communities | Reddit, Slack, Discord, newsletters | Third-party organic mention |

**The metric that matters most in the next 90 days:** A GitHub issue or email from someone who ran VulnPilot on their own (not sample) Nessus data and hit a real problem or had a real question. That single event is worth more than 1,000 PyPI downloads.

---

## What would falsify this thesis?

- If consultants who find PatchVex do not use it past the first run → the workflow model is wrong or the friction is too high.
- If the primary adopters are individual engineers, not consultants → the "consultant as first customer" assumption is wrong; reframe for internal teams.
- If the evidence pack output is not usable by auditors without significant editing → the output format is wrong for the actual audit interaction.
- If Nessus CSV is not the common export format (e.g., most consultants use the `.nessus` XML format or Tenable.io API) → the input format assumption is wrong.
