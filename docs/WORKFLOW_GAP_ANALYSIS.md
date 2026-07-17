# Workflow Gap Analysis

> Source: Consultant workflow map modeled 2026-07-17.
> Persona: Security consultant managing 10 SMB clients, quarterly vulnerability review cycle, Nessus scanner.
> Purpose: Identify which workflow steps PatchVex automates today, which are partial, and which are gaps.
> Confidence ratings are honest assessments of how the workflow step was derived — not feature confidence.

---

## Confidence Key

| Rating | Meaning |
|---|---|
| High | Directly observed or confirmed by running PatchVex against real scan data |
| Medium | Inferred from knowledge of Nessus workflows, audit requirements, and tooling — plausible but unconfirmed by a real consultant |
| Low | Assumed based on general consulting context — needs direct practitioner validation |
| Unvalidated | No evidence either way — specific to consultant personas not yet observed |

---

## The Workflow

| # | Step | Manual Today | PatchVex Today | Gap | Priority | Confidence | Validation Needed |
|---|---|---|---|---|---|---|---|
| 1.1 | Schedule scan window | Email/Slack/calendar with client IT contact | None | Full gap | — | Low | Do consultants own the scan schedule or does client IT? How much coordination is actually required? |
| 1.2 | Run or trigger Nessus scan | Login to Nessus via VPN, launch scan manually | None | Full gap — outside PatchVex scope by design | — | High | Confirmed: PatchVex starts after scan completes |
| 1.3 | Export Nessus CSV | Nessus web UI → Reports → Export CSV | None | Full gap — manual trigger required | Medium | High | Confirmed: PatchVex requires CSV as input. Are there consultants using `.nessus` XML instead of CSV? |
| 2.1 | Load into spreadsheet, clean columns | Excel/Google Sheets, delete ~50 irrelevant columns, format | **Solved** — PatchVex ingests CSV and structures output automatically | Gap remains for Excel delivery — PatchVex outputs Markdown, not `.xlsx` | High | High | Confirmed by running `vulnpilot analyze` against sample data. Gap: do consultants need to deliver Excel to clients? |
| 2.2 | Deduplicate findings | Manual pivot table or VLOOKUP by Plugin ID | **Partial** — PatchVex treats each host/port/plugin combination as distinct (correct for SLA) but does not group by root cause for executive summary | No plugin-level deduplication for reporting purposes | Medium | Medium | Unvalidated: do consultants actually need root-cause grouping, or is per-host tracking sufficient? |
| 2.3 | Compare to last quarter's findings | Two spreadsheets side by side, VLOOKUP or manual | **Solved** — `vulnpilot verify` classifies findings as remediated, persistent, or new using local scan history | History compares to immediately previous scan only — cannot compare to arbitrary past scan | High | High | Confirmed by running `vulnpilot verify` against sample data. Gap: do consultants need multi-quarter lookback beyond the previous scan? |
| 3.1 | Sort and filter by severity | Excel sort by CVSS/severity, filter to Critical+High | **Solved** — composite KEV+EPSS+CVSS scoring produces a priority ranking automatically | No internet-facing vs. internal asset weighting (context not in CSV) | High | High | Confirmed: composite scoring works. Gap unvalidated: how much do consultants weight asset exposure in manual triage? |
| 3.2 | Cross-reference CISA KEV catalog | Manual lookup at cisa.gov or VLOOKUP against downloaded KEV CSV — often skipped | **Solved** — KEV cross-reference applied automatically on every run | None | High | High | Confirmed by running analysis. Validates that PatchVex does something consultants often skip entirely. |
| 3.3 | Apply EPSS scoring | FIRST.org API or Python script — almost always skipped by SMB consultants | **Solved** — EPSS fetched and applied automatically | None — but EPSS fetch requires internet connection; air-gapped use breaks this | High | High | Confirmed technically. Unvalidated: do SMB security consultants know what EPSS is? Does the output make EPSS legible to a non-expert? |
| 4.1 | Filter findings by in-scope asset list | Manual deletion of out-of-scope rows in spreadsheet | **Not implemented** | PatchVex analyzes all findings in the CSV regardless of scope | Medium | Medium | Unvalidated: how often do Nessus scans include out-of-scope hosts? Is this a real friction point or rare? |
| 4.2 | Check status of existing remediation tickets | Manual cross-reference between Nessus export and Jira/ServiceNow/spreadsheet | **Not implemented** | No ticketing system integration. Largest unaddressed time sink: estimated 60–180 min/client/quarter | High | Medium | Unvalidated: what ticketing systems do SMB clients actually use? Is it Jira, or more often a shared spreadsheet or GitHub Issues? |
| 4.3 | Calculate SLA compliance per finding | Excel date formula (today − first_seen_date), first-seen sourced from prior spreadsheet | **Solved** — SLA engine calculates days-open using scan history, applies severity-based thresholds from sla.yaml | SLA config is one file — running for 10 clients with different SLA policies requires 10 configs or per-run override | High | High | Confirmed technically. Gap (10-client config management) is inferred — unvalidated whether consultants use uniform SLA policy across all clients or customize per client. |
| 5.1 | Review exception register from last quarter | Exception register spreadsheet or Word doc reviewed manually against current findings | **Solved** — `--exceptions exceptions.csv` loads the register and auto-classifies findings as approved, expired, or no-exception | Consultant still maintains the CSV manually. PatchVex reads it, does not create or manage it. | High | High | Confirmed by running with sample_exceptions.csv. Gap: is CSV the right format or would consultants prefer a different input format? |
| 5.2 | Obtain approval for new risk exceptions | Email, ticket, or verbal approval from client management — then documented manually | **Not implemented** — PatchVex cannot facilitate approval workflow | Full gap by design: approval is a human governance decision | — | High | Confirmed: this is outside scope and appropriate to leave manual |
| 6.1 | Write executive summary narrative | Word/Google Docs, template with manual placeholders | **Not implemented** — PatchVex produces structured data, not prose narrative | Gap: consultant still writes the client-facing narrative from PatchVex output | Medium | Medium | Unvalidated: do consultants deliver a separate client-facing narrative, or do they share the evidence pack directly? |
| 6.2 | Assemble audit evidence pack | Multi-source assembly in Word/Google Docs: scan metadata + methodology description + findings table + exception register + sign-off block | **Solved** — `vulnpilot verify --evidence soc2` generates a complete structured evidence pack as Markdown | Management sign-off table is blank — must be filled in manually. Remediation ownership records (ticket assignments) must be appended separately. | High | High | Confirmed against sample data. Gap validation: would a real auditor accept this output as-is, or would they require reformatting? |
| 6.3 | Collect supplementary evidence | Vulnerability management policy document, ticket export, previous quarters' packs | **Partial** — `vulnpilot trend` provides operational history for Type II consistency evidence. Policy document and ticket export remain manual. | No policy document generation. No ticketing export integration. | Medium | High | Confirmed: trend output exists and is accurate. Whether auditors accept trend output as Type II consistency evidence is unvalidated. |
| 7.1 | Internal QC review before delivery | Manual read-through for consistency between narrative and underlying data | **Implicit improvement** — because PatchVex generates the evidence from the same data used for analysis, numbers are inherently consistent; copy-paste errors between spreadsheet and document are eliminated | No explicit QC step or validation output | Low | Medium | Inferred benefit — not directly observed or measured |
| 7.2 | Client review call | Screenshare walkthrough of findings with client IT contact | None — human communication | Full gap by design | — | High | N/A |
| 7.3 | Auditor submission | Upload to audit portal or email | None | Full gap by design | — | High | N/A |

---

## Summary

### Already solved by PatchVex

Steps 2.1, 2.3, 3.1, 3.2, 3.3, 4.3, 5.1, 6.2

Estimated time saved: **5–7 hours per client per quarter** (based on modeled workflow — unvalidated against real consultant timing).

### Partially solved

Steps 2.2, 6.3

### Not implemented (gaps)

| Gap | Estimated time cost | Confidence in estimate | Notes |
|---|---|---|---|
| Ticket status check (4.2) | 60–180 min/client | Medium | Largest single gap. Requires ticketing API integration. |
| In-scope asset filtering (4.1) | 10–30 min/client | Low | Depends on how often Nessus over-scans — unvalidated |
| Executive narrative (6.1) | 30–60 min/client | Medium | Could be partially addressed with structured output that consultants can adapt |
| Multi-client SLA config (4.3 gap) | Setup time only | Low | One config file per client is a workaround, not a blocker |
| Excel output (2.1 gap) | Variable | Low | Only relevant if consultants need to deliver Excel to clients — unvalidated |

### Outside scope by design

Steps 1.1, 1.2, 1.3, 5.2, 7.2, 7.3

---

## What needs validation from a real practitioner

These are the assumptions that will most change product priorities if they're wrong:

1. **Do SMB security consultants use Nessus CSV export as their primary data format, or do they use `.nessus` XML, Tenable.io API, or something else?** If CSV is not the norm, the entire input model needs rethinking.

2. **Do consultants manage separate SLA policies per client, or do they apply a standard policy across all clients?** This determines whether per-client SLA config is a real friction point.

3. **What ticketing system do the SMB clients actually use?** If the answer is "a shared Google Sheet" or "GitHub Issues," a Jira API integration is not the right next feature.

4. **Would a real auditor accept the `vulnpilot verify --evidence soc2` output as CC7.1 evidence without reformatting?** This is the most important validation question. Everything else is secondary.

5. **Do consultants deliver a separate executive narrative to the client, or do they share the evidence pack directly?** This determines whether a prose generation feature has value.

6. **How much time do consultants actually spend on each step?** The 12–18 hours/client/quarter estimate is modeled, not measured.
