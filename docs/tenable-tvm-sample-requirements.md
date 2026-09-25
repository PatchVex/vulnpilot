# Tenable Vulnerability Management — sample export needed

VulnPilot does not support Tenable Vulnerability Management (TVM) exports yet.
Before a parser is written we need one **real, scrubbed** Findings CSV export.
Nothing below should be implemented from documentation alone.

- **OBSERVED** — stated in Tenable's public documentation (source linked).
- **REQUIRED TO VERIFY** — must be confirmed from the real export.

## The export

| Item | Status |
|---|---|
| Exported from the Findings page, as CSV or JSON | OBSERVED — [Findings export fields](https://docs.tenable.com/vulnerability-management/Content/Explore/export-findings-csv-keys.htm) |
| Tenable product name and version the sample came from | REQUIRED TO VERIFY |
| Exact export path/menu used, and any export options chosen | REQUIRED TO VERIFY |
| Whether the CSV header row uses the CSV keys below (e.g. `first_observed`) or the UI labels (e.g. `First Seen`) | REQUIRED TO VERIFY |
| File encoding (UTF-8? BOM?) and delimiter | REQUIRED TO VERIFY |

## Fields

UI label → CSV key are from Tenable's [Vulnerabilities Findings Export Mappings](https://docs.tenable.com/other/vulnerability-management/VulnerabilitiesFindingsExportMapping.csv) (OBSERVED). Everything about the values is REQUIRED TO VERIFY.

| UI label | CSV key (OBSERVED) | REQUIRED TO VERIFY from the sample |
|---|---|---|
| First Seen | `first_observed` | Date/time format and timezone. Whether it is kept or reset when a finding resurfaces. Tenable describes it as "Date and time Tenable first detected the vulnerability on this asset" ([Findings Details](https://docs.tenable.com/vulnerability-management/Content/Explore/findings-details-vulnerabilities.htm), OBSERVED) |
| Last Seen | `last_seen` | Format; relation to the export time |
| Last Fixed | `last_fixed` | Format; empty for never-fixed findings? |
| State | `state` | Exact values in the file (UI states are New, Active, Fixed, Resurfaced — [Vulnerability States](https://docs.tenable.com/vulnerability-management/Content/Explore/Findings/VulnerabilityStates.htm), OBSERVED) |
| Asset Name | `asset.name` | What it contains (hostname, FQDN, IP?) and whether it is always set |
| IPv4 Address | `asset.display_ipv4_address` | Single value or list; empty for some assets? |
| Host | `asset.host_name` | Populated or not; relation to Asset Name |
| FQDN | `asset.display_fqdn` | Single value or list |
| Asset ID | `asset.id` | UUID format; stable across exports |
| Plugin ID | `definition.id` | Same numbering as Nessus plugin IDs? |
| Port | `port` | Value for host-level findings (VulnPilot's Nessus sample uses `0`) |
| Protocol | `protocol` | Values (`tcp`/`udp`/`TCP`?) |
| CVE | `definition.cve` | One per row, or a list in one cell — and its separator/format |
| Severity | `severity` | Exact values, including the informational level and its spelling |

Also useful if present: plugin/definition name, synopsis, solution, CVSS v3/v2 base score — note their exact header and format.

## What the sample must contain

- At least one finding in each state present in the account: **active**, **fixed**, and — if at all possible — one that was **fixed and later resurfaced** (to settle whether First Seen resets).
- At least one **host-level** finding (no service port) and one on a service port.
- At least one finding with **several CVEs**, and one with **none**.
- At least one asset with **no FQDN** or **no IPv4**, if such assets exist.
- Several rows for the **same asset**, so identity handling can be checked.
- An informational-severity finding, if the export includes them.

## Scrubbing

Keep the header row, column order, date formats and value formats **exactly** as exported. Replace real hostnames, IPs, FQDNs and asset UUIDs consistently (the same real value always maps to the same fake value, across all columns), and remove anything customer-identifying. A few dozen rows are enough. Do not commit an unscrubbed export.

## Open decision (not to be settled by the sample)

Whether a scanner-provided First Seen should ever replace VulnPilot's own first-seen date for SLA purposes. Today SLA clocks start when VulnPilot first records a finding, and that stays unchanged until this is explicitly decided.
