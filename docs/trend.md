# Posture Trend

`vulnpilot trend` shows your vulnerability posture over time, drawn from the
local scan history database at `~/.vulnpilot/history.db`.

## Usage

```bash
vulnpilot trend
```

## Example output

```
  VulnPilot — Posture Trend

  Date          Findings    KEV  Critical
  ───────────────────────────────────────
  2026-06-01          42      6        12
  2026-06-15          38      5        10
  2026-07-01          31      3         8
  2026-07-15          27      2         6
  ───────────────────────────────────────
  Since first scan: findings ▼ down 15, KEV ▼ down 4
```

Each row is one `analyze` or `verify` run recorded in your local history.

## What it shows

| Column | Description |
|---|---|
| Date | UTC date of the scan run |
| Findings | Total findings evaluated in that scan |
| KEV | CISA KEV-confirmed findings in that scan |
| Critical | Scanner-rated Critical findings |

The summary line at the bottom compares your most recent scan against your
first recorded scan — a quick indicator of whether your posture is improving.

## How history is built

Every `vulnpilot analyze` and `vulnpilot verify` run is silently recorded to
`~/.vulnpilot/history.db`. No action required — the trend starts from your
first run.

## Why this matters for audits

SOC 2 Type II audits require evidence that your vulnerability management
process operated consistently over a 6–12 month observation period. This
history cannot be recreated retroactively.

Run `vulnpilot analyze scan.csv` on a regular schedule — weekly or after
each scan cycle — to build a continuous evidence trail. Include a trend
snapshot in your quarterly evidence pack to demonstrate consistent operation
over time.

## Resetting history

To start fresh:

```bash
rm ~/.vulnpilot/history.db
```

Note: this permanently removes your audit trail. Do not delete the database
before extracting any evidence you need for ongoing audits.

## Querying history directly

The database is a standard SQLite file. Advanced users can query it directly:

```bash
sqlite3 ~/.vulnpilot/history.db \
  "SELECT timestamp_utc, total_findings, kev_count, critical_count FROM scan_history ORDER BY timestamp_utc;"
```

Schema:

```sql
CREATE TABLE scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc   TEXT NOT NULL,
    scan_file_name  TEXT,
    scan_file_hash  TEXT,
    total_findings  INTEGER,
    kev_count       INTEGER,
    critical_count  INTEGER,
    high_count      INTEGER,
    findings_json   TEXT
);
```
