# How Scoring Works

## The composite score

Each finding receives a 0–100 score from four signals:

| Signal | Weight | Why |
|---|---|---|
| CISA KEV match | 40% | Confirmed exploited in the wild — the strongest priority signal available |
| FIRST EPSS | 35% | ML-modeled probability of exploitation in the next 30 days |
| CVSS base score | 15% | Severity context |
| Scanner severity | 10% | Scanner's own risk label |

## The KEV floor

Any finding in the CISA KEV catalog scores a **minimum of 75** regardless of
other factors. Active exploitation overrides theoretical severity.

## Priority labels

| Score | Label |
|---|---|
| KEV match | CRITICAL NOW |
| 75–100 | CRITICAL NOW |
| 50–74 | HIGH |
| 25–49 | MEDIUM |
| 0–24 | LOW |

## Determinism

The same inputs always produce the same ranking. There is no hidden model
and no randomness — a property auditors specifically look for when they
test reproducibility.

## What the score is not

The score does not know your business context: asset criticality,
compensating controls, or exposure. It answers "what does real-world threat
intelligence say to fix first" — final remediation decisions belong to your
team.
