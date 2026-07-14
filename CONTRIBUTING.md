# Contributing to VulnPilot

Thanks for your interest in improving VulnPilot. Contributions of all kinds are
welcome — bug reports, documentation fixes, scanner parsers, and new evidence
frameworks.

## Getting started

```bash
git clone https://github.com/PatchVex/vulnpilot
cd vulnpilot
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

All 57+ tests should pass before you start. Python 3.10, 3.11, and 3.12 are
supported — CI runs the suite on all three.

## Try it on sample data

```bash
vulnpilot analyze data/sample/sample_nessus.csv
vulnpilot verify data/sample/sample_nessus_after.csv --exceptions data/sample/sample_exceptions.csv
```

## Project layout

| Path | Responsibility |
|---|---|
| `vulnpilot/cli.py` | Argument parsing and orchestration only — no business logic |
| `vulnpilot/parser/` | Scanner CSV parsers (Nessus today) |
| `vulnpilot/enrich/` | KEV and EPSS feed handling |
| `vulnpilot/scoring/` | Composite risk scoring |
| `vulnpilot/sla.py` | SLA engine — breach detection against policy |
| `vulnpilot/exceptions.py` | Exception register and governance classification |
| `vulnpilot/verify.py` | Remediation verification and terminal rendering |
| `vulnpilot/evidence.py` | Audit evidence pack generation |
| `vulnpilot/reports/` | Terminal and HTML rendering |

Design principle: engines own business logic, renderers own presentation,
`cli.py` wires them together. Please keep changes within those boundaries.

## Making a change

1. Fork and create a branch from `main`.
2. Add or update tests for your change — every engine has a matching
   `tests/test_*.py` file.
3. Run `pytest` locally; CI must be green.
4. Open a pull request with a short description of what and why.

## Good first contributions

- Additional scanner parsers (Qualys, Rapid7, OpenVAS) — follow the pattern in
  `vulnpilot/parser/nessus.py`
- New evidence frameworks (HIPAA, DPDP) — follow the `FRAMEWORKS` dict in
  `vulnpilot/evidence.py`
- Documentation improvements — everything in `docs/`

Issues labelled `good first issue` are a good place to start.

## Reporting bugs

Open an issue at https://github.com/PatchVex/vulnpilot/issues with the command
you ran, the output you got, and your Python version. Do **not** attach real
scan data — reproduce with the sample files in `data/sample/` where possible.

## Security disclosures

Do not open public issues for security vulnerabilities. Email
security@patchvex.com — see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
