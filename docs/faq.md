# FAQ

**Does my scan data get uploaded anywhere?**
No. Analysis is fully local. The only network calls are downloads of two
public feeds (CISA KEV, FIRST EPSS). Air-gapped use works after the initial
feed download using `--kev` and `--epss` with local files.

**What's stored in `~/.vulnpilot/history.db`?**
A local record of each analysis run: timestamp, file hash, finding counts,
and finding identifiers. It exists to support trend reporting, remediation
verification, and Type II audit evidence. It never leaves your machine —
delete the file anytime.

**Which scanners are supported?**
Nessus CSV today. Qualys is next. Rapid7, OpenVAS, Defender, and AWS
Inspector are planned.

**Why is my finding scored high when CVSS says medium?**
Almost certainly a KEV match or high EPSS — real-world exploitation
outranks theoretical severity. Run with the finding's CVE against
cisa.gov's KEV catalog to confirm.

**The free tier shows 20 findings — why?**
The Community Edition prioritizes the top 20. For most scans the KEV and
high-EPSS findings that demand action fit well within that. Full output and
report features are part of the paid tiers (in development — pricing
publishes after early-user validation).

**Can I use this in CI?**
Yes — `--no-colour` gives pipeline-friendly output. A dedicated CI mode
with exit codes is on the roadmap.

**Found a bug or want a framework added?**
Open an issue: https://github.com/PatchVex/vulnpilot/issues
Security disclosures: security@patchvex.com
