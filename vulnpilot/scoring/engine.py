"""
vulnpilot/scoring/engine.py
Composite risk scoring engine.
Score = KEV(40) + EPSS(35) + CVSS(15) + Severity(10)
KEV hard floor: any KEV finding scores at least 75.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import List
from vulnpilot.parser.base import Finding

logger = logging.getLogger(__name__)

SEVERITY_SCORE = {"critical": 1.0, "high": 0.75, "medium": 0.4, "low": 0.1, "none": 0.0, "": 0.0}


@dataclass
class ScoringConfig:
    kev_weight: float = 40.0
    epss_weight: float = 35.0
    cvss_weight: float = 15.0
    severity_weight: float = 10.0


DEFAULT_CONFIG = ScoringConfig()


def _normalize_cvss(cvss: float) -> float:
    return min(max(cvss, 0.0), 10.0) / 10.0


def score_finding(finding: Finding, config: ScoringConfig = DEFAULT_CONFIG) -> float:
    raw = (
        (config.kev_weight if finding.kev_match else 0.0) +
        config.epss_weight * (finding.epss_score or 0.0) +
        config.cvss_weight * _normalize_cvss(finding.cvss) +
        config.severity_weight * SEVERITY_SCORE.get(finding.risk.lower(), 0.0)
    )
    if finding.kev_match:
        raw = max(raw, 75.0)
    return min(round(raw, 2), 100.0)


def _priority_label(score: float, kev: bool) -> str:
    if kev or score >= 75:
        return "CRITICAL NOW"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def score_all(findings: List[Finding], config: ScoringConfig = DEFAULT_CONFIG, limit: int = 0) -> List[Finding]:
    for f in findings:
        f.priority_score = score_finding(f, config)
        f.priority_label = _priority_label(f.priority_score, f.kev_match)
    findings.sort(key=lambda f: f.priority_score, reverse=True)
    return findings[:limit] if limit > 0 else findings
