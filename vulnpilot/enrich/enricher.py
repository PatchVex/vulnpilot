"""
vulnpilot/enrich/enricher.py
Applies KEV and EPSS data to parsed findings.
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import List, Optional
from vulnpilot.parser.base import Finding
from .feeds import load_kev, load_epss

logger = logging.getLogger(__name__)


def enrich(findings: List[Finding], kev_path: Optional[Path] = None, epss_path: Optional[Path] = None) -> List[Finding]:
    kev_set = load_kev(kev_path)
    epss_map = load_epss(epss_path)
    kev_hits = epss_hits = 0

    for f in findings:
        for cve in f.cve_list:
            if cve in kev_set:
                f.kev_match = True
                kev_hits += 1
            if cve in epss_map:
                score, percentile = epss_map[cve]
                if f.epss_score is None or score > f.epss_score:
                    f.epss_score = score
                    f.epss_percentile = percentile
                    epss_hits += 1

    logger.info("Enrichment: %d KEV matches, %d EPSS scores", kev_hits, epss_hits)
    return findings
