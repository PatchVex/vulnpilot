"""
vulnpilot/enrich/feeds.py
Loads CISA KEV and FIRST EPSS data from local cache.
Customer vulnerability data never leaves their machine.
"""
from __future__ import annotations
import csv
import gzip
import json
import logging
import urllib.request
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

logger = logging.getLogger(__name__)

DEFAULT_CACHE = Path.home() / ".vulnpilot" / "feeds"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def load_kev(kev_path: Optional[Path] = None) -> Set[str]:
    path = kev_path or DEFAULT_CACHE / "known_exploited_vulnerabilities.json"
    if not path.exists():
        logger.warning("KEV file not found at %s — run 'vulnpilot update-feeds' first.", path)
        return set()
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    cve_set = {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
    logger.info("Loaded %d KEV entries", len(cve_set))
    return cve_set


def load_epss(epss_path: Optional[Path] = None) -> Dict[str, Tuple[float, float]]:
    path = epss_path or DEFAULT_CACHE / "epss_scores-current.csv.gz"
    if not path.exists():
        uncompressed = path.with_suffix("")
        if uncompressed.exists():
            path = uncompressed
        else:
            logger.warning("EPSS file not found at %s — run 'vulnpilot update-feeds' first.", path)
            return {}

    epss: Dict[str, Tuple[float, float]] = {}
    opener = gzip.open if path.suffix == ".gz" else open

    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            break
        reader = csv.DictReader(fh, fieldnames=["cve", "epss", "percentile"])
        next(reader, None)
        for row in reader:
            cve = row["cve"].strip().upper()
            try:
                epss[cve] = (float(row["epss"].strip()), float(row["percentile"].strip()))
            except (ValueError, KeyError):
                continue

    logger.info("Loaded %d EPSS scores", len(epss))
    return epss


def update_feeds(cache_dir: Optional[Path] = None) -> None:
    cache = cache_dir or DEFAULT_CACHE
    cache.mkdir(parents=True, exist_ok=True)
    print("Downloading CISA KEV feed...")
    urllib.request.urlretrieve(KEV_URL, cache / "known_exploited_vulnerabilities.json")
    print("Downloading FIRST EPSS feed...")
    urllib.request.urlretrieve(EPSS_URL, cache / "epss_scores-current.csv.gz")
    print("Feeds updated successfully.")
