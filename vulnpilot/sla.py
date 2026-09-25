"""SLA engine — tracks remediation deadlines and breach status."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

CONFIG_PATH = Path.home() / ".vulnpilot" / "sla.yaml"
DEFAULT_SLA = {"critical": 7, "high": 30, "medium": 90, "low": 180}
SLA_WARN_PCT = 0.80


@dataclass
class SLAStatus:
    finding_key: tuple
    risk: str
    first_seen: Optional[str]
    days_open: Optional[int]
    sla_days: Optional[int]
    pct_elapsed: Optional[float]
    status: str
    exception_ref: Optional[str] = None


def load_sla_config(config_path: Optional[Path] = None) -> dict:
    path = config_path or CONFIG_PATH
    if not path.exists():
        return dict(DEFAULT_SLA)
    try:
        data = {}
        for line in path.read_text().splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                k, _, v = line.partition(":")
                try:
                    data[k.strip().lower()] = int(v.strip())
                except ValueError:
                    pass
        merged = dict(DEFAULT_SLA)
        merged.update({k: v for k, v in data.items() if k in DEFAULT_SLA})
        return merged
    except Exception:
        return dict(DEFAULT_SLA)


def write_default_config() -> Path:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(
        "# VulnPilot SLA policy (~/.vulnpilot/sla.yaml)\n"
        "# Days allowed to remediate by severity level\n"
        "critical: 7\nhigh: 30\nmedium: 90\nlow: 180\n"
    )
    return CONFIG_PATH


def _first_seen_from_history(finding_key: tuple) -> Optional[str]:
    from vulnpilot import history
    return history.first_seen_map(history.load_rows()).get(finding_key)


def compute_sla_status(finding, sla_config: Optional[dict] = None,
                       first_seen_map: Optional[dict] = None) -> SLAStatus:
    """SLA status for one finding.

    Pass `first_seen_map` (from history.first_seen_map) when scoring many
    findings; without it, history is read for this finding alone.
    """
    if sla_config is None:
        sla_config = load_sla_config()
    risk = (finding.risk or "").lower().strip()
    key = (finding.host or "", finding.plugin_id or "", finding.port or "")
    sla_days = sla_config.get(risk)
    if first_seen_map is None:
        first_seen = _first_seen_from_history(key)
    else:
        first_seen = first_seen_map.get(key)
    if first_seen is None or sla_days is None:
        return SLAStatus(finding_key=key, risk=risk, first_seen=first_seen,
                         days_open=None, sla_days=sla_days,
                         pct_elapsed=None, status="unknown")
    try:
        ts = datetime.fromisoformat(first_seen)
    except ValueError:
        return SLAStatus(finding_key=key, risk=risk, first_seen=first_seen,
                         days_open=None, sla_days=sla_days,
                         pct_elapsed=None, status="unknown")
    now = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    days_open = (now - ts).days
    pct = days_open / sla_days
    status = "breached" if pct > 1.0 else "approaching" if pct >= SLA_WARN_PCT else "within"
    return SLAStatus(finding_key=key, risk=risk, first_seen=first_seen[:10],
                     days_open=days_open, sla_days=sla_days,
                     pct_elapsed=round(pct, 2), status=status)


def compute_all_sla(findings: list,
                    sla_config: Optional[dict] = None,
                    rows: Optional[list] = None) -> list:
    """SLA status for every finding. Pass `rows` (from history.load_rows())
    when the caller has already loaded history, to avoid reading it again."""
    from vulnpilot import history
    if sla_config is None:
        sla_config = load_sla_config()
    seen = history.first_seen_map(history.load_rows() if rows is None else rows)
    return [compute_sla_status(f, sla_config, seen) for f in findings]
