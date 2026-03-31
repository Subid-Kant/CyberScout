"""
utils/helpers.py
Shared helper functions for CyberScout.
"""

import re
from urllib.parse import urlparse


def normalize_url(target: str) -> str:
    """Ensure URL has a scheme."""
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def extract_host(target: str) -> str:
    parsed = urlparse(normalize_url(target))
    return parsed.hostname or target


def is_valid_target(target: str) -> bool:
    """Basic validation — not empty, looks like a URL or hostname."""
    if not target or len(target) > 500:
        return False
    target = normalize_url(target)
    parsed = urlparse(target)
    return bool(parsed.scheme and parsed.netloc)


def calculate_risk_score(findings: list) -> int:
    """
    Return a 0–100 risk score.
    Critical=40pts each (cap 40), High=20 (cap 20), Medium=10 (cap 20),
    Low=5 (cap 10), Info=0.
    """
    weights = {"critical": 40, "high": 20, "medium": 10, "low": 5, "info": 0}
    caps    = {"critical": 40, "high": 20, "medium": 20, "low": 10, "info": 0}

    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        totals[sev] = totals.get(sev, 0) + weights.get(sev, 0)

    score = sum(min(totals[s], caps[s]) for s in totals)
    return min(score, 100)
