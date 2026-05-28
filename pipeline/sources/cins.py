"""CINS Score (Collective Intelligence Network Security) — no API key required."""
import re

import httpx

URL = "https://cinsscore.com/list/ci-badguys.txt"
MAX_IPS = 400
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def fetch() -> list[str]:
    """Return up to MAX_IPS high-confidence attacker IPs from CINS Score."""
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        r = client.get(URL, headers={"User-Agent": "threatmap/1.0 (research)"})
        r.raise_for_status()

    ips = []
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and _IP_RE.match(line):
            ips.append(line)
        if len(ips) >= MAX_IPS:
            break

    return ips
