"""Emerging Threats / Proofpoint compromised IP blocklist — free, no key."""
import re

import httpx

ET_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
MAX_IPS = 400
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def fetch() -> list[str]:
    """Return list of compromised IPv4 addresses."""
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        r = client.get(ET_URL, headers={"User-Agent": "threatmap/1.0 (research)"})
        r.raise_for_status()

    ips = []
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and _IP_RE.match(line):
            ips.append(line)
        if len(ips) >= MAX_IPS:
            break

    return ips
