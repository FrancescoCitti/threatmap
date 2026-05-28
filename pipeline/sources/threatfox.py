"""ThreatFox (abuse.ch) — POST API with anonymous key, ip:port IOCs only."""
import re

import httpx
import orjson

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
MAX_RESULTS = 400
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def fetch() -> list[dict]:
    """Query ThreatFox for recent ip:port IOCs via anonymous POST."""
    payload = {"query": "get_iocs", "days": 1, "auth_key": ""}
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        r = client.post(
            API_URL,
            content=orjson.dumps(payload),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "threatmap/1.0 (research)",
            },
        )
        r.raise_for_status()

    data = r.json()
    if data.get("query_status") not in ("ok", "no_results"):
        raise ValueError(f"ThreatFox API returned: {data.get('query_status')}")

    entries = data.get("data") or []

    result = []
    for e in entries:
        if not isinstance(e, dict) or e.get("ioc_type") != "ip:port":
            continue
        ioc = e.get("ioc", "")
        ip = ioc.rsplit(":", 1)[0] if ":" in ioc else ioc
        if _IP_RE.match(ip):
            result.append(e)
        if len(result) >= MAX_RESULTS:
            break

    return result
