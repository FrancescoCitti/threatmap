"""ThreatFox (abuse.ch) — recent IOC bulk export, no API key required."""
import io
import re
import zipfile

import httpx
import orjson

EXPORT_URL = "https://threatfox.abuse.ch/export/json/recent.zip"
MAX_RESULTS = 400
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def fetch() -> list[dict]:
    """Download ThreatFox recent IOC export and return ip:port entries only."""
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        r = client.get(EXPORT_URL, headers={"User-Agent": "threatmap/1.0 (research)"})
        r.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        raw = z.read(z.namelist()[0])

    data = orjson.loads(raw)

    # Export can be a flat list, {"data": [...]}, or {"data": {"date": [...]}}
    entries: list[dict] = []
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        inner = data.get("data", [])
        if isinstance(inner, list):
            entries = inner
        elif isinstance(inner, dict):
            for v in inner.values():
                if isinstance(v, list):
                    entries.extend(v)

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
