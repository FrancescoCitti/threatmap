"""SANS ISC DShield top attackers — returns XML, ~30 IPs with attack counts."""
import xml.etree.ElementTree as ET

import httpx

DSHIELD_URL = "https://isc.sans.edu/api/sources/attacks/30/json"


def fetch() -> list[dict]:
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        r = client.get(DSHIELD_URL, headers={"User-Agent": "threatmap/1.0 (research)"})
        r.raise_for_status()

    # Response is XML despite the /json suffix — parse it
    text = r.text
    xml_end = text.find("</sources>")
    if xml_end == -1:
        return []

    root = ET.fromstring(text[: xml_end + len("</sources>")])
    entries = []
    for data in root.findall("data"):
        ip = (data.findtext("ip") or "").strip()
        if not ip:
            continue
        entries.append(
            {
                "ip": ip,
                "attacks": int(data.findtext("attacks") or 0),
                "count": int(data.findtext("count") or 0),
                "firstseen": (data.findtext("firstseen") or "").strip(),
                "lastseen": (data.findtext("lastseen") or "").strip(),
            }
        )
    return entries
