"""Batch IP geolocating via ip-api.com (free, no key, 45 req/min)."""
import time

import httpx

BATCH_URL = "http://ip-api.com/batch"
FIELDS = "query,status,country,countryCode,lat,lon,as,org"
BATCH_SIZE = 100


def geolocate_ips(ips: list[str]) -> dict[str, dict]:
    """Return a dict mapping IP → geo fields for all IPs that resolve."""
    results: dict[str, dict] = {}
    if not ips:
        return results

    with httpx.Client(timeout=30) as client:
        for i in range(0, len(ips), BATCH_SIZE):
            batch = list(dict.fromkeys(ips[i : i + BATCH_SIZE]))  # dedupe, keep order
            resp = client.post(
                BATCH_URL,
                params={"fields": FIELDS},
                json=batch,
                headers={"User-Agent": "threatmap/1.0 (research)"},
            )
            resp.raise_for_status()
            for item in resp.json():
                if item.get("status") == "success":
                    results[item["query"]] = item
            if i + BATCH_SIZE < len(ips):
                time.sleep(1.5)  # stay within 45 req/min

    return results
