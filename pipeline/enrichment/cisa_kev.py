"""CISA Known Exploited Vulnerabilities catalog — free, no key, authoritative."""
import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cve_set() -> set[str]:
    """Return CVE IDs listed in the CISA KEV catalog, or empty set on failure."""
    try:
        with httpx.Client(timeout=30, follow_redirects=True) as client:
            r = client.get(KEV_URL, headers={"User-Agent": "threatmap/1.0 (research)"})
            r.raise_for_status()
        return {v["cveID"] for v in r.json().get("vulnerabilities", [])}
    except Exception:
        return set()
