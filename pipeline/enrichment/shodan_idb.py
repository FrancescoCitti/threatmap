"""Shodan InternetDB — completely free, no API key. Ports, CVEs, tags per IP."""
import asyncio

import httpx

BASE_URL = "https://internetdb.shodan.io"
CONCURRENCY = 6
TIMEOUT = 8.0


async def _fetch_one(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    ip: str,
) -> tuple[str, dict]:
    async with sem:
        try:
            r = await client.get(f"{BASE_URL}/{ip}", timeout=TIMEOUT)
            if r.status_code == 200:
                return ip, r.json()
        except Exception:
            pass
        return ip, {}


async def _run(ips: list[str]) -> dict[str, dict]:
    sem = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient(
        headers={"User-Agent": "threatmap/1.0 (research)"}
    ) as client:
        pairs = await asyncio.gather(*[_fetch_one(client, sem, ip) for ip in ips])
    return {ip: data for ip, data in pairs if data}


def enrich_ips(ips: list[str]) -> dict[str, dict]:
    """Query Shodan InternetDB for each unique IP. Returns {ip: {ports, vulns, tags}}."""
    unique = list(dict.fromkeys(ips))
    if not unique:
        return {}
    return asyncio.run(_run(unique))
