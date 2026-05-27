import httpx
import orjson

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def fetch() -> list[dict]:
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        r = client.get(FEODO_URL, headers={"User-Agent": "threatmap/1.0 (research)"})
        r.raise_for_status()

    data = orjson.loads(r.content)

    # Feodo returns either a plain list or {"results": [...]}
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "data", "blocklist"):
            if key in data and isinstance(data[key], list):
                return data[key]

    return []
