"""
Threat map data pipeline — Phase 2.
Sources : Feodo Tracker, DShield, ThreatFox, Emerging Threats
Enrichment: ip-api.com (geo), Shodan InternetDB (ports/CVEs/tags), CISA KEV
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

import orjson

sys.path.insert(0, str(Path(__file__).parent))

from sources.feodo import fetch as fetch_feodo
from sources.dshield import fetch as fetch_dshield
from sources.threatfox import fetch as fetch_threatfox
from sources.emerging_threats import fetch as fetch_emerging_threats
from enrichment.geolocate import geolocate_ips
from enrichment.shodan_idb import enrich_ips as shodan_enrich
from enrichment.cisa_kev import fetch_cve_set as fetch_kev
from normalize import (
    normalize_feodo,
    normalize_dshield,
    normalize_threatfox,
    normalize_emerging_threats,
)
from aggregate import compute_stats

DATA_DIR = Path(__file__).parent.parent / "public" / "data"


def _apply_enrichment(
    events: list[dict],
    shodan: dict[str, dict],
    kev: set[str],
) -> None:
    """Mutate events in-place: add Shodan ports/vulns/tags and KEV flag."""
    for event in events:
        ip = event["source"]["ip"]
        sd = shodan.get(ip, {})
        event["source"]["ports"] = sorted(sd.get("ports", []))
        event["source"]["vulns"] = sorted(sd.get("vulns", []))
        event["source"]["shodan_tags"] = sd.get("tags", [])
        vulns = event["source"]["vulns"]
        event["kev_match"] = bool(vulns and kev and set(vulns) & kev)


def _write(path: Path, data: object) -> None:
    path.write_bytes(orjson.dumps(data, option=orjson.OPT_INDENT_2))


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    health: dict = {"generated_at": now, "feeds": {}}

    # ── 1. Fetch raw data from all sources ───────────────────────────────
    raw_feodo: list[dict] = []
    raw_dshield: list[dict] = []
    raw_threatfox: list[dict] = []
    raw_et_ips: list[str] = []

    for name, fn, dest in [
        ("feodo", fetch_feodo, None),
        ("dshield", fetch_dshield, None),
        ("threatfox", fetch_threatfox, None),
        ("emerging_threats", fetch_emerging_threats, None),
    ]:
        try:
            result = fn()
            if name == "feodo":
                raw_feodo = result
            elif name == "dshield":
                raw_dshield = result
            elif name == "threatfox":
                raw_threatfox = result
            elif name == "emerging_threats":
                raw_et_ips = result
            print(f"[{name:<18}] fetched {len(result)} items")
        except Exception as exc:
            health["feeds"][name] = {
                "last_run": now, "status": "error", "count": 0, "error": str(exc),
            }
            print(f"[{name:<18}] ERROR: {exc}", file=sys.stderr)

    # ── 2. Batch geolocate all IPs that need it ──────────────────────────
    # Feodo already has country codes; DShield/ThreatFox/ET need geo lookup
    ds_ips = [e["ip"] for e in raw_dshield]
    tf_ips = [
        ioc.rsplit(":", 1)[0] if ":" in (ioc := e.get("ioc", "")) else ioc
        for e in raw_threatfox
    ]
    geo_ips = list(dict.fromkeys(ds_ips + tf_ips + raw_et_ips))

    geo: dict[str, dict] = {}
    if geo_ips:
        try:
            geo = geolocate_ips(geo_ips)
            print(f"[geo               ] resolved {len(geo)}/{len(geo_ips)} IPs")
        except Exception as exc:
            print(f"[geo               ] ERROR: {exc}", file=sys.stderr)

    # ── 3. Normalize each source ─────────────────────────────────────────
    all_events: list[dict] = []

    sources_normalized = [
        ("feodo",            normalize_feodo(raw_feodo)),
        ("dshield",          normalize_dshield(raw_dshield, geo)),
        ("threatfox",        normalize_threatfox(raw_threatfox, geo)),
        ("emerging_threats", normalize_emerging_threats(raw_et_ips, geo)),
    ]

    for feed_name, events in sources_normalized:
        if feed_name not in health["feeds"]:  # don't overwrite an error entry
            health["feeds"][feed_name] = {
                "last_run": now, "status": "ok", "count": len(events), "error": None,
            }
        all_events.extend(events)
        print(f"[{feed_name:<18}] {len(events)} events normalized")

    # ── 4. Shodan InternetDB enrichment (async, keyless) ─────────────────
    all_ips = list(dict.fromkeys(e["source"]["ip"] for e in all_events))
    shodan: dict[str, dict] = {}
    try:
        shodan = shodan_enrich(all_ips)
        hits = sum(1 for v in shodan.values() if v)
        print(f"[shodan            ] {hits}/{len(all_ips)} IPs enriched")
    except Exception as exc:
        print(f"[shodan            ] ERROR: {exc}", file=sys.stderr)

    # ── 5. CISA KEV cross-reference ──────────────────────────────────────
    kev: set[str] = set()
    try:
        kev = fetch_kev()
        print(f"[cisa_kev          ] {len(kev)} CVEs loaded")
    except Exception as exc:
        print(f"[cisa_kev          ] ERROR: {exc}", file=sys.stderr)

    _apply_enrichment(all_events, shodan, kev)

    kev_matches = sum(1 for e in all_events if e.get("kev_match"))
    if kev_matches:
        print(f"[kev               ] {kev_matches} events matched KEV CVEs")

    # ── 6. Write output ──────────────────────────────────────────────────
    _write(DATA_DIR / "threats-24h.json", {
        "generated_at": now,
        "window_hours": 24,
        "events": all_events,
    })
    _write(DATA_DIR / "stats-latest.json", compute_stats(all_events, now))
    _write(DATA_DIR / "pipeline-health.json", health)

    print(f"[pipeline          ] Done — {len(all_events)} total events → public/data/")


if __name__ == "__main__":
    main()
