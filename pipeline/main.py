"""
Threat map data pipeline — Phase 1.
Sources: Feodo Tracker (C2 botnet IPs) + DShield (top port scanners).
Outputs static JSON to public/data/ for the Vite frontend.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

import orjson

sys.path.insert(0, str(Path(__file__).parent))

from sources.feodo import fetch as fetch_feodo
from sources.dshield import fetch as fetch_dshield
from enrichment.geolocate import geolocate_ips
from normalize import normalize_feodo, normalize_dshield
from aggregate import compute_stats

DATA_DIR = Path(__file__).parent.parent / "public" / "data"


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    health: dict = {"generated_at": now, "feeds": {}}
    all_events: list[dict] = []

    # ── Feodo Tracker (botnet C2) ─────────────────────────────────────────
    try:
        raw = fetch_feodo()
        events = normalize_feodo(raw)
        all_events.extend(events)
        health["feeds"]["feodo"] = {"last_run": now, "status": "ok", "count": len(events), "error": None}
        print(f"[feodo]    {len(events)} events")
    except Exception as exc:
        health["feeds"]["feodo"] = {"last_run": now, "status": "error", "count": 0, "error": str(exc)}
        print(f"[feodo]    ERROR: {exc}", file=sys.stderr)

    # ── DShield top scanners ──────────────────────────────────────────────
    try:
        raw_ds = fetch_dshield()
        ips = [e["ip"] for e in raw_ds]
        geo = geolocate_ips(ips)
        events_ds = normalize_dshield(raw_ds, geo)
        all_events.extend(events_ds)
        health["feeds"]["dshield"] = {"last_run": now, "status": "ok", "count": len(events_ds), "error": None}
        print(f"[dshield]  {len(events_ds)} events")
    except Exception as exc:
        health["feeds"]["dshield"] = {"last_run": now, "status": "error", "count": 0, "error": str(exc)}
        print(f"[dshield]  ERROR: {exc}", file=sys.stderr)

    # ── Write output ──────────────────────────────────────────────────────
    _write(DATA_DIR / "threats-24h.json", {"generated_at": now, "window_hours": 24, "events": all_events})
    _write(DATA_DIR / "stats-latest.json", compute_stats(all_events, now))
    _write(DATA_DIR / "pipeline-health.json", health)

    print(f"[pipeline] Done — {len(all_events)} total events → public/data/")


def _write(path: Path, data: object) -> None:
    path.write_bytes(orjson.dumps(data, option=orjson.OPT_INDENT_2))


if __name__ == "__main__":
    main()
