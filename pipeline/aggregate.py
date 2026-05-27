from collections import Counter


def compute_stats(events: list[dict], generated_at: str) -> dict:
    country_counter: Counter[str] = Counter()
    country_names: dict[str, str] = {}
    malware_counter: Counter[str] = Counter()

    for e in events:
        code = e["source"]["country_code"]
        country_counter[code] += 1
        country_names[code] = e["source"]["country_name"]
        family = e.get("malware_family")
        if family and family != "Unknown":
            malware_counter[family] += 1

    c2_count = sum(1 for e in events if e.get("type") == "c2")

    return {
        "generated_at": generated_at,
        "window_hours": 24,
        "total_events": len(events),
        "active_c2_count": c2_count,
        "top_source_countries": [
            {"code": code, "name": country_names[code], "count": count}
            for code, count in country_counter.most_common(10)
        ],
        "top_malware_families": [
            {"name": family, "count": count}
            for family, count in malware_counter.most_common(10)
        ],
        "events_by_hour": [],
    }
