import hashlib
import re
from datetime import datetime, timezone

from enrichment.country_centroids import CENTROIDS, NAMES

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# ThreatFox uses slightly different casing for some families
_TF_ALIASES: dict[str, str] = {
    "CobaltStrike": "Cobalt Strike",
    "Qakbot": "QakBot",
    "QAKBOT": "QakBot",
    "Trickbot": "TrickBot",
    "TRICKBOT": "TrickBot",
    "Dridex": "Dridex",
}

MALWARE_SEVERITY: dict[str, int] = {
    "Emotet": 4,
    "QakBot": 4,
    "TrickBot": 4,
    "Dridex": 4,
    "BazarLoader": 3,
    "IcedID": 3,
    "Cobalt Strike": 4,
    "AsyncRAT": 2,
    "NanoCore": 2,
    "AgentTesla": 2,
    "FormBook": 2,
    "Remcos": 2,
}

MALWARE_TTPS: dict[str, list[str]] = {
    "Emotet": ["T1566.001", "T1055", "T1071.001"],
    "QakBot": ["T1566.001", "T1071.001", "T1059.001"],
    "TrickBot": ["T1078", "T1486", "T1071.001"],
    "IcedID": ["T1566.002", "T1055", "T1059.001"],
    "BazarLoader": ["T1059.001", "T1218", "T1071.001"],
    "Dridex": ["T1055", "T1566.002", "T1486"],
    "Cobalt Strike": ["T1090", "T1059.003", "T1027"],
    "AsyncRAT": ["T1219", "T1059.001"],
    "NanoCore": ["T1219", "T1057"],
    "AgentTesla": ["T1056.001", "T1071.003"],
    "FormBook": ["T1056.001", "T1083"],
    "Remcos": ["T1219", "T1059.003"],
}


def _coerce_ts(raw: str | None, fallback: str) -> str:
    if not raw:
        return fallback
    raw = str(raw).strip()
    if "T" in raw:
        return raw if raw.endswith("Z") or "+" in raw else raw + "Z"
    # ThreatFox format: "2024-01-15 10:30:00 UTC"
    if " UTC" in raw:
        return raw.replace(" UTC", "Z").replace(" ", "T", 1)
    # Date-only: 2024-01-15
    if len(raw) == 10 and raw[4] == "-":
        return raw + "T00:00:00Z"
    return fallback


def normalize_dshield(entries: list[dict], geo: dict[str, dict]) -> list[dict]:
    """Normalize DShield top-attacker entries (already geo-enriched)."""
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    events: list[dict] = []

    for entry in entries:
        ip = entry.get("ip", "")
        if not ip:
            continue

        g = geo.get(ip, {})
        country_code = (g.get("countryCode") or "XX").upper()
        country_name = g.get("country") or NAMES.get(country_code, country_code)
        lat = float(g.get("lat") or CENTROIDS.get(country_code, (0.0, 0.0))[0])
        lon = float(g.get("lon") or CENTROIDS.get(country_code, (0.0, 0.0))[1])

        as_raw: str = g.get("as") or ""
        asn = int(as_raw.split()[0].lstrip("AS")) if as_raw.startswith("AS") else None
        as_org: str | None = g.get("org") or (as_raw.split(" ", 1)[1] if " " in as_raw else None) or None

        attacks = entry.get("attacks", 0)
        if attacks >= 5000:
            severity = 4
        elif attacks >= 2000:
            severity = 3
        elif attacks >= 500:
            severity = 2
        else:
            severity = 1

        last_seen = _coerce_ts(entry.get("lastseen"), now)
        event_id = hashlib.sha256(f"dshield:{ip}".encode()).hexdigest()[:16]

        events.append(
            {
                "id": event_id,
                "ts": last_seen,
                "feed": "dshield",
                "type": "scanner",
                "severity": severity,
                "source": {
                    "ip": ip,
                    "country_code": country_code,
                    "country_name": country_name,
                    "lat": lat,
                    "lon": lon,
                    "asn": asn,
                    "as_org": as_org,
                },
                "tlp": "WHITE",
                "tags": ["scanner", "honeypot", f"attacks:{attacks}"],
                "mitre_ttps": ["T1046", "T1595.001"],
            }
        )

    return events


def normalize_feodo(entries: list[dict]) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    events: list[dict] = []

    for entry in entries:
        ip: str = str(entry.get("ip_address") or entry.get("ip") or "").strip()
        if not ip:
            continue

        country_code: str = (
            str(entry.get("country") or entry.get("country_code") or "XX")
            .strip()
            .upper()
        )[:2]

        malware: str = str(
            entry.get("malware") or entry.get("malware_family") or "Unknown"
        ).strip()

        asn_raw = entry.get("as_number") or entry.get("asn")
        asn = int(asn_raw) if asn_raw and str(asn_raw).isdigit() else None
        as_org: str | None = (
            str(entry.get("as_name") or entry.get("as_org") or entry.get("asname") or "").strip()
            or None
        )

        last_seen = _coerce_ts(
            entry.get("last_online") or entry.get("dtlastseen") or entry.get("lastseen"),
            now,
        )

        lat, lon = CENTROIDS.get(country_code, (0.0, 0.0))
        country_name = (
            str(entry.get("country_name") or "").strip()
            or NAMES.get(country_code, country_code)
        )

        base_severity = MALWARE_SEVERITY.get(malware, 2)
        is_online = str(entry.get("status", "")).lower() == "online"
        severity = min(4, base_severity + (1 if is_online else 0))

        event_id = hashlib.sha256(f"feodo:{ip}:{malware}".encode()).hexdigest()[:16]

        events.append(
            {
                "id": event_id,
                "ts": last_seen,
                "feed": "feodo",
                "type": "c2",
                "severity": severity,
                "malware_family": malware,
                "source": {
                    "ip": ip,
                    "country_code": country_code,
                    "country_name": country_name,
                    "lat": lat,
                    "lon": lon,
                    "asn": asn,
                    "as_org": as_org,
                },
                "tlp": "WHITE",
                "tags": ["botnet", "c2", malware.lower().replace(" ", "-")],
                "mitre_ttps": MALWARE_TTPS.get(malware, []),
            }
        )

    return events


def normalize_threatfox(entries: list[dict], geo: dict[str, dict]) -> list[dict]:
    """Normalize ThreatFox ip:port IOC entries."""
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    events: list[dict] = []

    for entry in entries:
        ioc = entry.get("ioc", "")
        ip = ioc.rsplit(":", 1)[0] if ":" in ioc else ioc
        if not ip or not _IP_RE.match(ip):
            continue

        g = geo.get(ip, {})
        country_code = (g.get("countryCode") or "XX").upper()
        country_name = g.get("country") or NAMES.get(country_code, country_code)
        lat = float(g.get("lat") or CENTROIDS.get(country_code, (0.0, 0.0))[0])
        lon = float(g.get("lon") or CENTROIDS.get(country_code, (0.0, 0.0))[1])
        as_raw: str = g.get("as") or ""
        asn = int(as_raw.split()[0].lstrip("AS")) if as_raw.startswith("AS") else None
        as_org: str | None = (
            g.get("org") or (as_raw.split(" ", 1)[1] if " " in as_raw else None) or None
        )

        raw_malware = str(entry.get("malware_printable") or "Unknown").strip()
        malware = _TF_ALIASES.get(raw_malware, raw_malware)

        confidence = int(entry.get("confidence_level") or 50)
        sev_by_confidence = 4 if confidence >= 90 else (3 if confidence >= 70 else (2 if confidence >= 50 else 1))
        severity = max(MALWARE_SEVERITY.get(malware, sev_by_confidence), sev_by_confidence)
        severity = min(4, severity)

        threat_type = str(entry.get("threat_type") or "")
        event_type = "c2" if "botnet" in threat_type or "_cc" in threat_type else "ioc"

        ts = _coerce_ts(entry.get("first_seen"), now)
        event_id = hashlib.sha256(f"threatfox:{ioc}".encode()).hexdigest()[:16]

        raw_tags = entry.get("tags") or []
        tags = ["threatfox"] + [t for t in raw_tags if isinstance(t, str)]

        events.append({
            "id": event_id,
            "ts": ts,
            "feed": "threatfox",
            "type": event_type,
            "severity": severity,
            "malware_family": malware if malware != "Unknown" else None,
            "source": {
                "ip": ip,
                "country_code": country_code,
                "country_name": country_name,
                "lat": lat,
                "lon": lon,
                "asn": asn,
                "as_org": as_org,
            },
            "tlp": "WHITE",
            "tags": tags,
            "mitre_ttps": MALWARE_TTPS.get(malware, []),
        })

    return events


def normalize_emerging_threats(ips: list[str], geo: dict[str, dict]) -> list[dict]:
    """Normalize Emerging Threats compromised IP list."""
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    events: list[dict] = []

    for ip in ips:
        if not ip or not _IP_RE.match(ip):
            continue
        g = geo.get(ip, {})
        country_code = (g.get("countryCode") or "XX").upper()
        country_name = g.get("country") or NAMES.get(country_code, country_code)
        lat = float(g.get("lat") or CENTROIDS.get(country_code, (0.0, 0.0))[0])
        lon = float(g.get("lon") or CENTROIDS.get(country_code, (0.0, 0.0))[1])
        as_raw: str = g.get("as") or ""
        asn = int(as_raw.split()[0].lstrip("AS")) if as_raw.startswith("AS") else None
        as_org: str | None = (
            g.get("org") or (as_raw.split(" ", 1)[1] if " " in as_raw else None) or None
        )

        event_id = hashlib.sha256(f"et:{ip}".encode()).hexdigest()[:16]

        events.append({
            "id": event_id,
            "ts": now,
            "feed": "emerging_threats",
            "type": "scanner",
            "severity": 2,
            "source": {
                "ip": ip,
                "country_code": country_code,
                "country_name": country_name,
                "lat": lat,
                "lon": lon,
                "asn": asn,
                "as_org": as_org,
            },
            "tlp": "WHITE",
            "tags": ["blocklist", "compromised", "emerging-threats"],
            "mitre_ttps": ["T1078", "T1190"],
        })

    return events
