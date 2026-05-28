# threatmap: Francesco's little globe

**Real-time global cyber threat intelligence, rendered on an interactive 3D globe.**

threatmap aggregates live indicators of compromise from eight open-source threat intelligence feeds, enriches each indicator with passive reconnaissance data, and projects the resulting picture onto a procedurally-generated Earth — a continuously updated window into internet-scale attack activity.

The project demonstrates production-grade engineering at the intersection of security operations, data engineering, and modern frontend development. Every data point is real. Every connection is live.

---

## What it shows

The pipeline runs every hour via GitHub Actions. It collects attacker infrastructure from Feodo Tracker, mass scanner IPs from DShield, bruteforce sources from Blocklist.de and CINS Army, and malware IOCs from ThreatFox. Each IP is then enriched with passive Shodan InternetDB data — open ports, exposed CVEs, infrastructure tags — and cross-referenced against the CISA Known Exploited Vulnerabilities catalogue. MITRE ATT&CK technique identifiers are derived automatically from Emerging Threats rule signatures.

The enriched dataset is published as a static JSON payload to GitHub Pages. No backend. No WebSocket. No API keys in the browser.

---

## Globe views

| Mode | Description |
|------|-------------|
| **EVENTS** | Live attack points sized by severity, coloured by malware family |
| **ARCS** | Directional attack flow from source infrastructure to internet transit hubs |
| **HEAT** | Country-level heatmap extruded by event density |
| **CLUST** | Campaign clustering by /24 subnet, pulsing rings surface coordinated scanning |

---

## Intelligence features

**Free-text search** runs across IP, country, ASN org, CVE, malware family, MITRE TTP, threat actor name, feed name, and Shodan tags simultaneously. All space-separated tokens must match (AND logic). Severity chips (CRIT / HIGH / MED / LOW) provide one-click filtering.

**Threat actor attribution** matches observed indicators against a curated database of eleven threat groups — including APT28, Lazarus Group, Evil Corp, Wizard Spider, and FIN7 — using malware family, normalised tag, and TTP overlap heuristics. Actor and malware names link directly to their Malpedia entries.

**MITRE ATT&CK tab** lists every observed technique grouped by tactic. Clicking any technique pivots the entire view to events associated with that TTP.

**IOC export** produces a UTF-8 CSV or a STIX 2.1 bundle of all indicators currently visible in the filtered view, ready for ingestion into a SIEM or threat intelligence platform.

---

## Interactivity

- Click any globe point to inspect the full indicator — ports, CVEs, Shodan tags, actor attribution, and one-click pivot links to VirusTotal, AbuseIPDB, and Shodan
- Click a country polygon to instantly filter the entire view to that country
- Click an ASN org name to pivot on that infrastructure
- URL-encoded filter state: shareable links restore the exact search query and active tab
- Keyboard shortcuts: `Esc` clears filters, `1` `2` `3` `4` switch sidebar tabs, `E` `A` `H` `C` switch globe modes
- One-click pipeline refresh via GitHub Actions workflow dispatch, triggered directly from the status bar

---

## Data sources

| Source | Feed type |
|--------|-----------|
| [Feodo Tracker](https://feodotracker.abuse.ch/) | C2 botnet infrastructure |
| [DShield](https://dshield.org/) | Mass scanner IPs |
| [Blocklist.de](https://www.blocklist.de/) | Bruteforce and attack sources |
| [CINS Army](https://cinsscore.com/) | Threat intelligence blocklist |
| [ThreatFox](https://threatfox.abuse.ch/) | Malware IOC sharing |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities |
| [Emerging Threats](https://rules.emergingthreats.net/) | IDS rule signatures → MITRE TTPs |
| [Shodan InternetDB](https://internetdb.shodan.io/) | Passive port and CVE enrichment |

---

## Architecture

```
GitHub Actions  (hourly cron + push + manual dispatch)
│
├── pipeline/main.py
│     ├── collect  — Feodo, DShield, Blocklist.de, CINS, ThreatFox
│     ├── enrich   — Shodan InternetDB per-IP passive lookup
│     ├── cross-ref — CISA KEV catalogue
│     ├── tag      — Emerging Threats signatures → MITRE ATT&CK TTPs
│     └── emit     — public/data/{events,stats,health}.json
│
├── npm run build  — React app compiled to dist/
│
└── GitHub Pages   — static deployment, zero infrastructure
```

---

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| Globe rendering | react-globe.gl, Three.js, WebGL |
| State management | Zustand |
| Vector geography | topojson-client, Natural Earth 110m |
| Data pipeline | Python 3.12, httpx, orjson |
| CI/CD and hosting | GitHub Actions, GitHub Pages |

---

## Local development

```bash
npm install
npm run dev
```

The development server reads from `public/data/` at runtime. Sample data is included in the repository so the globe loads immediately without running the pipeline.

To regenerate live data locally:

```bash
pip install -r pipeline/requirements.txt
export MAXMIND_ACCOUNT_ID=your_id
export MAXMIND_LICENSE_KEY=your_key
python pipeline/main.py
```

MaxMind GeoIP2 credentials are required for geographic resolution. A free licence is available at [maxmind.com](https://www.maxmind.com/en/geolite2/signup). Without them, the pipeline falls back to Shodan enrichment coordinates where available.

---

## License

MIT
