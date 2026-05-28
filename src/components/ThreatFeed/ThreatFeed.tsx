import { useMemo } from 'react'
import { useThreatStore } from '../../stores/threatStore'
import { useFilteredEvents } from '../../hooks/useFilteredEvents'
import { THREAT_ACTOR_DB, malpediaMalwareUrl, malpediaActorUrl } from '../../data/threatActors'
import { MITRE_TECHNIQUES, TACTIC_ORDER } from '../../data/mitreTechniques'
import type { ThreatEvent } from '../../types/schema'
import type { SidebarTab } from '../../stores/threatStore'

// ── Helpers ───────────────────────────────────────────────────────────────────

function uuid(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16)
  })
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function exportCsv(events: ThreatEvent[]) {
  const header = [
    'timestamp', 'ip', 'type', 'malware_family', 'country_code', 'country_name',
    'asn', 'as_org', 'severity', 'feed', 'cves', 'mitre_ttps', 'tags', 'kev_match',
  ]
  const rows = events.map(e =>
    [
      e.ts, e.source.ip, e.type, e.malware_family ?? '',
      e.source.country_code, e.source.country_name,
      e.source.asn ?? '', e.source.as_org ?? '',
      e.severity, e.feed,
      (e.source.vulns ?? []).join('|'),
      (e.mitre_ttps ?? []).join('|'),
      e.tags.join('|'),
      e.kev_match ? 'true' : 'false',
    ].map(v => JSON.stringify(String(v))).join(',')
  )
  const csv = [header.join(','), ...rows].join('\n')
  downloadBlob(new Blob([csv], { type: 'text/csv' }), `threatmap-iocs-${new Date().toISOString().slice(0, 10)}.csv`)
}

function exportStix(events: ThreatEvent[]) {
  const bundle = {
    type: 'bundle',
    id: `bundle--${uuid()}`,
    objects: events.map(e => ({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${uuid()}`,
      created: e.ts,
      modified: e.ts,
      name: `${e.malware_family ?? e.type.toUpperCase()} — ${e.source.ip}`,
      description: `${e.type} activity from ${e.source.country_name} (${e.source.country_code}). Feed: ${e.feed}. Severity: ${e.severity}.`,
      pattern: `[ipv4-addr:value = '${e.source.ip}']`,
      pattern_type: 'stix',
      valid_from: e.ts,
      labels: ['malicious-activity'],
      confidence: e.severity * 25,
      external_references: (e.source.vulns ?? []).map(cve => ({
        source_name: 'cve',
        external_id: cve,
        url: `https://nvd.nist.gov/vuln/detail/${cve}`,
      })),
      kill_chain_phases: (e.mitre_ttps ?? []).map(t => ({
        kill_chain_name: 'mitre-attack',
        phase_name: t,
      })),
    })),
  }
  downloadBlob(
    new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }),
    `threatmap-iocs-${new Date().toISOString().slice(0, 10)}.stix.json`
  )
}

// ── Severity styles ───────────────────────────────────────────────────────────

const SEV_DOT:   Record<number, string> = { 1:'bg-slate-400', 2:'bg-yellow-400', 3:'bg-orange-400', 4:'bg-red-500' }
const SEV_LABEL: Record<number, string> = { 1:'LOW', 2:'MED', 3:'HIGH', 4:'CRIT' }
const SEV_COLOR: Record<number, string> = { 1:'text-slate-400', 2:'text-yellow-400', 3:'text-orange-400', 4:'text-red-500' }

// ── Feed row ──────────────────────────────────────────────────────────────────

function FeedRow({ event: e }: { event: ThreatEvent }) {
  const setSelected = useThreatStore(s => s.setSelected)
  const time = new Date(e.ts).toLocaleTimeString('en-US', {
    hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
  return (
    <button
      onClick={() => setSelected(e)}
      className="w-full text-left px-3 py-2 hover:bg-white/5 border-b border-white/5 transition-colors"
    >
      <div className="flex items-center justify-between gap-2 mb-0.5">
        <div className="flex items-center gap-1.5">
          <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${SEV_DOT[e.severity]}`} />
          <span className={`text-[10px] font-bold tracking-wider ${SEV_COLOR[e.severity]}`}>
            {SEV_LABEL[e.severity]}
          </span>
        </div>
        <span className="text-[10px] text-slate-600 font-mono">{time}</span>
      </div>
      <div className="flex items-center gap-1.5">
        <span className="text-xs font-semibold text-slate-200 truncate">{e.malware_family ?? e.type}</span>
        <span className="text-[10px] text-slate-600">·</span>
        <span className="text-[10px] text-slate-500 truncate">{e.source.country_name}</span>
      </div>
      <div className="text-[10px] text-slate-700 font-mono truncate mt-0.5">{e.source.ip}</div>
    </button>
  )
}

// ── FEED tab ──────────────────────────────────────────────────────────────────

function FeedTab() {
  const { events, loading, searchQuery, timelineHour, setSearchQuery, setTimelineHour } = useThreatStore()
  const filteredEvents = useFilteredEvents()

  const hourBuckets = useMemo(() => {
    const buckets = new Map<string, number>()
    events.forEach(e => {
      const key = e.ts.slice(0, 13)
      buckets.set(key, (buckets.get(key) ?? 0) + 1)
    })
    return [...buckets.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(-24)
  }, [events])

  const maxCount = useMemo(
    () => Math.max(...hourBuckets.map(([, c]) => c), 1),
    [hourBuckets]
  )

  const recent = useMemo(
    () => [...filteredEvents].sort((a, b) =>
      b.severity !== a.severity ? b.severity - a.severity : b.ts.localeCompare(a.ts)
    ),
    [filteredEvents]
  )

  const isFiltered = searchQuery.trim() !== '' || timelineHour !== null

  return (
    <div className="flex flex-col h-full">
      {/* Search */}
      <div className="px-3 py-2 border-b border-white/10 shrink-0">
        <input
          type="text"
          value={searchQuery}
          onChange={ev => setSearchQuery(ev.target.value)}
          placeholder="IP, CVE, malware, actor, severity, TTP…"
          className="w-full bg-black/50 border border-white/10 rounded-sm px-2 py-1.5 text-[11px] font-mono text-slate-300 placeholder:text-slate-700 focus:outline-none focus:border-sky-500/50 transition-colors"
        />

        {/* Severity quick-filter chips */}
        <div className="flex gap-1 mt-1.5">
          {([
            { label: 'CRIT', value: 'critical', on: 'bg-red-950/60 border-red-600 text-red-400',   off: 'border-white/10 text-slate-700 hover:text-red-500 hover:border-red-800' },
            { label: 'HIGH', value: 'high',     on: 'bg-orange-950/60 border-orange-600 text-orange-400', off: 'border-white/10 text-slate-700 hover:text-orange-500 hover:border-orange-800' },
            { label: 'MED',  value: 'medium',   on: 'bg-yellow-950/60 border-yellow-600 text-yellow-400', off: 'border-white/10 text-slate-700 hover:text-yellow-500 hover:border-yellow-800' },
            { label: 'LOW',  value: 'low',      on: 'bg-slate-900 border-slate-600 text-slate-300',       off: 'border-white/10 text-slate-700 hover:text-slate-400 hover:border-slate-600' },
          ] as const).map(({ label, value, on, off }) => {
            const active = searchQuery.trim().toLowerCase() === value
            return (
              <button
                key={value}
                onClick={() => setSearchQuery(active ? '' : value)}
                className={`flex-1 py-0.5 text-[8px] font-mono tracking-wider rounded-sm border transition-all ${active ? on : off}`}
              >
                {label}
              </button>
            )
          })}
        </div>

        {isFiltered && (
          <div className="flex items-center justify-between mt-1.5">
            <span className="text-[9px] text-slate-600 font-mono">
              {filteredEvents.length} of {events.length} events
            </span>
            <button
              onClick={() => { setSearchQuery(''); setTimelineHour(null) }}
              className="text-[9px] text-sky-600 hover:text-sky-400 font-mono transition-colors"
            >
              clear
            </button>
          </div>
        )}
      </div>

      {/* 24h mini-timeline */}
      {hourBuckets.length > 0 && (
        <div className="px-3 pt-2 pb-1.5 border-b border-white/5 shrink-0">
          <div className="text-[8px] text-slate-700 font-mono mb-1.5 tracking-widest">
            24H ACTIVITY
          </div>
          <div className="flex items-end gap-px h-7">
            {hourBuckets.map(([hour, count]) => {
              const active = timelineHour === hour
              const pct = count / maxCount
              return (
                <button
                  key={hour}
                  title={`${hour.replace('T', ' ')}:00 UTC — ${count} events`}
                  onClick={() => setTimelineHour(active ? null : hour)}
                  className={`flex-1 rounded-sm transition-all ${
                    active ? 'bg-sky-400' : 'bg-sky-900/60 hover:bg-sky-700/70'
                  }`}
                  style={{ height: `${Math.max(pct * 28, 2)}px` }}
                />
              )
            })}
          </div>
          <div className="flex justify-between mt-0.5">
            <span className="text-[7px] text-slate-800 font-mono">-24h</span>
            <span className="text-[7px] text-slate-800 font-mono">now</span>
          </div>
        </div>
      )}

      {/* Event list */}
      <div className="flex-1 overflow-y-auto scrollbar-thin">
        {loading && (
          <div className="flex items-center justify-center h-20">
            <span className="text-[10px] text-slate-600 font-mono animate-pulse">Loading…</span>
          </div>
        )}
        {!loading && recent.length === 0 && (
          <div className="flex flex-col items-center justify-center gap-1 p-6">
            <span className="text-[10px] text-slate-700 font-mono text-center leading-relaxed">
              {isFiltered ? 'No events match current filters.' : 'No data yet.\nPipeline runs on first deploy.'}
            </span>
          </div>
        )}
        {recent.map(e => <FeedRow key={e.id} event={e} />)}
      </div>
    </div>
  )
}

// ── INTEL tab ─────────────────────────────────────────────────────────────────

function generateSitrep(events: ThreatEvent[]): string[] {
  if (events.length === 0) return ['No indicators in current dataset.']
  const out: string[] = []

  const sev4 = events.filter(e => e.severity === 4).length
  const c2   = events.filter(e => e.type === 'c2').length
  out.push(`${events.length} indicators observed.${sev4 ? ` ${sev4} CRITICAL.` : ''}${c2 ? ` ${c2} active C2 servers.` : ''}`)

  const byCountry = new Map<string, number>()
  events.forEach(e => byCountry.set(e.source.country_name, (byCountry.get(e.source.country_name) ?? 0) + 1))
  const topCountries = [...byCountry.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3)
  if (topCountries.length) {
    out.push(`Primary sources: ${topCountries.map(([n, c]) => `${n} (${c})`).join(', ')}.`)
  }

  const kev = events.filter(e => e.kev_match).length
  if (kev > 0) {
    out.push(`${kev} event${kev > 1 ? 's' : ''} matched CISA KEV — actively exploited CVEs on attacker infra.`)
  }

  const byMalware = new Map<string, number>()
  events.forEach(e => { if (e.malware_family) byMalware.set(e.malware_family, (byMalware.get(e.malware_family) ?? 0) + 1) })
  const topMalware = [...byMalware.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([n]) => n)
  if (topMalware.length) out.push(`Dominant families: ${topMalware.join(', ')}.`)

  const byTtp = new Map<string, number>()
  events.forEach(e => e.mitre_ttps?.forEach(t => byTtp.set(t, (byTtp.get(t) ?? 0) + 1)))
  const topTtps = [...byTtp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([id]) => id)
  if (topTtps.length) out.push(`Dominant TTPs: ${topTtps.join(' · ')}.`)

  return out
}

const MOTIVATION_COLOR: Record<string, string> = {
  financial:   'text-yellow-500',
  espionage:   'text-blue-400',
  disruption:  'text-red-400',
  hacktivism:  'text-purple-400',
}

const SEV_COLOR_TEXT: Record<number, string> = {
  4: 'text-red-500', 3: 'text-orange-400', 2: 'text-yellow-400', 1: 'text-slate-400',
}

function IntelTab() {
  const filteredEvents = useFilteredEvents()
  const { setSearchQuery } = useThreatStore()

  // Top source IPs and ASNs
  const { topIps, topAsns } = useMemo(() => {
    const ipMap   = new Map<string, { count: number; country: string; maxSev: number }>()
    const asnMap  = new Map<string, { count: number; maxSev: number }>()

    filteredEvents.forEach(e => {
      const ip  = e.source.ip
      const rec = ipMap.get(ip) ?? { count: 0, country: e.source.country_name, maxSev: 0 }
      rec.count++
      rec.maxSev = Math.max(rec.maxSev, e.severity)
      ipMap.set(ip, rec)

      if (e.source.as_org) {
        const r = asnMap.get(e.source.as_org) ?? { count: 0, maxSev: 0 }
        r.count++
        r.maxSev = Math.max(r.maxSev, e.severity)
        asnMap.set(e.source.as_org, r)
      }
    })

    return {
      topIps:  [...ipMap.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 10),
      topAsns: [...asnMap.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 5),
    }
  }, [filteredEvents])

  // Build a broad signal set: malware_family + lowercase/hyphenated tags + observed TTPs
  const { activeFamilies, activeTtps } = useMemo(() => {
    const families = new Set<string>()
    const ttps = new Set<string>()
    filteredEvents.forEach(e => {
      if (e.malware_family) families.add(e.malware_family)
      // Tags like "qakbot", "cobalt-strike" written by the pipeline
      e.tags.forEach(t => families.add(t))
      e.mitre_ttps?.forEach(t => ttps.add(t))
    })
    return { activeFamilies: families, activeTtps: ttps }
  }, [filteredEvents])

  const activeActors = useMemo(() => {
    return THREAT_ACTOR_DB.filter(actor => {
      // Primary: malware_family exact match
      if (actor.malware.some(m => activeFamilies.has(m))) return true
      // Secondary: normalised tag match (lowercase, hyphenated)
      if (actor.malware.some(m => {
        const norm = m.toLowerCase().replace(/\s+/g, '-')
        return activeFamilies.has(norm) || activeFamilies.has(m.toLowerCase())
      })) return true
      // Tertiary: TTP overlap — require ≥2 shared TTPs to avoid noise
      const overlap = actor.ttps.filter(t => activeTtps.has(t)).length
      return overlap >= 2
    })
  }, [activeFamilies, activeTtps])

  const sitrep = useMemo(() => generateSitrep(filteredEvents), [filteredEvents])

  return (
    <div className="flex-1 overflow-y-auto scrollbar-thin p-3 space-y-4">
      {/* Sitrep */}
      <div>
        <div className="text-[8px] font-mono font-bold tracking-widest text-sky-500 mb-2">
          SITUATION REPORT · {new Date().toUTCString().slice(5, 22)} UTC
        </div>
        <div className="border border-white/[0.07] rounded-sm p-2.5 bg-black/30 space-y-1.5">
          {sitrep.map((line, i) => (
            <p key={i} className="text-[10px] text-slate-400 leading-relaxed font-mono">{line}</p>
          ))}
        </div>
      </div>

      {/* Top attackers */}
      {topIps.length > 0 && (
        <div>
          <div className="text-[8px] font-mono font-bold tracking-widest text-sky-500 mb-2">
            TOP SOURCE IPs ({topIps.length})
          </div>
          <div className="border border-white/[0.07] rounded-sm overflow-hidden">
            {topIps.map(([ip, { count, country, maxSev }]) => (
              <button
                key={ip}
                onClick={() => setSearchQuery(ip)}
                className="w-full flex items-center gap-2 px-2 py-1.5 hover:bg-white/5 border-b border-white/5 last:border-0 text-left transition-colors group"
              >
                <span className={`w-1 h-3 rounded-full shrink-0 ${maxSev === 4 ? 'bg-red-500' : maxSev === 3 ? 'bg-orange-400' : maxSev === 2 ? 'bg-yellow-400' : 'bg-slate-500'}`} />
                <span className="text-[10px] font-mono text-slate-300 group-hover:text-sky-300 transition-colors flex-1 truncate">{ip}</span>
                <span className="text-[9px] text-slate-600 truncate max-w-[5rem]">{country}</span>
                <span className={`text-[9px] font-mono font-bold shrink-0 ${SEV_COLOR_TEXT[maxSev]}`}>{count}×</span>
              </button>
            ))}
          </div>
          {topAsns.length > 0 && (
            <div className="mt-2">
              <div className="text-[8px] font-mono font-bold tracking-widest text-sky-500 mb-1.5">
                TOP ASNs
              </div>
              <div className="border border-white/[0.07] rounded-sm overflow-hidden">
                {topAsns.map(([org, { count, maxSev }]) => (
                  <button
                    key={org}
                    onClick={() => setSearchQuery(org)}
                    className="w-full flex items-center gap-2 px-2 py-1.5 hover:bg-white/5 border-b border-white/5 last:border-0 text-left transition-colors group"
                  >
                    <span className={`w-1 h-3 rounded-full shrink-0 ${maxSev === 4 ? 'bg-red-500' : maxSev === 3 ? 'bg-orange-400' : maxSev === 2 ? 'bg-yellow-400' : 'bg-slate-500'}`} />
                    <span className="text-[10px] font-mono text-slate-400 group-hover:text-sky-300 transition-colors flex-1 truncate">{org}</span>
                    <span className={`text-[9px] font-mono font-bold shrink-0 ${SEV_COLOR_TEXT[maxSev]}`}>{count}×</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Threat actor attribution */}
      <div>
        <div className="text-[8px] font-mono font-bold tracking-widest text-sky-500 mb-2">
          ATTRIBUTED ADVERSARIES{activeActors.length > 0 ? ` (${activeActors.length})` : ''}
        </div>
        {activeActors.length === 0 ? (
          <p className="text-[10px] text-slate-700 font-mono italic">
            No attributed actors in current dataset.
          </p>
        ) : (
          <div className="space-y-2">
            {activeActors.map(actor => (
              <div key={actor.id} className="border border-white/[0.07] rounded-sm p-2.5 bg-black/20">
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <div>
                    <a
                      href={malpediaActorUrl(actor.id)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[11px] font-bold text-slate-100 hover:text-purple-300 font-mono leading-tight underline underline-offset-2 decoration-slate-700 hover:decoration-purple-500 transition-colors"
                    >
                      {actor.name}
                    </a>
                    {actor.aliases.length > 0 && (
                      <div className="text-[8px] text-slate-700 font-mono mt-0.5 leading-relaxed">
                        {actor.aliases.slice(0, 3).join(' · ')}
                      </div>
                    )}
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-[9px] text-slate-500 font-mono leading-tight">{actor.suspectedOrigin}</div>
                    <div className={`text-[8px] font-mono uppercase tracking-wide mt-0.5 ${MOTIVATION_COLOR[actor.motivation]}`}>
                      {actor.motivation}
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1 mb-2">
                  {actor.malware.map(m => (
                    <a
                      key={m}
                      href={malpediaMalwareUrl(m)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`px-1 py-px text-[8px] font-mono rounded border transition-colors ${
                        activeFamilies.has(m)
                          ? 'bg-orange-950/60 border-orange-700/50 text-orange-400 hover:text-orange-300'
                          : 'bg-slate-900/60 border-slate-800 text-slate-600 hover:text-slate-400'
                      }`}
                    >
                      {m}
                    </a>
                  ))}
                </div>
                <p className="text-[9px] text-slate-600 leading-relaxed">{actor.description}</p>
                <div className="text-[8px] text-slate-800 font-mono mt-1.5">
                  Active since {actor.firstSeen}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── ATT&CK tab ────────────────────────────────────────────────────────────────

function AttackTab() {
  const filteredEvents = useFilteredEvents()
  const { setSearchQuery, setActiveTab } = useThreatStore()

  const observed = useMemo(() => {
    const seen = new Map<string, number>()
    filteredEvents.forEach(e => {
      e.mitre_ttps?.forEach(id => seen.set(id, (seen.get(id) ?? 0) + 1))
    })
    return seen
  }, [filteredEvents])

  const grouped = useMemo(() => {
    const g = new Map<string, Array<{ id: string; name: string; count: number }>>()
    TACTIC_ORDER.forEach(tactic => g.set(tactic, []))
    observed.forEach((count, id) => {
      const tech = MITRE_TECHNIQUES[id]
      const tactic = tech?.tactic ?? 'Command and Control'
      const bucket = g.get(tactic) ?? []
      bucket.push({ id, name: tech?.name ?? id, count })
      g.set(tactic, bucket)
    })
    TACTIC_ORDER.forEach(t => { if ((g.get(t)?.length ?? 0) === 0) g.delete(t) })
    return g
  }, [observed])

  if (observed.size === 0) {
    return (
      <div className="flex-1 flex items-center justify-center p-6">
        <p className="text-[10px] text-slate-700 font-mono text-center leading-relaxed italic">
          No MITRE ATT&CK TTPs in current dataset.
          <br />TTPs are derived from feed signatures.
        </p>
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-y-auto scrollbar-thin p-3">
      <div className="text-[8px] font-mono font-bold tracking-widest text-sky-500 mb-3">
        OBSERVED TECHNIQUES ({observed.size}) — click to filter feed
      </div>
      <div className="space-y-3">
        {TACTIC_ORDER.filter(t => grouped.has(t)).map(tactic => (
          <div key={tactic}>
            <div className="text-[8px] font-mono text-slate-600 tracking-widest mb-1 uppercase border-b border-white/5 pb-0.5">
              {tactic}
            </div>
            <div className="space-y-px">
              {(grouped.get(tactic) ?? [])
                .sort((a, b) => b.count - a.count)
                .map(tech => (
                  <button
                    key={tech.id}
                    onClick={() => { setSearchQuery(tech.id); setActiveTab('feed') }}
                    className="w-full flex items-center gap-2 px-1.5 py-1 rounded-sm hover:bg-white/5 text-left group transition-colors"
                  >
                    <span className="text-[9px] font-mono text-sky-700 group-hover:text-sky-400 w-14 shrink-0 transition-colors">
                      {tech.id}
                    </span>
                    <span className="text-[10px] text-slate-500 group-hover:text-slate-200 flex-1 truncate transition-colors">
                      {tech.name}
                    </span>
                    <span className="text-[9px] text-slate-700 shrink-0 font-mono">{tech.count}x</span>
                  </button>
                ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── EXPORT tab ────────────────────────────────────────────────────────────────

function ExportTab() {
  const { events } = useThreatStore()
  const filteredEvents = useFilteredEvents()

  return (
    <div className="flex-1 overflow-y-auto scrollbar-thin p-4 space-y-5">
      <div>
        <div className="text-[8px] font-mono font-bold tracking-widest text-sky-500 mb-3">
          IOC EXPORT
        </div>
        <p className="text-[10px] text-slate-500 font-mono leading-relaxed mb-4">
          {filteredEvents.length} indicator{filteredEvents.length !== 1 ? 's' : ''}
          {filteredEvents.length < events.length ? ` (filtered from ${events.length})` : ''} ready to export.
        </p>
        <div className="space-y-2">
          <button
            onClick={() => exportCsv(filteredEvents)}
            disabled={filteredEvents.length === 0}
            className="w-full flex items-center justify-between px-3 py-2.5 border border-white/10 rounded-sm hover:border-sky-500/40 hover:bg-sky-950/20 disabled:opacity-30 disabled:pointer-events-none transition-all group"
          >
            <div className="text-left">
              <div className="text-[11px] font-mono font-semibold text-slate-200 group-hover:text-sky-300 transition-colors">
                CSV Export
              </div>
              <div className="text-[9px] text-slate-600 mt-0.5">
                ip · type · malware · country · severity · CVEs · TTPs
              </div>
            </div>
            <span className="text-[10px] font-mono text-slate-600 group-hover:text-sky-400 transition-colors">.csv</span>
          </button>

          <button
            onClick={() => exportStix(filteredEvents)}
            disabled={filteredEvents.length === 0}
            className="w-full flex items-center justify-between px-3 py-2.5 border border-white/10 rounded-sm hover:border-purple-500/40 hover:bg-purple-950/20 disabled:opacity-30 disabled:pointer-events-none transition-all group"
          >
            <div className="text-left">
              <div className="text-[11px] font-mono font-semibold text-slate-200 group-hover:text-purple-300 transition-colors">
                STIX 2.1 Bundle
              </div>
              <div className="text-[9px] text-slate-600 mt-0.5">
                Structured Threat Information eXpression
              </div>
            </div>
            <span className="text-[10px] font-mono text-slate-600 group-hover:text-purple-400 transition-colors">.json</span>
          </button>
        </div>
      </div>

      <div>
        <div className="text-[8px] font-mono font-bold tracking-widest text-sky-500 mb-2">
          DATA SOURCES
        </div>
        <div className="space-y-1 text-[9px] font-mono text-slate-700 leading-relaxed">
          {[
            'Feodo Tracker — C2 botnet infrastructure',
            'MalwareBazaar — malware sample repository',
            'ThreatFox — IOC sharing platform',
            'URLhaus — malicious URL database',
            'Blocklist.de — attack / bruteforce IPs',
            'CINS Army — threat intelligence feeds',
            'Shodan InternetDB — passive enrichment',
            'CISA KEV — exploited vulnerability catalogue',
            'Emerging Threats — IDS rule signatures',
          ].map(s => <div key={s}>{s}</div>)}
        </div>
      </div>

      <div>
        <div className="text-[8px] font-mono font-bold tracking-widest text-sky-500 mb-1.5">
          USAGE TERMS
        </div>
        <p className="text-[9px] text-slate-700 font-mono leading-relaxed">
          TLP:WHITE — May be distributed freely. Attribution appreciated.
          Data accuracy subject to source quality. Not for automated enforcement.
        </p>
      </div>
    </div>
  )
}

// ── Tab bar definition ────────────────────────────────────────────────────────

const TABS: Array<{ id: SidebarTab; label: string }> = [
  { id: 'feed',   label: 'FEED'   },
  { id: 'intel',  label: 'INTEL'  },
  { id: 'attack', label: 'ATT&CK' },
  { id: 'export', label: 'EXPORT' },
]

// ── Main component ────────────────────────────────────────────────────────────

export function ThreatFeed() {
  const { events, loading, activeTab, setActiveTab, setSidebarOpen } = useThreatStore()

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-white/10 shrink-0">
        <span className="text-[10px] font-bold tracking-widest text-sky-400 uppercase">
          Intel
        </span>
        <div className="flex items-center gap-3">
          {!loading && (
            <span className="text-[10px] text-slate-600">{events.length} events</span>
          )}
          {/* Close button — mobile only */}
          <button
            onClick={() => setSidebarOpen(false)}
            className="md:hidden text-slate-600 hover:text-slate-300 text-xs leading-none transition-colors"
          >
            ✕
          </button>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-white/10 shrink-0">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex-1 py-1.5 text-[9px] font-mono tracking-widest transition-colors border-b-2 ${
              activeTab === tab.id
                ? 'text-sky-400 border-sky-500'
                : 'text-slate-600 hover:text-slate-400 border-transparent'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden flex flex-col min-h-0">
        {activeTab === 'feed'   && <FeedTab />}
        {activeTab === 'intel'  && <IntelTab />}
        {activeTab === 'attack' && <AttackTab />}
        {activeTab === 'export' && <ExportTab />}
      </div>
    </div>
  )
}
