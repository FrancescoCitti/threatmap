import { useState, useEffect } from 'react'
import { ThreatGlobe } from './components/Globe/Globe'
import { ThreatFeed } from './components/ThreatFeed/ThreatFeed'
import { StatusBar } from './components/StatusBar/StatusBar'
import { useThreatData } from './hooks/useThreatData'
import { useThreatStore } from './stores/threatStore'
import { useUrlSync } from './hooks/useUrlSync'
import { getActorsForMalware, malpediaMalwareUrl, malpediaActorUrl } from './data/threatActors'
import type { ThreatEvent } from './types/schema'

const SEV_LABEL: Record<number, string> = {
  1: 'LOW',
  2: 'MEDIUM',
  3: 'HIGH',
  4: 'CRITICAL',
}
const SEV_COLOR: Record<number, string> = {
  1: 'text-slate-400',
  2: 'text-yellow-400',
  3: 'text-orange-400',
  4: 'text-red-500',
}

function DetailRow({
  label,
  value,
  accent,
}: {
  label: string
  value: string
  accent?: boolean
}) {
  return (
    <div className="flex gap-2 items-start">
      <span className="text-slate-600 w-16 shrink-0 text-[10px] pt-px">{label}</span>
      <span className={`text-xs break-all ${accent ? 'text-orange-400' : 'text-slate-300'}`}>
        {value}
      </span>
    </div>
  )
}

function EventDetail({ event: e }: { event: ThreatEvent }) {
  const setSelected = useThreatStore((s) => s.setSelected)
  const setSearchQuery = useThreatStore((s) => s.setSearchQuery)
  const [cveExpanded, setCveExpanded] = useState(false)

  return (
    <div className="absolute bottom-10 left-4 w-72 max-h-[80vh] flex flex-col bg-black/85 backdrop-blur-sm border border-sky-900/50 rounded-sm font-mono">
      <div className="flex items-center justify-between px-3 py-2 border-b border-white/10 shrink-0">
        <span className="text-[10px] font-bold tracking-widest text-sky-400">
          THREAT DETAIL
        </span>
        <button
          onClick={() => setSelected(null)}
          className="text-slate-600 hover:text-slate-300 text-xs leading-none"
        >
          ✕
        </button>
      </div>

      {e.kev_match && (
        <div className="mx-3 my-1.5 px-2 py-1 bg-red-950/60 border border-red-700/50 rounded-sm flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse shrink-0" />
          <span className="text-[9px] font-bold tracking-widest text-red-400">
            CISA KEV — ACTIVELY EXPLOITED CVE ON ATTACKER INFRA
          </span>
        </div>
      )}

      <div className="px-3 py-2 space-y-1.5 overflow-y-auto scrollbar-thin flex-1">
        <DetailRow label="IP" value={e.source.ip} />
        <DetailRow label="FEED" value={e.feed.toUpperCase()} />
        <DetailRow label="TYPE" value={e.type.toUpperCase()} />
        {e.malware_family && (
          <div className="flex gap-2 items-start">
            <span className="text-slate-600 w-16 shrink-0 text-[10px] pt-px">MALWARE</span>
            <a
              href={malpediaMalwareUrl(e.malware_family)}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-orange-400 hover:text-orange-300 underline underline-offset-2 decoration-orange-800 hover:decoration-orange-400 transition-colors break-all"
            >
              {e.malware_family}
            </a>
          </div>
        )}
        {e.malware_family && (() => {
          const actors = getActorsForMalware(e.malware_family)
          if (!actors.length) return null
          return (
            <div className="flex gap-2 items-start">
              <span className="text-slate-600 w-16 shrink-0 text-[10px] pt-0.5">ACTOR</span>
              <div className="flex flex-col gap-0.5">
                {actors.map(a => (
                  <div key={a.id} className="flex items-center gap-1.5">
                    <a
                      href={malpediaActorUrl(a.id)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-purple-400 hover:text-purple-300 text-[10px] font-semibold font-mono underline underline-offset-2 decoration-purple-900 hover:decoration-purple-500 transition-colors"
                    >
                      {a.name}
                    </a>
                    <span className="text-slate-600 text-[9px] font-mono">{a.suspectedOrigin}</span>
                  </div>
                ))}
              </div>
            </div>
          )
        })()}
        <DetailRow label="COUNTRY" value={e.source.country_name} />
        {e.source.asn != null && (
          <div className="flex gap-2 items-start">
            <span className="text-slate-600 w-16 shrink-0 text-[10px] pt-px">ASN</span>
            <span className="text-xs text-slate-300">
              AS{e.source.asn}
              {e.source.as_org && (
                <>
                  {' · '}
                  <button
                    onClick={() => setSearchQuery(e.source.as_org!)}
                    className="text-sky-400 hover:text-sky-300 underline underline-offset-2 decoration-sky-800 hover:decoration-sky-400 transition-colors cursor-pointer"
                    title="Filter by this ASN"
                  >
                    {e.source.as_org}
                  </button>
                </>
              )}
            </span>
          </div>
        )}
        <div className="flex gap-2 items-center">
          <span className="text-slate-600 w-16 shrink-0 text-[10px]">SEVERITY</span>
          <span className={`text-xs font-bold ${SEV_COLOR[e.severity]}`}>
            {SEV_LABEL[e.severity]}
          </span>
        </div>

        {/* Shodan InternetDB enrichment block */}
        {(() => {
          const hasPorts = e.source.ports && e.source.ports.length > 0
          const hasVulns = e.source.vulns && e.source.vulns.length > 0
          const hasTags  = e.source.shodan_tags && e.source.shodan_tags.length > 0
          const hasAny   = hasPorts || hasVulns || hasTags
          return (
            <>
              {hasPorts && (
                <div className="flex gap-2 items-start">
                  <span className="text-slate-600 w-16 shrink-0 text-[10px] pt-0.5">PORTS</span>
                  <div className="flex flex-wrap gap-1">
                    {e.source.ports!.map((p) => (
                      <span key={p} className="px-1 py-px bg-slate-900 border border-slate-800 text-slate-400 text-[9px] font-mono rounded">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {hasVulns && (
                <div className="flex gap-2 items-start">
                  <span className="text-slate-600 w-16 shrink-0 text-[10px] pt-0.5">CVEs</span>
                  <div className="flex flex-col gap-0.5">
                    {(cveExpanded ? e.source.vulns! : e.source.vulns!.slice(0, 5)).map((cve) => (
                      <a
                        key={cve}
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[9px] font-mono text-orange-400 hover:text-orange-300 underline underline-offset-2 decoration-orange-800 hover:decoration-orange-400 transition-colors"
                      >
                        {cve}
                      </a>
                    ))}
                    {e.source.vulns!.length > 5 && (
                      <button
                        onClick={() => setCveExpanded((v) => !v)}
                        className="text-[9px] text-sky-600 hover:text-sky-400 transition-colors text-left mt-0.5"
                      >
                        {cveExpanded
                          ? '▲ show less'
                          : `▼ +${e.source.vulns!.length - 5} more CVEs`}
                      </button>
                    )}
                  </div>
                </div>
              )}
              {hasTags && (
                <div className="flex gap-2 items-start">
                  <span className="text-slate-600 w-16 shrink-0 text-[10px] pt-0.5">INFRA</span>
                  <div className="flex flex-wrap gap-1">
                    {e.source.shodan_tags!.map((t) => (
                      <span key={t} className="px-1 py-px bg-slate-900 border border-slate-800 text-slate-500 text-[9px] rounded">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {!hasAny && (
                <div className="flex gap-2 items-start">
                  <span className="text-slate-600 w-16 shrink-0 text-[10px]">SHODAN</span>
                  <span className="text-[9px] text-slate-700 italic">no data for this IP</span>
                </div>
              )}
            </>
          )
        })()}

        <div className="flex gap-2 items-center">
          <span className="text-slate-600 w-16 shrink-0 text-[10px]">PIVOT</span>
          <div className="flex gap-1">
            {[
              { label: 'VT', href: `https://www.virustotal.com/gui/ip-address/${e.source.ip}` },
              { label: 'AIPDB', href: `https://www.abuseipdb.com/check/${e.source.ip}` },
              { label: 'SHODAN', href: `https://www.shodan.io/host/${e.source.ip}` },
            ].map(({ label, href }) => (
              <a
                key={label}
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="px-1.5 py-0.5 text-[9px] font-mono bg-slate-900 border border-slate-800 text-sky-600 hover:text-sky-400 hover:border-sky-700 rounded transition-colors"
              >
                {label}
              </a>
            ))}
          </div>
        </div>

        <DetailRow label="TLP" value={`TLP:${e.tlp}`} />
        {e.mitre_ttps && e.mitre_ttps.length > 0 && (
          <DetailRow label="TTPs" value={e.mitre_ttps.join('  ')} />
        )}
        <DetailRow
          label="SEEN"
          value={
            new Date(e.ts).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
          }
        />
      </div>

      {e.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 px-3 pb-2 pt-1 border-t border-white/5">
          {e.tags.map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 bg-sky-950/60 text-sky-500 rounded-sm text-[9px] tracking-wide"
            >
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export default function App() {
  useThreatData()
  useUrlSync()
  const selectedEvent  = useThreatStore(s => s.selectedEvent)
  const sidebarOpen    = useThreatStore(s => s.sidebarOpen)
  const setSidebarOpen = useThreatStore(s => s.setSidebarOpen)

  // Global keyboard shortcuts (skip when typing in an input)
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
      const { setSearchQuery, setActiveTab, setTimelineHour } = useThreatStore.getState()
      if (e.key === 'Escape') { setSearchQuery(''); setTimelineHour(null) }
      if (e.key === '1') setActiveTab('feed')
      if (e.key === '2') setActiveTab('intel')
      if (e.key === '3') setActiveTab('attack')
      if (e.key === '4') setActiveTab('export')
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="relative w-screen h-screen bg-[#070b14] overflow-hidden scanlines">
      {/* Full-viewport globe */}
      <ThreatGlobe />

      {/* Top-left branding */}
      <div className="absolute top-4 left-4 pointer-events-none select-none z-10">
        <div className="font-mono leading-tight">
          <span className="text-sky-400 font-bold text-xl tracking-[0.12em]">threatmap</span>
          <span className="text-slate-600 text-base mx-1.5">:</span>
          <span className="text-slate-400 text-sm tracking-wide">Francesco's little globe</span>
        </div>
        <div className="text-slate-600 font-mono text-[9px] tracking-[0.15em] mt-1">
          LIVE · OSINT · GLOBAL CYBER INTELLIGENCE
        </div>
      </div>

      {/* Mobile backdrop — closes sidebar on tap */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-20 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Right sidebar — overlay on mobile, always-on on desktop */}
      <div
        className={`fixed md:absolute top-0 right-0 w-96 h-full md:h-[calc(100vh-2rem)]
          bg-black/90 md:bg-black/65 backdrop-blur-sm border-l border-white/[0.07]
          z-30 md:z-10 flex flex-col transition-transform duration-200
          ${sidebarOpen ? 'translate-x-0' : 'translate-x-full md:translate-x-0'}`}
      >
        <ThreatFeed />
      </div>

      {/* Mobile sidebar toggle — hidden on desktop */}
      <button
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="fixed bottom-14 right-4 md:hidden z-20 px-3 py-1.5 text-[10px] font-mono tracking-widest bg-black/80 border border-sky-500/40 text-sky-400 rounded-sm backdrop-blur-sm"
      >
        {sidebarOpen ? 'CLOSE' : 'INTEL'}
      </button>

      {/* Click-to-inspect panel */}
      {selectedEvent && <EventDetail key={selectedEvent.id} event={selectedEvent} />}

      {/* Bottom status bar */}
      <div className="absolute bottom-0 left-0 right-0 h-8 bg-black/80 backdrop-blur-sm border-t border-white/[0.07] z-10">
        <StatusBar />
      </div>
    </div>
  )
}
