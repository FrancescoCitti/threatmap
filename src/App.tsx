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
      <span className="text-slate-600 w-16 shrink-0 text-[10px] pt-px font-mono uppercase tracking-wider">{label}</span>
      <span className={`text-xs break-all font-mono ${accent ? 'text-orange-400' : 'text-slate-300'}`}>
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
    <div className="absolute bottom-10 left-4 w-72 max-h-[80vh] flex flex-col bg-[#0d0d0d]/95 backdrop-blur-sm border border-[#76b900]/25 rounded-none glow-green-sm">
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#76b900]/15 shrink-0">
        <span className="text-[10px] font-bold tracking-[0.2em] text-[#76b900] uppercase">
          Threat Detail
        </span>
        <button
          onClick={() => setSelected(null)}
          className="text-slate-600 hover:text-slate-300 text-xs leading-none transition-colors"
        >
          ✕
        </button>
      </div>

      {e.kev_match && (
        <div className="mx-3 my-1.5 px-2 py-1 bg-red-950/60 border border-red-700/50 flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse shrink-0" />
          <span className="text-[9px] font-bold tracking-widest text-red-400 font-mono">
            CISA KEV — ACTIVELY EXPLOITED
          </span>
        </div>
      )}

      <div className="px-3 py-2 space-y-1.5 overflow-y-auto scrollbar-thin flex-1">
        <DetailRow label="IP" value={e.source.ip} />
        <DetailRow label="FEED" value={e.feed.toUpperCase()} />
        <DetailRow label="TYPE" value={e.type.toUpperCase()} />
        {e.malware_family && (
          <div className="flex gap-2 items-start">
            <span className="text-slate-600 w-16 shrink-0 text-[10px] pt-px font-mono uppercase tracking-wider">MALWARE</span>
            <a
              href={malpediaMalwareUrl(e.malware_family)}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-mono text-orange-400 hover:text-orange-300 underline underline-offset-2 decoration-orange-800 hover:decoration-orange-400 transition-colors break-all"
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
              <span className="text-slate-600 w-16 shrink-0 text-[10px] font-mono uppercase tracking-wider pt-0.5">ACTOR</span>
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
            <span className="text-slate-600 w-16 shrink-0 text-[10px] font-mono uppercase tracking-wider pt-px">ASN</span>
            <span className="text-xs font-mono text-slate-300">
              AS{e.source.asn}
              {e.source.as_org && (
                <>
                  {' · '}
                  <button
                    onClick={() => setSearchQuery(e.source.as_org!)}
                    className="text-[#76b900] hover:text-[#8fd400] underline underline-offset-2 decoration-[#76b900]/30 hover:decoration-[#76b900] transition-colors cursor-pointer"
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
          <span className="text-slate-600 w-16 shrink-0 text-[10px] font-mono uppercase tracking-wider">SEV</span>
          <span className={`text-xs font-bold font-mono ${SEV_COLOR[e.severity]}`}>
            {SEV_LABEL[e.severity]}
          </span>
        </div>

        {(() => {
          const hasPorts = e.source.ports && e.source.ports.length > 0
          const hasVulns = e.source.vulns && e.source.vulns.length > 0
          const hasTags  = e.source.shodan_tags && e.source.shodan_tags.length > 0
          const hasAny   = hasPorts || hasVulns || hasTags
          return (
            <>
              {hasPorts && (
                <div className="flex gap-2 items-start">
                  <span className="text-slate-600 w-16 shrink-0 text-[10px] font-mono uppercase tracking-wider pt-0.5">PORTS</span>
                  <div className="flex flex-wrap gap-1">
                    {e.source.ports!.map((p) => (
                      <span key={p} className="px-1 py-px bg-[#1a1a1a] border border-white/10 text-slate-400 text-[9px] font-mono">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {hasVulns && (
                <div className="flex gap-2 items-start">
                  <span className="text-slate-600 w-16 shrink-0 text-[10px] font-mono uppercase tracking-wider pt-0.5">CVEs</span>
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
                        className="text-[9px] font-mono text-[#76b900]/60 hover:text-[#76b900] transition-colors text-left mt-0.5"
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
                  <span className="text-slate-600 w-16 shrink-0 text-[10px] font-mono uppercase tracking-wider pt-0.5">INFRA</span>
                  <div className="flex flex-wrap gap-1">
                    {e.source.shodan_tags!.map((t) => (
                      <span key={t} className="px-1 py-px bg-[#1a1a1a] border border-white/10 text-slate-500 text-[9px] font-mono">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {!hasAny && (
                <div className="flex gap-2 items-start">
                  <span className="text-slate-600 w-16 shrink-0 text-[10px] font-mono uppercase tracking-wider">SHODAN</span>
                  <span className="text-[9px] font-mono text-slate-700 italic">no data for this IP</span>
                </div>
              )}
            </>
          )
        })()}

        <div className="flex gap-2 items-center">
          <span className="text-slate-600 w-16 shrink-0 text-[10px] font-mono uppercase tracking-wider">PIVOT</span>
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
                className="px-1.5 py-0.5 text-[9px] font-mono bg-[#1a1a1a] border border-white/10 text-[#76b900]/70 hover:text-[#76b900] hover:border-[#76b900]/50 transition-colors"
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
        <div className="flex flex-wrap gap-1 px-3 pb-2 pt-1 border-t border-[#76b900]/10">
          {e.tags.map((t) => (
            <span
              key={t}
              className="px-1.5 py-0.5 bg-[#76b900]/10 text-[#76b900] text-[9px] font-mono tracking-wide border border-[#76b900]/20"
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
    <div className="relative w-screen h-screen bg-[#0a0a0a] overflow-hidden">
      {/* Full-viewport globe */}
      <ThreatGlobe />

      {/* Top-left branding */}
      <div className="absolute top-5 left-5 pointer-events-none select-none z-10">
        <div className="flex items-stretch gap-3">
          <div className="w-[3px] bg-[#76b900] rounded-full" />
          <div>
            <div className="font-black text-[22px] tracking-tight text-white leading-none">
              THREATMAP
            </div>
            <div className="text-[#76b900] text-[10px] font-semibold tracking-[0.3em] mt-1.5 uppercase">
              Live Global Intelligence
            </div>
          </div>
        </div>
      </div>

      {/* Mobile backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/70 z-20 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Right sidebar */}
      <div
        className={`fixed md:absolute top-0 right-0 w-96 h-full md:h-[calc(100vh-2rem)]
          bg-[#0d0d0d]/95 md:bg-[#0d0d0d]/90 backdrop-blur-sm border-l border-[#76b900]/15
          z-30 md:z-10 flex flex-col transition-transform duration-200 glow-green-sm
          ${sidebarOpen ? 'translate-x-0' : 'translate-x-full md:translate-x-0'}`}
      >
        <ThreatFeed />
      </div>

      {/* Mobile sidebar toggle */}
      <button
        onClick={() => setSidebarOpen(!sidebarOpen)}
        className="fixed bottom-14 right-4 md:hidden z-20 px-3 py-1.5 text-[10px] font-mono tracking-widest bg-[#0d0d0d]/90 border border-[#76b900]/40 text-[#76b900] backdrop-blur-sm"
      >
        {sidebarOpen ? 'CLOSE' : 'INTEL'}
      </button>

      {/* Click-to-inspect panel */}
      {selectedEvent && <EventDetail key={selectedEvent.id} event={selectedEvent} />}

      {/* Bottom status bar */}
      <div className="absolute bottom-0 left-0 right-0 h-8 bg-[#0d0d0d]/95 backdrop-blur-sm border-t border-[#76b900]/15 z-10">
        <StatusBar />
      </div>
    </div>
  )
}
