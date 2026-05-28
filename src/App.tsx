import { ThreatGlobe } from './components/Globe/Globe'
import { ThreatFeed } from './components/ThreatFeed/ThreatFeed'
import { StatusBar } from './components/StatusBar/StatusBar'
import { useThreatData } from './hooks/useThreatData'
import { useThreatStore } from './stores/threatStore'
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
          <DetailRow label="MALWARE" value={e.malware_family} accent />
        )}
        <DetailRow label="COUNTRY" value={e.source.country_name} />
        {e.source.asn != null && (
          <DetailRow
            label="ASN"
            value={`AS${e.source.asn}${e.source.as_org ? ' · ' + e.source.as_org : ''}`}
          />
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
                    {e.source.vulns!.slice(0, 5).map((cve) => (
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
                      <span className="text-[9px] text-slate-600 italic">
                        +{e.source.vulns!.length - 5} more CVEs
                      </span>
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
  const selectedEvent = useThreatStore((s) => s.selectedEvent)

  return (
    <div className="relative w-screen h-screen bg-[#070b14] overflow-hidden scanlines">
      {/* Full-viewport globe */}
      <ThreatGlobe />

      {/* Top-left branding */}
      <div className="absolute top-4 left-4 pointer-events-none select-none z-10">
        <div className="text-sky-400 font-mono font-bold text-xl tracking-[0.2em]">
          THREATMAP
        </div>
        <div className="text-slate-600 font-mono text-[9px] tracking-[0.15em] mt-0.5">
          GLOBAL CYBER INTELLIGENCE · LIVE · OSINT
        </div>
      </div>

      {/* Right sidebar */}
      <div className="absolute top-0 right-0 w-64 h-[calc(100vh-2rem)] bg-black/65 backdrop-blur-sm border-l border-white/[0.07] z-10">
        <ThreatFeed />
      </div>

      {/* Click-to-inspect panel */}
      {selectedEvent && <EventDetail event={selectedEvent} />}

      {/* Bottom status bar */}
      <div className="absolute bottom-0 left-0 right-0 h-8 bg-black/80 backdrop-blur-sm border-t border-white/[0.07] z-10">
        <StatusBar />
      </div>
    </div>
  )
}
