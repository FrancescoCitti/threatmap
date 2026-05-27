import { useMemo } from 'react'
import { useThreatStore } from '../../stores/threatStore'
import type { ThreatEvent } from '../../types/schema'

const SEV_LABEL: Record<number, string> = { 1: 'LOW', 2: 'MED', 3: 'HIGH', 4: 'CRIT' }
const SEV_COLOR: Record<number, string> = {
  1: 'text-slate-400',
  2: 'text-yellow-400',
  3: 'text-orange-400',
  4: 'text-red-500',
}
const SEV_DOT: Record<number, string> = {
  1: 'bg-slate-400',
  2: 'bg-yellow-400',
  3: 'bg-orange-400',
  4: 'bg-red-500',
}

function FeedRow({ event: e }: { event: ThreatEvent }) {
  const setSelected = useThreatStore((s) => s.setSelected)
  const time = new Date(e.ts).toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
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
        <span className="text-xs font-semibold text-slate-200 truncate">
          {e.malware_family ?? e.type}
        </span>
        <span className="text-[10px] text-slate-600">·</span>
        <span className="text-[10px] text-slate-500 truncate">{e.source.country_name}</span>
      </div>
      <div className="text-[10px] text-slate-700 font-mono truncate mt-0.5">{e.source.ip}</div>
    </button>
  )
}

export function ThreatFeed() {
  const { events, loading } = useThreatStore()

  const recent = useMemo(
    () => [...events].sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 80),
    [events]
  )

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-3 py-2 border-b border-white/10 shrink-0">
        <span className="text-[10px] font-bold tracking-widest text-sky-400 uppercase">
          Live Feed
        </span>
        {!loading && (
          <span className="text-[10px] text-slate-600">{events.length} events</span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin">
        {loading && (
          <div className="flex items-center justify-center h-20">
            <span className="text-[10px] text-slate-600 font-mono animate-pulse">
              Loading…
            </span>
          </div>
        )}
        {!loading && recent.length === 0 && (
          <div className="flex flex-col items-center justify-center gap-1.5 p-6">
            <div className="w-6 h-6 rounded-full border border-slate-700 flex items-center justify-center">
              <span className="text-slate-600 text-xs">?</span>
            </div>
            <span className="text-[10px] text-slate-600 text-center leading-relaxed">
              No data yet.
              <br />
              Pipeline runs on first deploy.
            </span>
          </div>
        )}
        {recent.map((e) => (
          <FeedRow key={e.id} event={e} />
        ))}
      </div>
    </div>
  )
}
