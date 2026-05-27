import { useThreatStore } from '../../stores/threatStore'

export function StatusBar() {
  const { stats, health, events, loading } = useThreatStore()

  const total = stats?.total_events ?? events.length
  const c2Count = stats?.active_c2_count ?? events.filter((e) => e.type === 'c2').length
  const topCountry = stats?.top_source_countries[0]?.name ?? '—'
  const topMalware = stats?.top_malware_families[0]?.name ?? '—'
  const updatedAt = stats?.generated_at
    ? new Date(stats.generated_at).toLocaleTimeString('en-US', { hour12: false })
    : null

  const feeds = health?.feeds ? Object.entries(health.feeds) : []

  return (
    <div className="flex items-center gap-3 px-4 h-full text-[10px] font-mono text-slate-500 overflow-hidden whitespace-nowrap">
      <span className="text-sky-500 font-bold tracking-widest shrink-0">THREATMAP</span>

      <span className="text-white/10">│</span>

      <div className="flex items-center gap-1.5 shrink-0">
        <span
          className={`w-1.5 h-1.5 rounded-full shrink-0 ${
            loading ? 'bg-yellow-500 animate-pulse' : 'bg-green-500'
          }`}
        />
        <span>{loading ? 'Refreshing…' : `${total.toLocaleString()} events`}</span>
      </div>

      <div className="flex items-center gap-1 shrink-0">
        <span className="text-orange-400">C2</span>
        <span className="text-slate-400">{c2Count}</span>
      </div>

      <div className="flex items-center gap-1 shrink-0">
        <span>TOP SRC</span>
        <span className="text-slate-300">{topCountry}</span>
      </div>

      <div className="flex items-center gap-1 shrink-0">
        <span>TOP MALWARE</span>
        <span className="text-slate-300">{topMalware}</span>
      </div>

      <div className="flex-1" />

      {feeds.map(([feed, status]) => (
        <div key={feed} className="flex items-center gap-1 shrink-0">
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              status.status === 'ok'
                ? 'bg-green-500'
                : status.status === 'error'
                  ? 'bg-red-500'
                  : 'bg-yellow-500'
            }`}
          />
          <span>{feed}</span>
          <span className="text-slate-700">({status.count})</span>
        </div>
      ))}

      {updatedAt && (
        <>
          <span className="text-white/10">│</span>
          <span className="text-slate-700">updated {updatedAt}</span>
        </>
      )}
    </div>
  )
}
