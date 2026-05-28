import { useState } from 'react'
import { createPortal } from 'react-dom'
import { useThreatStore } from '../../stores/threatStore'

// ── GitHub Actions trigger ────────────────────────────────────────────────────

const REPO          = 'FrancescoCitti/threatmap'
const WORKFLOW_FILE = 'deploy.yml'

type TriggerStatus = 'idle' | 'running' | 'ok' | 'error'

function UpdateButton() {
  const [status, setStatus]     = useState<TriggerStatus>('idle')
  const [showModal, setShowModal] = useState(false)
  const [patDraft, setPatDraft]   = useState('')

  async function triggerWorkflow(pat: string) {
    setStatus('running')
    try {
      const res = await fetch(
        `https://api.github.com/repos/${REPO}/actions/workflows/${WORKFLOW_FILE}/dispatches`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${pat}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ ref: 'main' }),
        }
      )
      setStatus(res.status === 204 ? 'ok' : 'error')
    } catch {
      setStatus('error')
    }
    setTimeout(() => setStatus('idle'), 5000)
  }

  function handleClick() {
    if (status === 'running') return
    const pat = localStorage.getItem('gh-pat') ?? ''
    if (pat) { triggerWorkflow(pat) } else { setShowModal(true) }
  }

  function handleSave() {
    const pat = patDraft.trim()
    if (!pat) return
    localStorage.setItem('gh-pat', pat)
    setShowModal(false)
    setPatDraft('')
    triggerWorkflow(pat)
  }

  const btnClass = {
    idle:    'border-white/10 text-slate-600 hover:text-sky-400 hover:border-sky-500/40',
    running: 'border-sky-500/40 text-sky-400 animate-pulse cursor-not-allowed',
    ok:      'border-green-500/40 text-green-400',
    error:   'border-red-500/40 text-red-400',
  }[status]

  const btnLabel = {
    idle:    '↺ UPDATE',
    running: '↺ …',
    ok:      '✓ TRIGGERED',
    error:   '✕ ERROR',
  }[status]

  return (
    <>
      {showModal && createPortal(
        <div className="fixed inset-0 z-[200] pointer-events-none flex items-end justify-end p-4 pb-12">
          <div className="pointer-events-auto bg-black/95 border border-sky-900/50 rounded-sm p-3 w-64 font-mono shadow-xl">
            <div className="text-[9px] text-sky-400 font-bold tracking-widest mb-1.5">
              GITHUB ACCESS TOKEN
            </div>
            <p className="text-[9px] text-slate-600 leading-relaxed mb-2">
              Create a PAT with <span className="text-orange-400">workflow</span> scope at
              github.com → Settings → Developer settings. Stored in your browser only.
            </p>
            <input
              autoFocus
              type="password"
              value={patDraft}
              onChange={e => setPatDraft(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSave()}
              placeholder="ghp_…"
              className="w-full bg-black/60 border border-white/10 rounded-sm px-2 py-1.5 text-[11px] font-mono text-slate-300 placeholder:text-slate-700 focus:outline-none focus:border-sky-500/50 mb-2 transition-colors"
            />
            <div className="flex gap-1.5">
              <button
                onClick={handleSave}
                className="flex-1 py-1 text-[9px] font-mono bg-sky-500/20 border border-sky-500/50 text-sky-400 rounded-sm hover:bg-sky-500/30 transition-colors"
              >
                SAVE & TRIGGER
              </button>
              <button
                onClick={() => { setShowModal(false); setPatDraft('') }}
                className="px-2 py-1 text-[9px] font-mono border border-white/10 text-slate-600 rounded-sm hover:text-slate-400 transition-colors"
              >
                ✕
              </button>
            </div>
            <button
              onClick={() => { localStorage.removeItem('gh-pat') }}
              className="mt-1.5 text-[8px] text-slate-800 hover:text-slate-600 font-mono transition-colors"
            >
              clear stored token
            </button>
          </div>
        </div>,
        document.body
      )}

      <button
        onClick={handleClick}
        disabled={status === 'running'}
        className={`shrink-0 px-2 py-px text-[9px] font-mono tracking-widest border rounded-sm transition-all ${btnClass}`}
      >
        {btnLabel}
      </button>
    </>
  )
}

// ── Status bar ────────────────────────────────────────────────────────────────

export function StatusBar() {
  const { stats, health, events, loading } = useThreatStore()

  const total      = stats?.total_events ?? events.length
  const c2Count    = stats?.active_c2_count ?? events.filter((e) => e.type === 'c2').length
  const topCountry = stats?.top_source_countries[0]?.name ?? '—'
  const topMalware = stats?.top_malware_families[0]?.name ?? '—'
  const updatedAt  = stats?.generated_at
    ? new Date(stats.generated_at).toLocaleTimeString('en-US', { hour12: false })
    : null

  const feeds = health?.feeds ? Object.entries(health.feeds) : []

  return (
    <div className="flex items-center gap-3 px-4 h-full text-[10px] font-mono text-slate-500 overflow-hidden whitespace-nowrap">
      <span className="text-sky-500 font-bold tracking-widest shrink-0">THREATMAP</span>

      <span className="text-white/10">│</span>

      <div className="flex items-center gap-1.5 shrink-0">
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${loading ? 'bg-yellow-500 animate-pulse' : 'bg-green-500'}`} />
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
          <span className={`w-1.5 h-1.5 rounded-full ${
            status.status === 'ok' ? 'bg-green-500' : status.status === 'error' ? 'bg-red-500' : 'bg-yellow-500'
          }`} />
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

      <span className="text-white/10">│</span>
      <UpdateButton />
    </div>
  )
}
