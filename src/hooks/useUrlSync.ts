import { useEffect } from 'react'
import { useThreatStore } from '../stores/threatStore'
import type { SidebarTab } from '../stores/threatStore'

const VALID_TABS: SidebarTab[] = ['feed', 'intel', 'attack', 'export']

function readHash(): { q: string; tab: SidebarTab | null } {
  const hash = window.location.hash.replace(/^#/, '')
  if (!hash) return { q: '', tab: null }
  const params = new URLSearchParams(hash)
  const q = decodeURIComponent(params.get('q') ?? '')
  const tabRaw = params.get('tab') as SidebarTab | null
  const tab = tabRaw && VALID_TABS.includes(tabRaw) ? tabRaw : null
  return { q, tab }
}

function writeHash(q: string, tab: SidebarTab) {
  const params = new URLSearchParams()
  if (q) params.set('q', q)
  if (tab !== 'feed') params.set('tab', tab)
  const str = params.toString()
  window.history.replaceState(
    null, '',
    str ? `#${str}` : window.location.pathname + window.location.search
  )
}

export function useUrlSync() {
  useEffect(() => {
    const { setSearchQuery, setActiveTab } = useThreatStore.getState()

    // Restore state from URL on mount
    const { q, tab } = readHash()
    if (q)   setSearchQuery(q)
    if (tab) setActiveTab(tab)

    // Keep URL in sync whenever search or tab changes
    const unsub = useThreatStore.subscribe((state, prev) => {
      if (state.searchQuery === prev.searchQuery && state.activeTab === prev.activeTab) return
      writeHash(state.searchQuery, state.activeTab)
    })

    // Sync back when user hits browser back/forward
    function onHashChange() {
      const { q: hq, tab: htab } = readHash()
      useThreatStore.getState().setSearchQuery(hq)
      if (htab) useThreatStore.getState().setActiveTab(htab)
    }
    window.addEventListener('hashchange', onHashChange)

    return () => {
      unsub()
      window.removeEventListener('hashchange', onHashChange)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps
}
