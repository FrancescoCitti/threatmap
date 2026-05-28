import { create } from 'zustand'
import type { ThreatEvent, ThreatStats, PipelineHealth } from '../types/schema'

export type SidebarTab = 'feed' | 'intel' | 'attack' | 'export'

interface ThreatState {
  events: ThreatEvent[]
  stats: ThreatStats | null
  health: PipelineHealth | null
  selectedEvent: ThreatEvent | null
  loading: boolean
  error: string | null
  searchQuery: string
  sidebarOpen: boolean
  activeTab: SidebarTab
  timelineHour: string | null
  setData: (events: ThreatEvent[], stats: ThreatStats | null, health: PipelineHealth | null) => void
  setSelected: (event: ThreatEvent | null) => void
  setLoading: (v: boolean) => void
  setError: (msg: string | null) => void
  setSearchQuery: (q: string) => void
  setSidebarOpen: (open: boolean) => void
  setActiveTab: (tab: SidebarTab) => void
  setTimelineHour: (h: string | null) => void
}

export const useThreatStore = create<ThreatState>((set) => ({
  events: [],
  stats: null,
  health: null,
  selectedEvent: null,
  loading: true,
  error: null,
  searchQuery: '',
  sidebarOpen: false,
  activeTab: 'feed',
  timelineHour: null,
  setData: (events, stats, health) => set({ events, stats, health }),
  setSelected: (event) => set({ selectedEvent: event }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  setSearchQuery: (searchQuery) => set({ searchQuery }),
  setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
  setActiveTab: (activeTab) => set({ activeTab }),
  setTimelineHour: (timelineHour) => set({ timelineHour }),
}))
