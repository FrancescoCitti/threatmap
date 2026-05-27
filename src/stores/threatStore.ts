import { create } from 'zustand'
import type { ThreatEvent, ThreatStats, PipelineHealth } from '../types/schema'

interface ThreatState {
  events: ThreatEvent[]
  stats: ThreatStats | null
  health: PipelineHealth | null
  selectedEvent: ThreatEvent | null
  loading: boolean
  error: string | null
  setData: (
    events: ThreatEvent[],
    stats: ThreatStats | null,
    health: PipelineHealth | null
  ) => void
  setSelected: (event: ThreatEvent | null) => void
  setLoading: (v: boolean) => void
  setError: (msg: string | null) => void
}

export const useThreatStore = create<ThreatState>((set) => ({
  events: [],
  stats: null,
  health: null,
  selectedEvent: null,
  loading: true,
  error: null,
  setData: (events, stats, health) => set({ events, stats, health }),
  setSelected: (event) => set({ selectedEvent: event }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
}))
