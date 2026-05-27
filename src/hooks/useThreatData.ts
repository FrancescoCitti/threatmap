import { useEffect } from 'react'
import {
  ThreatDataSchema,
  ThreatStatsSchema,
  PipelineHealthSchema,
} from '../types/schema'
import { useThreatStore } from '../stores/threatStore'

const REFRESH_INTERVAL = 5 * 60 * 1000 // 5 min

export function useThreatData() {
  const { setData, setLoading, setError } = useThreatStore()

  useEffect(() => {
    async function load() {
      setLoading(true)
      try {
        const [dataRes, statsRes, healthRes] = await Promise.allSettled([
          fetch('/data/threats-24h.json'),
          fetch('/data/stats-latest.json'),
          fetch('/data/pipeline-health.json'),
        ])

        const parse = async <T>(
          result: PromiseSettledResult<Response>,
          schema: { safeParse: (v: unknown) => { success: boolean; data?: T } }
        ): Promise<T | null> => {
          if (result.status !== 'fulfilled' || !result.value.ok) return null
          const json = await result.value.json()
          const parsed = schema.safeParse(json)
          return parsed.success ? (parsed.data ?? null) : null
        }

        const [data, stats, health] = await Promise.all([
          parse(dataRes, ThreatDataSchema),
          parse(statsRes, ThreatStatsSchema),
          parse(healthRes, PipelineHealthSchema),
        ])

        setData(data?.events ?? [], stats, health)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load data')
      } finally {
        setLoading(false)
      }
    }

    load()
    const timer = setInterval(load, REFRESH_INTERVAL)
    return () => clearInterval(timer)
  }, [setData, setLoading, setError])
}
