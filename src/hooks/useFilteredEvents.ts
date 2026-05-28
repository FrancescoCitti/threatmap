import { useMemo } from 'react'
import { useThreatStore } from '../stores/threatStore'
import type { ThreatEvent } from '../types/schema'

export function useFilteredEvents(): ThreatEvent[] {
  const { events, searchQuery, timelineHour } = useThreatStore()

  return useMemo(() => {
    let result = events

    if (timelineHour) {
      result = result.filter(e => e.ts.slice(0, 13) === timelineHour)
    }

    const q = searchQuery.trim().toLowerCase()
    if (!q) return result

    return result.filter(e => {
      const corpus = [
        e.source.ip,
        e.source.country_name,
        e.source.country_code,
        e.source.as_org ?? '',
        String(e.source.asn ?? ''),
        e.malware_family ?? '',
        e.feed,
        e.type,
        e.tags.join(' '),
        (e.mitre_ttps ?? []).join(' '),
        (e.source.vulns ?? []).join(' '),
        (e.source.shodan_tags ?? []).join(' '),
      ].join(' ').toLowerCase()

      // All space-separated tokens must match (AND logic)
      return q.split(/\s+/).every(token => corpus.includes(token))
    })
  }, [events, searchQuery, timelineHour])
}
