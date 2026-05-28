import { useMemo } from 'react'
import { useThreatStore } from '../stores/threatStore'
import { THREAT_ACTOR_DB } from '../data/threatActors'
import type { ThreatEvent } from '../types/schema'

// Map normalised malware/tag name → actor names + aliases (built once at module load)
const MALWARE_TO_ACTORS = new Map<string, string[]>()
THREAT_ACTOR_DB.forEach(actor => {
  const labels = [actor.name, actor.id, ...actor.aliases].map(s => s.toLowerCase())
  actor.malware.forEach(m => {
    const keys = [m.toLowerCase(), m.toLowerCase().replace(/\s+/g, '-')]
    keys.forEach(k => {
      if (!MALWARE_TO_ACTORS.has(k)) MALWARE_TO_ACTORS.set(k, [])
      labels.forEach(l => MALWARE_TO_ACTORS.get(k)!.push(l))
    })
  })
})

const SEV_WORD: Record<number, string> = { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' }

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
      // Collect attributed actor names for this event
      const actorLabels: string[] = []
      const lookupKeys = [
        ...(e.malware_family ? [e.malware_family.toLowerCase()] : []),
        ...e.tags.map(t => t.toLowerCase()),
      ]
      lookupKeys.forEach(k => {
        MALWARE_TO_ACTORS.get(k)?.forEach(l => actorLabels.push(l))
      })

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
        SEV_WORD[e.severity],
        ...actorLabels,
      ].join(' ').toLowerCase()

      // All space-separated tokens must match (AND logic)
      return q.split(/\s+/).every(token => corpus.includes(token))
    })
  }, [events, searchQuery, timelineHour])
}
