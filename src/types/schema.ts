import { z } from 'zod'

export const SourceGeoSchema = z.object({
  ip: z.string(),
  country_code: z.string(),
  country_name: z.string(),
  lat: z.number(),
  lon: z.number(),
  asn: z.number().nullable().optional(),
  as_org: z.string().nullable().optional(),
  // Shodan InternetDB enrichment (present when Shodan has data for the IP)
  ports: z.array(z.number()).optional().default([]),
  vulns: z.array(z.string()).optional().default([]),
  shodan_tags: z.array(z.string()).optional().default([]),
})

export const ThreatEventSchema = z.object({
  id: z.string(),
  ts: z.string(),
  feed: z.enum(['feodo', 'dshield', 'malwarebazaar', 'threatfox', 'urlhaus', 'emerging_threats']),
  type: z.enum(['c2', 'scanner', 'malware_drop', 'ioc', 'botnet']),
  severity: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]),
  malware_family: z.string().optional(),
  source: SourceGeoSchema,
  sensor: z
    .object({ country_code: z.string(), lat: z.number(), lon: z.number() })
    .optional(),
  mitre_ttps: z.array(z.string()).optional(),
  tlp: z.enum(['WHITE', 'GREEN']),
  tags: z.array(z.string()),
  kev_match: z.boolean().optional().default(false),
})

export const ThreatDataSchema = z.object({
  generated_at: z.string(),
  window_hours: z.number(),
  events: z.array(ThreatEventSchema),
})

export const ThreatStatsSchema = z.object({
  generated_at: z.string(),
  window_hours: z.number(),
  total_events: z.number(),
  active_c2_count: z.number(),
  top_source_countries: z.array(
    z.object({ code: z.string(), name: z.string(), count: z.number() })
  ),
  top_malware_families: z.array(
    z.object({ name: z.string(), count: z.number() })
  ),
  events_by_hour: z.array(
    z.object({ hour: z.string(), count: z.number() })
  ),
})

export const FeedStatusSchema = z.object({
  last_run: z.string().nullable(),
  status: z.enum(['ok', 'error', 'pending']),
  count: z.number(),
  error: z.string().nullable().optional(),
})

export const PipelineHealthSchema = z.object({
  generated_at: z.string(),
  feeds: z.record(FeedStatusSchema),
})

export type ThreatEvent = z.infer<typeof ThreatEventSchema>
export type ThreatData = z.infer<typeof ThreatDataSchema>
export type ThreatStats = z.infer<typeof ThreatStatsSchema>
export type PipelineHealth = z.infer<typeof PipelineHealthSchema>
