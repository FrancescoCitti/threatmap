import { useRef, useEffect, useState, useCallback } from 'react'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — react-globe.gl ships CJS types that don't align with Vite ESM
import GlobeGL from 'react-globe.gl'
import { useThreatStore } from '../../stores/threatStore'
import type { ThreatEvent } from '../../types/schema'

const MALWARE_COLORS: Record<string, string> = {
  Emotet: '#ff4444',
  QakBot: '#ff8800',
  IcedID: '#ffaa00',
  TrickBot: '#ffe600',
  Dridex: '#bb44ff',
  BazarLoader: '#00aaff',
  'Cobalt Strike': '#ff00cc',
  AsyncRAT: '#00ffcc',
  NanoCore: '#44ff66',
  AgentTesla: '#ff6633',
  FormBook: '#ff44bb',
  Remcos: '#4488ff',
}
const DEFAULT_COLOR = '#00ff41'

function getColor(family?: string) {
  if (!family) return DEFAULT_COLOR
  return MALWARE_COLORS[family] ?? DEFAULT_COLOR
}

interface GlobePoint {
  lat: number
  lng: number
  size: number
  color: string
  event: ThreatEvent
}

export function ThreatGlobe() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const globeRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dims, setDims] = useState({ width: 0, height: 0 })
  const { events, setSelected } = useThreatStore()

  // Track container size
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect
      setDims({ width, height })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // Auto-rotate after mount
  useEffect(() => {
    const g = globeRef.current
    if (!g) return
    g.controls().autoRotate = true
    g.controls().autoRotateSpeed = 0.25
    g.controls().enableDamping = true
    g.pointOfView({ lat: 30, lng: 15, altitude: 2.2 }, 0)
  }, [dims.width]) // re-apply once globe has rendered

  const points: GlobePoint[] = events.map((e) => ({
    lat: e.source.lat,
    lng: e.source.lon,
    size: e.severity * 0.18 + 0.12,
    color: getColor(e.malware_family),
    event: e,
  }))

  const pointLabel = useCallback((d: object) => {
    const p = d as GlobePoint
    const e = p.event
    const ts = new Date(e.ts).toISOString().replace('T', ' ').slice(0, 16)
    return `
      <div style="
        background:rgba(7,11,20,0.92);
        border:1px solid rgba(56,189,248,0.3);
        padding:8px 12px;border-radius:4px;
        font-family:'JetBrains Mono',monospace;font-size:11px;
        color:#e2e8f0;min-width:160px;
      ">
        <div style="color:${p.color};font-weight:700;margin-bottom:4px">
          ${e.malware_family ?? e.type.toUpperCase()}
        </div>
        <div style="color:#94a3b8">${e.source.ip}</div>
        <div style="color:#64748b">${e.source.country_name}</div>
        ${e.source.as_org ? `<div style="color:#475569;font-size:10px">${e.source.as_org}</div>` : ''}
        <div style="color:#334155;font-size:10px;margin-top:4px">
          ${e.feed.toUpperCase()} · TLP:${e.tlp} · ${ts} UTC
        </div>
      </div>
    `
  }, [])

  const handleClick = useCallback(
    (d: object) => setSelected((d as GlobePoint).event),
    [setSelected]
  )

  return (
    <div ref={containerRef} className="absolute inset-0">
      {dims.width > 0 && (
        <GlobeGL
          ref={globeRef}
          width={dims.width}
          height={dims.height}
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
          bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
          backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
          atmosphereColor="rgba(56,189,248,0.35)"
          atmosphereAltitude={0.13}
          pointsData={points}
          pointLat="lat"
          pointLng="lng"
          pointColor="color"
          pointRadius="size"
          pointAltitude={0.02}
          pointLabel={pointLabel}
          pointsTransitionDuration={800}
          onPointClick={handleClick}
        />
      )}
    </div>
  )
}
