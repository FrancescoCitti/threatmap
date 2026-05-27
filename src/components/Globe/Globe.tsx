import { useRef, useEffect, useState, useCallback } from 'react'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — react-globe.gl ships CJS types that don't align with Vite ESM
import GlobeGL from 'react-globe.gl'
import * as THREE from 'three'
import { feature } from 'topojson-client'
import type { Topology } from 'topojson-specification'
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type GeoFeature = any

export function ThreatGlobe() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const globeRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dims, setDims] = useState({ width: 0, height: 0 })
  const [countries, setCountries] = useState<GeoFeature[]>([])
  const { events, setSelected } = useThreatStore()

  // Load vector country polygons
  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}data/countries-110m.json`)
      .then((r) => r.json())
      .then((topo: Topology) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const fc = feature(topo, (topo.objects as any).countries) as any
        setCountries(fc.features)
      })
      .catch(() => {/* silently fall back to no polygons */})
  }, [])

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

  // Configure renderer, controls, and procedural star field after mount
  useEffect(() => {
    const g = globeRef.current
    if (!g || dims.width === 0) return

    // Fix DPR for retina/HiDPI displays
    const renderer = g.renderer()
    renderer.setPixelRatio(window.devicePixelRatio)

    // Max anisotropy on all textures for crisp quality at oblique angles
    const maxAniso = renderer.capabilities.getMaxAnisotropy()
    const scene = g.scene()
    scene.traverse((obj: any) => {
      if (obj.isMesh && obj.material) {
        const mats = Array.isArray(obj.material) ? obj.material : [obj.material]
        mats.forEach((mat: any) => {
          ['map', 'bumpMap', 'specularMap', 'normalMap'].forEach((key) => {
            if (mat[key]) {
              mat[key].anisotropy = maxAniso
              mat[key].needsUpdate = true
            }
          })
        })
      }
    })

    // Procedural star field — point-based so it stays perfectly crisp at any zoom
    if (!scene.getObjectByName('starfield')) {
      const COUNT = 8000
      const R = 900
      const positions = new Float32Array(COUNT * 3)
      const colors = new Float32Array(COUNT * 3)
      // Tint palette: mostly white, occasional blue-white or warm-white
      const tints = [
        [1.0, 1.0, 1.0],
        [0.85, 0.92, 1.0],  // cool blue-white
        [1.0, 0.95, 0.85],  // warm white
        [0.75, 0.85, 1.0],  // blue giant
      ]
      for (let i = 0; i < COUNT; i++) {
        const theta = Math.random() * Math.PI * 2
        const phi = Math.acos(2 * Math.random() - 1)
        positions[i * 3]     = R * Math.sin(phi) * Math.cos(theta)
        positions[i * 3 + 1] = R * Math.sin(phi) * Math.sin(theta)
        positions[i * 3 + 2] = R * Math.cos(phi)
        const [r, gv, b] = tints[Math.floor(Math.random() * tints.length)]
        const brightness = 0.4 + Math.random() * 0.6
        colors[i * 3]     = r * brightness
        colors[i * 3 + 1] = gv * brightness
        colors[i * 3 + 2] = b * brightness
      }
      const geo = new THREE.BufferGeometry()
      geo.setAttribute('position', new THREE.BufferAttribute(positions, 3))
      geo.setAttribute('color', new THREE.BufferAttribute(colors, 3))
      const mat = new THREE.PointsMaterial({
        size: 0.6,
        sizeAttenuation: false,   // consistent pixel size regardless of zoom
        vertexColors: true,
        transparent: true,
        opacity: 0.9,
      })
      const stars = new THREE.Points(geo, mat)
      stars.name = 'starfield'
      scene.add(stars)
    }

    g.controls().autoRotate = true
    g.controls().autoRotateSpeed = 0.25
    g.controls().enableDamping = true
    g.controls().dampingFactor = 0.08
    g.controls().minDistance = 101
    g.controls().maxDistance = 800
    g.pointOfView({ lat: 30, lng: 15, altitude: 2.2 }, 0)
  }, [dims.width])

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
          atmosphereColor="rgba(56,189,248,0.35)"
          atmosphereAltitude={0.13}

          // Vector country polygons — crisp at any zoom level
          polygonsData={countries}
          polygonCapColor={() => 'rgba(14, 30, 50, 0.55)'}
          polygonSideColor={() => 'rgba(0,0,0,0)'}
          polygonStrokeColor={() => 'rgba(56,189,248,0.25)'}
          polygonAltitude={0.003}

          // Threat points
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
