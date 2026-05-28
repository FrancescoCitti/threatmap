import { useRef, useEffect, useState, useCallback, useMemo } from 'react'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — react-globe.gl ships CJS types that don't align with Vite ESM
import GlobeGL from 'react-globe.gl'
import * as THREE from 'three'
import { feature } from 'topojson-client'
import type { Topology } from 'topojson-specification'
import { useThreatStore } from '../../stores/threatStore'
import { useFilteredEvents } from '../../hooks/useFilteredEvents'
import type { ThreatEvent } from '../../types/schema'

// ── Colour palettes ───────────────────────────────────────────────────────────

const MALWARE_COLORS: Record<string, string> = {
  Emotet: '#ff4444', QakBot: '#ff8800', IcedID: '#ffaa00',
  TrickBot: '#ffe600', Dridex: '#bb44ff', BazarLoader: '#00aaff',
  'Cobalt Strike': '#ff00cc', AsyncRAT: '#00ffcc', NanoCore: '#44ff66',
  AgentTesla: '#ff6633', FormBook: '#ff44bb', Remcos: '#4488ff',
}
const SEV_COLOR: Record<number, string> = {
  4: '#ff2244', 3: '#ff8800', 2: '#ffdd00', 1: '#4499ff',
}
const DEFAULT_COLOR = '#00ff41'

function getColor(family?: string) {
  return family ? (MALWARE_COLORS[family] ?? DEFAULT_COLOR) : DEFAULT_COLOR
}
function getSevColor(sev: number) {
  return SEV_COLOR[sev] ?? DEFAULT_COLOR
}

// ── ISO 3166-1 numeric → alpha-2 (covers all 177 topojson geometries) ────────

const ISO_NUM_TO_A2: Record<number, string> = {
  4:'AF', 8:'AL', 10:'AQ', 12:'DZ', 24:'AO', 31:'AZ', 32:'AR', 36:'AU',
  40:'AT', 44:'BS', 50:'BD', 51:'AM', 56:'BE', 64:'BT', 68:'BO', 70:'BA',
  72:'BW', 76:'BR', 84:'BZ', 90:'SB', 96:'BN', 100:'BG', 104:'MM', 108:'BI',
  112:'BY', 116:'KH', 120:'CM', 124:'CA', 132:'CV', 140:'CF', 144:'LK',
  148:'TD', 152:'CL', 156:'CN', 158:'TW', 170:'CO', 178:'CG', 180:'CD',
  188:'CR', 191:'HR', 192:'CU', 196:'CY', 203:'CZ', 204:'BJ', 208:'DK',
  214:'DO', 218:'EC', 222:'SV', 226:'GQ', 231:'ET', 232:'ER', 233:'EE',
  238:'FK', 242:'FJ', 246:'FI', 250:'FR', 260:'TF', 262:'DJ', 266:'GA',
  268:'GE', 270:'GM', 275:'PS', 276:'DE', 288:'GH', 300:'GR', 304:'GL',
  320:'GT', 324:'GN', 328:'GY', 332:'HT', 340:'HN', 344:'HK', 348:'HU',
  352:'IS', 356:'IN', 360:'ID', 364:'IR', 368:'IQ', 372:'IE', 376:'IL',
  380:'IT', 384:'CI', 388:'JM', 392:'JP', 398:'KZ', 400:'JO', 404:'KE',
  408:'KP', 410:'KR', 414:'KW', 417:'KG', 418:'LA', 422:'LB', 426:'LS',
  428:'LV', 430:'LR', 434:'LY', 440:'LT', 442:'LU', 450:'MG', 454:'MW',
  458:'MY', 466:'ML', 478:'MR', 484:'MX', 496:'MN', 498:'MD', 499:'ME',
  504:'MA', 508:'MZ', 512:'OM', 516:'NA', 524:'NP', 528:'NL', 540:'NC',
  548:'VU', 554:'NZ', 558:'NI', 562:'NE', 566:'NG', 578:'NO', 586:'PK',
  591:'PA', 598:'PG', 600:'PY', 604:'PE', 608:'PH', 616:'PL', 620:'PT',
  624:'GW', 626:'TL', 630:'PR', 634:'QA', 642:'RO', 643:'RU', 646:'RW',
  682:'SA', 686:'SN', 688:'RS', 694:'SL', 703:'SK', 704:'VN', 705:'SI',
  706:'SO', 710:'ZA', 716:'ZW', 724:'ES', 728:'SS', 729:'SD', 732:'EH',
  740:'SR', 748:'SZ', 752:'SE', 756:'CH', 760:'SY', 762:'TJ', 764:'TH',
  768:'TG', 776:'TO', 780:'TT', 784:'AE', 788:'TN', 792:'TR', 795:'TM',
  800:'UG', 804:'UA', 807:'MK', 818:'EG', 826:'GB', 834:'TZ', 840:'US',
  854:'BF', 858:'UY', 860:'UZ', 862:'VE', 882:'WS', 887:'YE', 894:'ZM',
}

// ── Major internet infrastructure hubs (arc destinations) ────────────────────

const HUBS = [
  { lat: 40.71, lng: -74.01 },  // New York
  { lat: 51.51, lng: -0.13  },  // London
  { lat: 50.11, lng:  8.68  },  // Frankfurt
  { lat: 35.68, lng: 139.69 },  // Tokyo
  { lat:  1.35, lng: 103.82 },  // Singapore
  { lat:-23.55, lng: -46.63 },  // São Paulo
]

function pickHub(lat: number, lng: number, ip: string) {
  // Sort by geographic distance descending, pick from top-3 based on IP hash
  const sorted = [...HUBS].sort(
    (a, b) =>
      (lat - b.lat) ** 2 + (lng - b.lng) ** 2 -
      ((lat - a.lat) ** 2 + (lng - a.lng) ** 2)
  )
  const hash = ip.split('.').reduce((s, o) => s + parseInt(o || '0'), 0)
  return sorted[hash % 3]
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface GlobePoint {
  lat: number; lng: number; size: number; color: string; event: ThreatEvent
}
interface ArcPoint {
  startLat: number; startLng: number
  endLat: number; endLng: number
  color: [string, string]
  dashTime: number
  event: ThreatEvent
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type GeoFeature = any

type ViewMode = 'events' | 'arcs' | 'heat'

// ── Procedural globe texture (dark navy, fully vector-friendly) ───────────────

function makeDarkGlobeTexture(): string {
  const canvas = document.createElement('canvas')
  canvas.width = 512
  canvas.height = 256
  const ctx = canvas.getContext('2d')!
  // Subtle pole-to-equator gradient for a faint sense of depth
  const g = ctx.createLinearGradient(0, 0, 0, 256)
  g.addColorStop(0,   '#040c17')
  g.addColorStop(0.5, '#070f1e')
  g.addColorStop(1,   '#040c17')
  ctx.fillStyle = g
  ctx.fillRect(0, 0, 512, 256)
  return canvas.toDataURL('image/jpeg', 0.9)
}

// ── Component ─────────────────────────────────────────────────────────────────

export function ThreatGlobe() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const globeRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dims, setDims] = useState({ width: 0, height: 0 })
  const [countries, setCountries] = useState<GeoFeature[]>([])
  const [viewMode, setViewMode] = useState<ViewMode>('events')
  const [arcFocusEvent, setArcFocusEvent] = useState<ThreatEvent | null>(null)
  const { selectedEvent, setSelected } = useThreatStore()
  const events = useFilteredEvents()
  const darkGlobeTexture = useMemo(() => makeDarkGlobeTexture(), [])

  // Clear arc focus when leaving arc mode or when the detail panel is closed
  useEffect(() => {
    if (viewMode !== 'arcs' || !selectedEvent) setArcFocusEvent(null)
  }, [viewMode, selectedEvent])

  // Load vector country polygons
  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}data/countries-110m.json`)
      .then((r) => r.json())
      .then((topo: Topology) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const fc = feature(topo, (topo.objects as any).countries) as any
        setCountries(fc.features)
      })
      .catch(() => {})
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

  // Configure renderer, controls, and procedural star field
  useEffect(() => {
    const g = globeRef.current
    if (!g || dims.width === 0) return

    const renderer = g.renderer()
    renderer.setPixelRatio(window.devicePixelRatio)

    const maxAniso = renderer.capabilities.getMaxAnisotropy()
    const scene = g.scene()
    scene.traverse((obj: any) => {
      if (obj.isMesh && obj.material) {
        const mats = Array.isArray(obj.material) ? obj.material : [obj.material]
        mats.forEach((mat: any) => {
          ['map', 'bumpMap', 'specularMap', 'normalMap'].forEach((key) => {
            if (mat[key]) { mat[key].anisotropy = maxAniso; mat[key].needsUpdate = true }
          })
        })
      }
    })

    // Procedural star field — crisp at any zoom
    if (!scene.getObjectByName('starfield')) {
      const COUNT = 8000, R = 900
      const positions = new Float32Array(COUNT * 3)
      const colors = new Float32Array(COUNT * 3)
      const tints = [[1,1,1],[0.85,0.92,1],[1,0.95,0.85],[0.75,0.85,1]]
      for (let i = 0; i < COUNT; i++) {
        const theta = Math.random() * Math.PI * 2
        const phi = Math.acos(2 * Math.random() - 1)
        positions[i*3]   = R * Math.sin(phi) * Math.cos(theta)
        positions[i*3+1] = R * Math.sin(phi) * Math.sin(theta)
        positions[i*3+2] = R * Math.cos(phi)
        const [r,gv,b] = tints[Math.floor(Math.random() * tints.length)]
        const br = 0.4 + Math.random() * 0.6
        colors[i*3]=r*br; colors[i*3+1]=gv*br; colors[i*3+2]=b*br
      }
      const geo = new THREE.BufferGeometry()
      geo.setAttribute('position', new THREE.BufferAttribute(positions, 3))
      geo.setAttribute('color', new THREE.BufferAttribute(colors, 3))
      const mat = new THREE.PointsMaterial({ size:0.6, sizeAttenuation:false, vertexColors:true, transparent:true, opacity:0.9 })
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

  // ── Derived data ────────────────────────────────────────────────────────────

  const points: GlobePoint[] = useMemo(
    () => events.map((e) => ({
      lat: e.source.lat, lng: e.source.lon,
      size: e.severity * 0.18 + 0.12,
      color: getColor(e.malware_family),
      event: e,
    })),
    [events]
  )

  // Top 80 events by severity → arcs toward internet hubs
  const arcs: ArcPoint[] = useMemo(() => {
    return [...events]
      .filter((e) => e.source.lat !== 0 || e.source.lon !== 0)
      .sort((a, b) => b.severity - a.severity)
      .slice(0, 80)
      .map((e) => {
        const hub = pickHub(e.source.lat, e.source.lon, e.source.ip)
        const c = getSevColor(e.severity)
        return {
          startLat: e.source.lat, startLng: e.source.lon,
          endLat: hub.lat, endLng: hub.lng,
          color: [c, 'rgba(255,255,255,0.6)'] as [string, string],
          dashTime: e.severity >= 3 ? 1200 : 2400,
          event: e,
        }
      })
  }, [events])

  // Filter arcs only when user clicks a point while in arc mode
  const visibleArcs = useMemo(() => {
    if (!arcFocusEvent) return arcs
    return arcs.filter(
      (a) => a.startLat === arcFocusEvent.source.lat && a.startLng === arcFocusEvent.source.lon
    )
  }, [arcs, arcFocusEvent])

  // Events per country for heatmap
  const countryCounts = useMemo(() => {
    const m = new Map<string, number>()
    events.forEach((e) => {
      const cc = e.source.country_code
      m.set(cc, (m.get(cc) ?? 0) + 1)
    })
    return m
  }, [events])

  const maxCount = useMemo(
    () => Math.max(...Array.from(countryCounts.values()), 1),
    [countryCounts]
  )

  // ── Globe callbacks ─────────────────────────────────────────────────────────

  const polygonCapColor = useCallback(
    (feat: GeoFeature) => {
      const alpha2 = ISO_NUM_TO_A2[feat.id as number]
      const count = alpha2 ? (countryCounts.get(alpha2) ?? 0) : 0
      if (viewMode !== 'heat' || count === 0) return 'rgba(10,24,44,0.82)'
      const t = Math.min(count / maxCount, 1)
      const r = Math.round(20 + t * 210)
      const gv = Math.round(40 - t * 15)
      const b  = Math.round(60 - t * 35)
      return `rgba(${r},${gv},${b},${0.45 + t * 0.5})`
    },
    [viewMode, countryCounts, maxCount]
  )

  const polygonAltitude = useCallback(
    (feat: GeoFeature) => {
      if (viewMode !== 'heat') return 0.003
      const alpha2 = ISO_NUM_TO_A2[feat.id as number]
      const count = alpha2 ? (countryCounts.get(alpha2) ?? 0) : 0
      if (count === 0) return 0.001
      return 0.003 + (Math.min(count / maxCount, 1)) * 0.06
    },
    [viewMode, countryCounts, maxCount]
  )

  const pointLabel = useCallback((d: object) => {
    const p = d as GlobePoint
    const e = p.event
    const ts = new Date(e.ts).toISOString().replace('T', ' ').slice(0, 16)
    return `
      <div style="background:rgba(7,11,20,0.92);border:1px solid rgba(56,189,248,0.3);
        padding:8px 12px;border-radius:4px;font-family:'JetBrains Mono',monospace;
        font-size:11px;color:#e2e8f0;min-width:160px;">
        <div style="color:${p.color};font-weight:700;margin-bottom:4px">
          ${e.malware_family ?? e.type.toUpperCase()}</div>
        <div style="color:#94a3b8">${e.source.ip}</div>
        <div style="color:#64748b">${e.source.country_name}</div>
        ${e.source.as_org ? `<div style="color:#475569;font-size:10px">${e.source.as_org}</div>` : ''}
        <div style="color:#334155;font-size:10px;margin-top:4px">
          ${e.feed.toUpperCase()} · TLP:${e.tlp} · ${ts} UTC</div>
      </div>`
  }, [])

  const handleClick = useCallback(
    (d: object) => {
      const event = (d as GlobePoint).event
      setSelected(event)
      setArcFocusEvent(viewMode === 'arcs' ? event : null)
    },
    [setSelected, viewMode]
  )

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div ref={containerRef} className="absolute inset-0">
      {dims.width > 0 && (
        <GlobeGL
          ref={globeRef}
          width={dims.width}
          height={dims.height}

          globeImageUrl={darkGlobeTexture}
          atmosphereColor="rgba(56,189,248,0.4)"
          atmosphereAltitude={0.15}

          polygonsData={countries}
          polygonCapColor={polygonCapColor}
          polygonSideColor={() => 'rgba(0,0,0,0)'}
          polygonStrokeColor={() => 'rgba(56,189,248,0.4)'}
          polygonAltitude={polygonAltitude}

          pointsData={points}
          pointLat="lat"
          pointLng="lng"
          pointColor="color"
          pointRadius="size"
          pointAltitude={0.02}
          pointLabel={pointLabel}
          pointsTransitionDuration={800}
          onPointClick={handleClick}

          arcsData={viewMode === 'arcs' ? visibleArcs : []}
          arcStartLat="startLat"
          arcStartLng="startLng"
          arcEndLat="endLat"
          arcEndLng="endLng"
          arcColor="color"
          arcStroke={0.18}
          arcDashLength={1}
          arcDashGap={0}
          arcDashAnimateTime={0}
          arcAltitudeAutoScale={0.22}
        />
      )}

      {/* Layer toggle — bottom-centre of the globe */}
      <div className="absolute bottom-12 left-1/2 -translate-x-1/2 z-10 flex gap-1">
        {(['events', 'arcs', 'heat'] as const).map((m) => (
          <button
            key={m}
            onClick={() => setViewMode(m)}
            className={`px-3 py-1 text-[10px] font-mono tracking-widest border rounded-sm transition-all ${
              viewMode === m
                ? 'bg-sky-500/20 border-sky-500/60 text-sky-400'
                : 'bg-black/50 border-white/10 text-slate-600 hover:text-slate-300 hover:border-white/25'
            }`}
          >
            {m === 'events' ? 'EVENTS' : m === 'arcs' ? 'ARCS' : 'HEAT'}
          </button>
        ))}
      </div>
    </div>
  )
}
