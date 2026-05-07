import { useCallback, useRef, useState, useMemo } from 'react'
import { Tooltip } from './Tooltip'

export interface SliverSession {
  id: string
  name: string
  hostname: string
  os: string
  arch: string
  remoteAddress: string
  transport: string
  username: string
}

interface NodeState {
  session: SliverSession
  type: 'session' | 'beacon' | 'dead'
  lastSeen: number
  status: 'active' | 'stale'
}

const STALE_TIMEOUT = 30_000

function osIcon(os: string, x: number, y: number) {
  const lower = os.toLowerCase()
  const size = 14
  const ix = x - size / 2
  const iy = y - size / 2

  if (lower.includes('windows') || lower.includes('win')) {
    return (
      <g transform={`translate(${ix},${iy}) scale(${size / 16})`}>
        <path d="M0 2.2L6.5 1.4V7.5H0V2.2Z" fill="var(--color-content-primary)" />
        <path d="M7.3 1.3L16 0V7.5H7.3V1.3Z" fill="var(--color-content-primary)" />
        <path d="M0 8.5H6.5V14.6L0 13.8V8.5Z" fill="var(--color-content-primary)" />
        <path d="M7.3 8.5H16V16L7.3 14.7V8.5Z" fill="var(--color-content-primary)" />
      </g>
    )
  }

  if (lower.includes('linux')) {
    return (
      <g transform={`translate(${ix},${iy}) scale(${size / 16})`}>
        <ellipse cx="8" cy="4" rx="3.5" ry="3.5" fill="var(--color-content-primary)" />
        <circle cx="6.5" cy="3.2" r="0.8" fill="var(--color-surface-card)" />
        <circle cx="9.5" cy="3.2" r="0.8" fill="var(--color-surface-card)" />
        <path d="M5 7C5 7 3 10 3 12C3 14 5 16 8 16C11 16 13 14 13 12C13 10 11 7 11 7Z" fill="var(--color-content-primary)" />
      </g>
    )
  }

  if (lower.includes('darwin') || lower.includes('mac') || lower.includes('osx')) {
    return (
      <g transform={`translate(${ix},${iy}) scale(${size / 16})`}>
        <path d="M12.2 8.4C12.1 6.2 14 5.1 14.1 5C13 3.4 11.2 3.2 10.6 3.1C9.1 3 7.7 4 7 4C6.2 4 5 3.2 3.8 3.2C2.2 3.2 0.7 4.2 0 5.8C-1.2 9 0.3 13.9 1.8 16C2.5 17 3.4 18.1 4.5 18.1C5.6 18 6 17.4 7.3 17.4C8.6 17.4 9 18.1 10.1 18C11.2 18 12 17 12.7 16C13.5 14.8 13.8 13.7 13.8 13.6C13.8 13.6 12.3 13 12.2 8.4Z" fill="var(--color-content-primary)" transform="translate(1,-2) scale(0.85)" />
      </g>
    )
  }

  return (
    <g transform={`translate(${ix},${iy}) scale(${size / 16})`}>
      <rect x="1" y="1" width="14" height="10" rx="1" fill="none" stroke="var(--color-content-primary)" strokeWidth="1.5" />
      <line x1="5" y1="13" x2="11" y2="13" stroke="var(--color-content-primary)" strokeWidth="1.5" />
      <line x1="8" y1="11" x2="8" y2="13" stroke="var(--color-content-primary)" strokeWidth="1.5" />
    </g>
  )
}

function truncate(text: string, maxLen: number): string {
  return text.length > maxLen ? text.slice(0, maxLen - 1) + '\u2026' : text
}

const CHAR_WIDTH_RATIO = 0.6 // monospace char width ≈ fontSize * 0.6
const MIN_FONT = 7

/** Compute fontSize (clamped to min 7px) and truncated text to fit within maxWidth. */
function fitText(text: string, preferredSize: number, maxWidth: number): { text: string; fontSize: number } {
  // Try preferred size first
  let fontSize = preferredSize
  let charW = fontSize * CHAR_WIDTH_RATIO
  if (text.length * charW <= maxWidth) return { text, fontSize }

  // Shrink font down to minimum
  fontSize = Math.max(MIN_FONT, Math.floor(maxWidth / (text.length * CHAR_WIDTH_RATIO)))
  charW = fontSize * CHAR_WIDTH_RATIO
  if (text.length * charW <= maxWidth) return { text, fontSize }

  // Still doesn't fit at min font — truncate
  fontSize = MIN_FONT
  charW = fontSize * CHAR_WIDTH_RATIO
  const maxChars = Math.floor(maxWidth / charW)
  return { text: maxChars >= 2 ? text.slice(0, maxChars - 1) + '\u2026' : text.slice(0, 1), fontSize }
}

function stripPort(addr: string): string {
  if (!addr) return ''
  // Handle IPv6 [::1]:1234
  const bracketEnd = addr.lastIndexOf(']')
  if (bracketEnd !== -1) {
    const colonAfter = addr.indexOf(':', bracketEnd)
    return colonAfter !== -1 ? addr.slice(0, colonAfter) : addr
  }
  // Handle IPv4 1.2.3.4:1234
  const lastColon = addr.lastIndexOf(':')
  const firstColon = addr.indexOf(':')
  if (lastColon !== -1 && lastColon === firstColon) {
    return addr.slice(0, lastColon)
  }
  return addr
}

export interface PluginGraphData {
  server?: { label: string; host: string; port: number }
  nodes: SliverSession[] // same shape as SliverSession (id, name, hostname, os, arch, remoteAddress, transport, username)
}

interface NetworkGraphProps {
  localHost?: { hostname: string; ip: string }
  teamServer?: { url: string }
  sliverServer?: { lhost: string; lport: number }
  sessions: SliverSession[]
  beacons: SliverSession[]
  deadSessions?: SliverSession[]
  connected: boolean
  pluginGraphs?: Record<string, PluginGraphData>
}

const VB_W = 800
const VB_H = 500
const CX = VB_W / 2
const CY = VB_H / 2
const CENTER_R = 32
const NODE_RX = 56
const NODE_RY = 28

function screenToSVG(svg: SVGSVGElement, clientX: number, clientY: number) {
  const ctm = svg.getScreenCTM()
  if (!ctm) return { x: clientX, y: clientY }
  const inv = ctm.inverse()
  return {
    x: inv.a * clientX + inv.c * clientY + inv.e,
    y: inv.b * clientX + inv.d * clientY + inv.f,
  }
}

function serverIcon(x: number, y: number, color: string) {
  return (
    <g transform={`translate(${x - 8},${y - 10})`}>
      <rect x="0" y="0" width="16" height="5" rx="1" fill="none" stroke={color} strokeWidth="1.2" />
      <circle cx="12" cy="2.5" r="1" fill={color} />
      <rect x="0" y="7" width="16" height="5" rx="1" fill="none" stroke={color} strokeWidth="1.2" />
      <circle cx="12" cy="9.5" r="1" fill={color} />
      <rect x="0" y="14" width="16" height="5" rx="1" fill="none" stroke={color} strokeWidth="1.2" />
      <circle cx="12" cy="16.5" r="1" fill={color} />
    </g>
  )
}

export default function NetworkGraph({
  localHost,
  teamServer,
  sliverServer,
  sessions,
  beacons,
  deadSessions = [],
  connected,
  pluginGraphs: _pluginGraphs,
}: NetworkGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({})
  const [dragging, setDragging] = useState(false)
  const dragOffset = useRef({ dx: 0, dy: 0 })

  // Zoom & pan state
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [panning, setPanning] = useState(false)
  const panStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 })

  const MIN_ZOOM = 0.25
  const MAX_ZOOM = 3

  const vbW = VB_W / zoom
  const vbH = VB_H / zoom
  const vbX = (VB_W - vbW) / 2 + pan.x
  const vbY = (VB_H - vbH) / 2 + pan.y

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    const svg = svgRef.current
    if (!svg) return
    const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1
    setZoom(z => Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, z * factor)))
  }, [])

  const handlePanStart = useCallback((e: React.MouseEvent) => {
    // Only pan on background (middle click or left click on SVG background)
    if (e.button !== 1 && e.target !== svgRef.current) return
    e.preventDefault()
    const svg = svgRef.current
    if (!svg) return
    const pt = screenToSVG(svg, e.clientX, e.clientY)
    panStart.current = { x: pt.x, y: pt.y, panX: pan.x, panY: pan.y }
    setPanning(true)

    const onMouseMove = (ev: MouseEvent) => {
      const pt2 = screenToSVG(svg, ev.clientX, ev.clientY)
      setPan({
        x: panStart.current.panX - (pt2.x - panStart.current.x),
        y: panStart.current.panY - (pt2.y - panStart.current.y),
      })
    }

    const onMouseUp = () => {
      setPanning(false)
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
    }

    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [pan])

  const resetView = useCallback(() => {
    setZoom(1)
    setPan({ x: 0, y: 0 })
  }, [])

  // Build node list from sessions, beacons, dead
  const nodes: NodeState[] = useMemo(() => {
    const now = Date.now()
    const result: NodeState[] = []
    for (const s of sessions) {
      result.push({ session: s, type: 'session', lastSeen: now, status: 'active' })
    }
    for (const b of beacons) {
      result.push({ session: b, type: 'beacon', lastSeen: now, status: 'active' })
    }
    for (const d of deadSessions) {
      result.push({ session: d, type: 'dead', lastSeen: now - STALE_TIMEOUT - 1, status: 'stale' })
    }
    return result
  }, [sessions, beacons, deadSessions])

  // Compute default positions for all nodes using layout algorithm
  const totalNodes = nodes.length
  const defaultPositions = useMemo(() => {
    const defaults: Record<string, { x: number; y: number }> = {}
    defaults['joro'] = { x: CX, y: CY }
    defaults['team'] = { x: CX - 220, y: CY }
    defaults['sliver'] = { x: CX + 220, y: CY - 80 }
    const sPos = defaults['sliver']
    const total = nodes.length
    nodes.forEach((node, i) => {
      const angleStart = -Math.PI / 3
      const angleEnd = Math.PI / 3
      const angle = total === 1 ? 0 : angleStart + (i / (total - 1)) * (angleEnd - angleStart)
      const radius = 160
      defaults[`session-${node.session.id}`] = {
        x: sPos.x + Math.cos(angle) * radius + 80,
        y: sPos.y + Math.sin(angle) * radius,
      }
    })
    return defaults
  }, [nodes])

  // Get effective position: user-dragged position or default
  const pos = useCallback(
    (key: string) => positions[key] ?? defaultPositions[key] ?? { x: CX, y: CY },
    [positions, defaultPositions],
  )

  // Generic drag handler for any node
  const handleMouseDown = useCallback((nodeId: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    const svg = svgRef.current
    if (!svg) return

    const current = positions[nodeId] ?? defaultPositions[nodeId] ?? { x: CX, y: CY }
    const svgPt = screenToSVG(svg, e.clientX, e.clientY)
    dragOffset.current = { dx: current.x - svgPt.x, dy: current.y - svgPt.y }
    setDragging(true)

    const onMouseMove = (ev: MouseEvent) => {
      const pt = screenToSVG(svg, ev.clientX, ev.clientY)
      const x = Math.max(NODE_RX, Math.min(VB_W - NODE_RX, pt.x + dragOffset.current.dx))
      const y = Math.max(NODE_RY, Math.min(VB_H - NODE_RY, pt.y + dragOffset.current.dy))
      setPositions(prev => ({
        ...prev,
        [nodeId]: { x, y },
      }))
    }

    const onMouseUp = () => {
      setDragging(false)
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
    }

    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [positions, defaultPositions])

  const isAlive = (node: NodeState) => node.type !== 'dead' && node.status === 'active'

  const borderColor = (node: NodeState) => {
    if (node.type === 'dead' || node.status === 'stale') return 'var(--color-semantic-error)'
    if (node.type === 'beacon') return 'var(--color-semantic-warning)'
    return 'var(--color-accent-secondary)'
  }

  const edgeColor = (node: NodeState) => {
    if (node.type === 'dead' || node.status === 'stale') return 'var(--color-semantic-error)'
    if (node.type === 'beacon') return 'var(--color-semantic-warning)'
    return 'var(--color-accent-secondary)'
  }

  return (
    <div className="relative w-full h-full" style={{ minHeight: 200 }}>
      {/* Zoom controls */}
      <div className="absolute top-2 right-2 z-10 flex items-center gap-1">
        <Tooltip content="Zoom in">
          <button
            onClick={() => setZoom(z => Math.min(MAX_ZOOM, z * 1.2))}
            className="w-6 h-6 flex items-center justify-center rounded bg-surface-input border border-border text-content-secondary text-xs hover:bg-surface-hover"
          >
            +
          </button>
        </Tooltip>
        <Tooltip content="Zoom out">
          <button
            onClick={() => setZoom(z => Math.max(MIN_ZOOM, z / 1.2))}
            className="w-6 h-6 flex items-center justify-center rounded bg-surface-input border border-border text-content-secondary text-xs hover:bg-surface-hover"
          >
            &minus;
          </button>
        </Tooltip>
        <Tooltip content="Reset zoom & pan">
          <button
            onClick={resetView}
            className="h-6 px-1.5 flex items-center justify-center rounded bg-surface-input border border-border text-content-muted text-[10px] font-mono hover:bg-surface-hover"
          >
            {Math.round(zoom * 100)}%
          </button>
        </Tooltip>
      </div>
    <svg
      ref={svgRef}
      viewBox={`${vbX} ${vbY} ${vbW} ${vbH}`}
      preserveAspectRatio="xMidYMid meet"
      className="w-full h-full"
      style={{ cursor: panning ? 'grabbing' : dragging ? 'grabbing' : undefined }}
      onWheel={handleWheel}
      onMouseDown={handlePanStart}
    >
      <defs>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Edge: JORO → Teamserver */}
      {teamServer && (
        <line
          x1={pos('joro').x}
          y1={pos('joro').y}
          x2={pos('team').x}
          y2={pos('team').y}
          stroke="var(--color-accent)"
          strokeWidth={2}
          strokeOpacity={0.8}
        />
      )}

      {/* Edge: JORO → Sliver */}
      {sliverServer && (
        <line
          x1={pos('joro').x}
          y1={pos('joro').y}
          x2={pos('sliver').x}
          y2={pos('sliver').y}
          stroke="var(--color-accent-secondary)"
          strokeWidth={2}
          strokeDasharray="8 4"
          strokeOpacity={0.9}
          style={{ animation: 'joro-edge-flow 1.5s linear infinite' }}
        />
      )}

      {/* Edges: Sliver → Session/Beacon nodes */}
      {sliverServer && totalNodes > 0 && nodes.map((node) => {
        const npos = pos(`session-${node.session.id}`)
        const alive = isAlive(node)
        return (
          <line
            key={`edge-${node.session.id}`}
            x1={pos('sliver').x}
            y1={pos('sliver').y}
            x2={npos.x}
            y2={npos.y}
            stroke={edgeColor(node)}
            strokeWidth={alive ? 2 : 1.5}
            strokeDasharray={alive ? '8 4' : '6 4'}
            strokeOpacity={alive ? 0.9 : 0.4}
            style={alive ? {
              animation: `joro-edge-flow ${node.type === 'beacon' ? '3s' : '1.5s'} linear infinite`,
            } : undefined}
          />
        )
      })}

      {/* Central Joro node (draggable) */}
      <g
        filter="url(#glow)"
        onMouseDown={handleMouseDown('joro')}
        style={{ cursor: 'grab' }}
      >
        <circle
          cx={pos('joro').x}
          cy={pos('joro').y}
          r={CENTER_R}
          fill="var(--color-surface-input)"
          stroke={connected ? 'var(--color-accent)' : 'var(--color-content-muted)'}
          strokeWidth={2.5}
        />
        {/* Computer icon */}
        <rect
          x={pos('joro').x - 12}
          y={pos('joro').y - 10}
          width={24}
          height={15}
          rx={2}
          fill="none"
          stroke={connected ? 'var(--color-accent)' : 'var(--color-content-muted)'}
          strokeWidth={1.5}
        />
        <line
          x1={pos('joro').x - 6}
          y1={pos('joro').y + 8}
          x2={pos('joro').x + 6}
          y2={pos('joro').y + 8}
          stroke={connected ? 'var(--color-accent)' : 'var(--color-content-muted)'}
          strokeWidth={1.5}
        />
        <line
          x1={pos('joro').x}
          y1={pos('joro').y + 5}
          x2={pos('joro').x}
          y2={pos('joro').y + 8}
          stroke={connected ? 'var(--color-accent)' : 'var(--color-content-muted)'}
          strokeWidth={1.5}
        />
      </g>
      {/* JORO label */}
      <text
        x={pos('joro').x}
        y={pos('joro').y + CENTER_R + 14}
        textAnchor="middle"
        fill={connected ? 'var(--color-accent)' : 'var(--color-content-muted)'}
        fontSize={12}
        fontWeight={700}
        fontFamily="monospace"
        style={{ pointerEvents: 'none', userSelect: 'none' }}
      >
        JORO
      </text>
      {/* Hostname under JORO */}
      {localHost && (
        <>
          <text
            x={pos('joro').x}
            y={pos('joro').y + CENTER_R + 27}
            textAnchor="middle"
            fill="var(--color-content-secondary)"
            fontSize={9}
            fontFamily="monospace"
            style={{ pointerEvents: 'none', userSelect: 'none' }}
          >
            {truncate(localHost.hostname, 20)}
          </text>
          <text
            x={pos('joro').x}
            y={pos('joro').y + CENTER_R + 39}
            textAnchor="middle"
            fill="var(--color-content-muted)"
            fontSize={9}
            fontFamily="monospace"
            style={{ pointerEvents: 'none', userSelect: 'none' }}
          >
            {localHost.ip}
          </text>
        </>
      )}

      {/* Teamserver node (draggable) */}
      {teamServer && (
        <g onMouseDown={handleMouseDown('team')} style={{ cursor: 'grab' }}>
          <rect
            x={pos('team').x - NODE_RX}
            y={pos('team').y - NODE_RY}
            width={NODE_RX * 2}
            height={NODE_RY * 2}
            rx={8}
            fill="var(--color-surface-input)"
            stroke="var(--color-accent)"
            strokeWidth={2}
          />
          {serverIcon(pos('team').x - NODE_RX + 20, pos('team').y - 2, 'var(--color-accent)')}
          {(() => {
            const textLeft = pos('team').x - 14
            const textMaxW = pos('team').x + NODE_RX - 6 - textLeft
            const url = teamServer.url.replace(/^https?:\/\//, '')
            const urlFit = fitText(url, 8, textMaxW)
            return (
              <>
                <text
                  x={textLeft}
                  y={pos('team').y - 4}
                  textAnchor="start"
                  fill="var(--color-content-primary)"
                  fontSize={10}
                  fontWeight={600}
                  fontFamily="monospace"
                >
                  TEAMSERVER
                </text>
                <text
                  x={textLeft}
                  y={pos('team').y + 10}
                  textAnchor="start"
                  fill="var(--color-content-muted)"
                  fontSize={urlFit.fontSize}
                  fontFamily="monospace"
                >
                  {urlFit.text}
                </text>
              </>
            )
          })()}
        </g>
      )}

      {/* Sliver server node (draggable) */}
      {sliverServer && (
        <g onMouseDown={handleMouseDown('sliver')} style={{ cursor: 'grab' }}>
          <rect
            x={pos('sliver').x - NODE_RX}
            y={pos('sliver').y - NODE_RY}
            width={NODE_RX * 2}
            height={NODE_RY * 2}
            rx={8}
            fill="var(--color-surface-input)"
            stroke="var(--color-accent-secondary)"
            strokeWidth={2}
          />
          {serverIcon(pos('sliver').x - NODE_RX + 20, pos('sliver').y - 2, 'var(--color-accent-secondary)')}
          {(() => {
            const textLeft = pos('sliver').x - 14
            const textMaxW = pos('sliver').x + NODE_RX - 6 - textLeft
            const addr = `${sliverServer.lhost}:${sliverServer.lport}`
            const addrFit = fitText(addr, 8, textMaxW)
            return (
              <>
                <text
                  x={textLeft}
                  y={pos('sliver').y - 4}
                  textAnchor="start"
                  fill="var(--color-content-primary)"
                  fontSize={10}
                  fontWeight={600}
                  fontFamily="monospace"
                >
                  SLIVER
                </text>
                <text
                  x={textLeft}
                  y={pos('sliver').y + 10}
                  textAnchor="start"
                  fill="var(--color-content-muted)"
                  fontSize={addrFit.fontSize}
                  fontFamily="monospace"
                >
                  {addrFit.text}
                </text>
              </>
            )
          })()}
        </g>
      )}

      {/* Session/beacon nodes (fan out from sliver, draggable) */}
      {sliverServer && totalNodes > 0 && nodes.map((node) => {
        const npos = pos(`session-${node.session.id}`)
        const alive = isAlive(node)
        const s = node.session
        const ip = stripPort(s.remoteAddress)
        return (
          <g
            key={`node-${s.id}`}
            onMouseDown={handleMouseDown(`session-${s.id}`)}
            style={alive ? { cursor: 'grab', animation: 'joro-node-pulse 3s ease-in-out infinite' } : { cursor: 'grab', opacity: 0.5 }}
          >
            <title>{`${s.name}\n${s.hostname} (${s.os}/${s.arch})\n${s.username}\n${s.transport} - ${s.remoteAddress}`}</title>
            <rect
              x={npos.x - NODE_RX}
              y={npos.y - NODE_RY}
              width={NODE_RX * 2}
              height={NODE_RY * 2}
              rx={8}
              fill="var(--color-surface-input)"
              stroke={borderColor(node)}
              strokeWidth={alive ? 2 : 1}
              strokeDasharray={alive ? undefined : '4 3'}
            />
            {osIcon(s.os, npos.x - NODE_RX + 16, npos.y - 4)}
            {(() => {
              const textLeft = npos.x - 20
              const textMaxW = npos.x + NODE_RX - 6 - textLeft
              const nameFit = fitText(s.name || s.hostname, 10, textMaxW)
              const hostFit = fitText(s.hostname, 8, textMaxW)
              const ipFit = fitText(ip, 7, textMaxW)
              return (
                <>
                  <text
                    x={textLeft}
                    y={npos.y - 6}
                    textAnchor="start"
                    fill="var(--color-content-primary)"
                    fontSize={nameFit.fontSize}
                    fontWeight={600}
                    fontFamily="monospace"
                  >
                    {nameFit.text}
                  </text>
                  <text
                    x={textLeft}
                    y={npos.y + 6}
                    textAnchor="start"
                    fill="var(--color-content-secondary)"
                    fontSize={hostFit.fontSize}
                    fontFamily="monospace"
                  >
                    {hostFit.text}
                  </text>
                  <text
                    x={textLeft}
                    y={npos.y + 17}
                    textAnchor="start"
                    fill="var(--color-content-muted)"
                    fontSize={ipFit.fontSize}
                    fontFamily="monospace"
                  >
                    {ipFit.text}
                  </text>
                </>
              )
            })()}
            <text
              x={npos.x + NODE_RX - 6}
              y={npos.y - NODE_RY + 12}
              textAnchor="end"
              fill={node.type === 'dead' || node.status === 'stale' ? 'var(--color-semantic-error)' : node.type === 'beacon' ? 'var(--color-semantic-warning)' : 'var(--color-accent-secondary)'}
              fontSize={7}
              fontWeight={700}
              fontFamily="monospace"
              style={{ textTransform: 'uppercase' }}
            >
              {node.type === 'dead' ? 'DEAD' : node.status === 'stale' ? 'LOST' : node.type === 'beacon' ? 'BCN' : 'SES'}
            </text>
          </g>
        )
      })}

      {/* Empty state for sliver */}
      {sliverServer && totalNodes === 0 && (
        <text
          x={pos('sliver').x + 80}
          y={pos('sliver').y + NODE_RY + 20}
          textAnchor="middle"
          fill="var(--color-content-muted)"
          fontSize={11}
          fontFamily="monospace"
        >
          No active sessions
        </text>
      )}
    </svg>
    </div>
  )
}
