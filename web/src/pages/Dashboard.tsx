import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import type { CallbackInteraction, CallbackToken } from '../stores/callbackStore'
import type { XSSFire, XSSProbe } from '../stores/xssHunterStore'
import { useTeamStore } from '../stores/teamStore'
import { useTeamFlaggedStore, type FlaggedRequest } from '../stores/teamFlaggedStore'
import { useRequestStore, type RequestDetail } from '../stores/requestStore'
import { useSettingsStore } from '../stores/settingsStore'
import NetworkGraph from '../components/NetworkGraph'
import FlaggedRequestModal from '../components/FlaggedRequestModal'
import type { SliverSession, PluginGraphData } from '../components/NetworkGraph'

interface UnifiedEvent {
  id: string
  kind: 'dns' | 'http' | 'xss'
  label: string       // token name or probe name
  source: string      // source IP
  detail: string      // queryName, path, or fired URL
  timestamp: string
}


interface LocalChatMessage {
  id: number
  author: string
  text: string
  timestamp: number
}

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

const CHAT_HEIGHT_KEY = 'joro-chat-height'
const DEFAULT_CHAT_HEIGHT = 256
const MIN_CHAT_HEIGHT = 100
const MAX_CHAT_HEIGHT = 600

function loadChatHeight(): number {
  const stored = localStorage.getItem(CHAT_HEIGHT_KEY)
  if (stored) {
    const n = parseInt(stored, 10)
    if (!isNaN(n) && n >= MIN_CHAT_HEIGHT && n <= MAX_CHAT_HEIGHT) return n
  }
  return DEFAULT_CHAT_HEIGHT
}

interface DashboardProps {
  teamMode?: boolean
}

export default function Dashboard({ teamMode = false }: DashboardProps) {
  const [mode, setMode] = useState<string>('proxy')
  const [interactions, setInteractions] = useState<CallbackInteraction[]>([])
  const [tokens, setTokens] = useState<CallbackToken[]>([])
  const [fires, setFires] = useState<XSSFire[]>([])
  const [probes, setProbes] = useState<XSSProbe[]>([])
  const [localMessages, setLocalMessages] = useState<LocalChatMessage[]>([])
  const [draft, setDraft] = useState('')
  const [flagError, setFlagError] = useState('')
  const [chatHeight, setChatHeight] = useState(loadChatHeight)
  const chatEndRef = useRef<HTMLDivElement>(null)
  const nextId = useRef(1)

  // Network graph state
  const [localHost, setLocalHost] = useState<{ hostname: string; ip: string } | null>(null)
  const [sliverConnected, setSliverConnected] = useState(false)
  const [sliverLhost, setSliverLhost] = useState('')
  const [sliverLport, setSliverLport] = useState(0)
  const [sliverSessions, setSliverSessions] = useState<SliverSession[]>([])
  const [sliverBeacons, setSliverBeacons] = useState<SliverSession[]>([])
  const [pluginGraphs, setPluginGraphs] = useState<Record<string, PluginGraphData>>({})

  const settings = useSettingsStore((s) => s.settings)

  const teamMessages = useTeamStore((s) => s.messages)
  const activeUsers = useTeamStore((s) => s.activeUsers)
  const setActiveUsers = useTeamStore((s) => s.setActiveUsers)

  const flaggedItems = useTeamFlaggedStore((s) => s.items)
  const setFlaggedItems = useTeamFlaggedStore((s) => s.setItems)
  const removeFlaggedItem = useTeamFlaggedStore((s) => s.removeItem)
  const requestItems = useRequestStore((s) => s.items)
  const [flaggedModal, setFlaggedModal] = useState<FlaggedRequest | null>(null)

  const openFlagged = useCallback(async (id: string) => {
    try {
      const f = await api.getFlagged(id)
      setFlaggedModal(f)
    } catch {
      // ignore — artifact may have been deleted
    }
  }, [])

  const deleteFlagged = useCallback(async (id: string) => {
    removeFlaggedItem(id)
    try {
      await api.deleteFlagged(id)
    } catch {
      // ignore
    }
  }, [removeFlaggedItem])

  const handleDragStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    const startY = e.clientY
    const startHeight = chatHeight

    const onMouseMove = (ev: MouseEvent) => {
      const delta = startY - ev.clientY
      const newHeight = Math.min(MAX_CHAT_HEIGHT, Math.max(MIN_CHAT_HEIGHT, startHeight + delta))
      setChatHeight(newHeight)
    }

    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
      setChatHeight((h) => {
        localStorage.setItem(CHAT_HEIGHT_KEY, String(h))
        return h
      })
    }

    document.body.style.cursor = 'row-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [chatHeight])

  // Fetch system info once on mount
  useEffect(() => {
    api.systemInfo().then(setLocalHost).catch(() => {})
  }, [])

  const fetchData = useCallback(async () => {
    // Isolate each fetch so one failure doesn't block the rest
    const [modeRes, intRes, tokRes, firesRes, probesRes, sliverRes] = await Promise.all([
      api.getMode().catch(() => ({ mode: 'proxy' })),
      api.listInteractions({ limit: 20 }).catch(() => ({ items: [] as CallbackInteraction[] })),
      api.listTokens().catch(() => [] as CallbackToken[]),
      api.listFires({ limit: 20 }).catch(() => ({ items: [] as XSSFire[] })),
      api.listProbes().catch(() => [] as XSSProbe[]),
      api.sliverStatus().catch((): { connected: boolean; lhost?: string; lport?: number } => ({ connected: false })),
    ])
    setMode(modeRes.mode)
    setInteractions(intRes.items || [])
    setTokens(tokRes || [])
    setFires(firesRes.items || [])
    setProbes(probesRes || [])

    setSliverConnected(sliverRes.connected)
    if (sliverRes.connected) {
      setSliverLhost(sliverRes.lhost || '')
      setSliverLport(sliverRes.lport || 0)
      try {
        const sessRes = await api.sliverSessions()
        setSliverSessions(sessRes.sessions || [])
        setSliverBeacons(sessRes.beacons || [])
      } catch {
        setSliverSessions([])
        setSliverBeacons([])
      }
    } else {
      setSliverLhost('')
      setSliverLport(0)
      setSliverSessions([])
      setSliverBeacons([])
    }

    // Fetch plugin graph data (from exec providers that implement GraphProvider).
    try {
      const graphRes = await api.pluginGraph()
      // Convert to the shape expected by NetworkGraph.
      const mapped: Record<string, PluginGraphData> = {}
      for (const [name, info] of Object.entries(graphRes)) {
        mapped[name] = {
          server: info.server,
          nodes: (info.nodes || []).map((n) => ({
            id: n.id,
            name: n.name,
            hostname: n.hostname,
            os: n.os,
            arch: n.arch,
            remoteAddress: n.remoteAddress,
            transport: n.transport,
            username: n.username,
          })),
        }
      }
      setPluginGraphs(mapped)
    } catch {
      setPluginGraphs({})
    }

    // Flagged requests live on the team server; only fetch in team mode.
    if (teamMode) {
      try {
        const flagged = await api.listFlagged({ limit: 50 })
        setFlaggedItems(flagged.items || [])
      } catch {
        // ignore
      }
    }
  }, [teamMode, setFlaggedItems])

  // Chat history is deliberately NOT fetched: clients show only messages arriving after launch.
  useEffect(() => {
    if (!teamMode) return
    api.listActiveUsers()
      .then((users) => setActiveUsers(users || []))
      .catch(() => {})
  }, [teamMode, setActiveUsers])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 5000)
    return () => clearInterval(id)
  }, [fetchData])

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [teamMode ? teamMessages : localMessages])

  const tokenName = (tokenId: string) => {
    const t = tokens.find((tk) => tk.id === tokenId)
    return t ? t.note || t.token : tokenId.slice(0, 8)
  }

  const probeName = (probeId: string) => {
    const p = probes.find((pr) => pr.id === probeId)
    return p ? p.name : probeId.slice(0, 8)
  }

  // Merge callback interactions and XSS fires into a single sorted list
  const unifiedEvents: UnifiedEvent[] = [
    ...interactions.map((i): UnifiedEvent => ({
      id: `cb-${i.id}`,
      kind: i.type as 'dns' | 'http',
      label: tokenName(i.tokenId),
      source: i.sourceIp,
      detail: i.queryName || i.path || '-',
      timestamp: i.timestamp,
    })),
    ...fires.map((f): UnifiedEvent => ({
      id: `xss-${f.id}`,
      kind: 'xss',
      label: probeName(f.probeId),
      source: f.sourceIp,
      detail: f.url || f.origin || '-',
      timestamp: f.firedAt,
    })),
  ]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 20)

  const sendMessage = async () => {
    const text = draft.trim()
    if (!text) return

    // /flag <seq> [note] — flag a locally-captured request into the team.
    if (teamMode && text.startsWith('/flag')) {
      const m = text.match(/^\/flag\s+(\d+)\s*(.*)$/)
      if (!m) {
        setFlagError('Usage: /flag <seq> [note]')
        return
      }
      const seq = parseInt(m[1], 10)
      const note = m[2].trim()
      const summary = requestItems.find((r) => r.seq === seq)
      if (!summary) {
        setFlagError(`Request #${seq} not in local history`)
        return
      }
      setDraft('')
      setFlagError('')
      try {
        const detail = (await api.getRequest(summary.id)) as RequestDetail
        await api.flagRequest({
          host: detail.host,
          method: detail.method,
          url: detail.url,
          status: detail.statusCode,
          reqRaw: detail.reqRaw,
          respRaw: detail.respRaw,
          note,
        })
      } catch {
        setFlagError('Failed to flag request')
      }
      return
    }

    setDraft('')
    if (teamMode) {
      try {
        await api.sendChatMessage(text)
      } catch {
        // ignore
      }
    } else {
      setLocalMessages((prev) => [
        ...prev,
        { id: nextId.current++, author: 'operator', text, timestamp: Date.now() },
      ])
    }
  }

  const showSliver = mode === 'proxy'

  return (
    <div className="flex flex-col h-full p-2 gap-2">
      {/* Top row: Network Graph (left) + Recent Interactions (right) */}
      <div className="flex-1 min-h-0 flex gap-2">
        {/* Network Graph */}
        {showSliver && (
          <div className="flex-1 min-w-0 flex flex-col bg-surface-card border border-border rounded">
            <div className="shrink-0 px-3 py-2 border-b border-border">
              <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
                Network Graph
              </span>
            </div>
            <div className="flex-1 min-h-0">
              <NetworkGraph
                localHost={localHost || undefined}
                teamServer={settings?.listenerUrl ? { url: settings.listenerUrl } : undefined}
                sliverServer={sliverConnected ? { lhost: sliverLhost, lport: sliverLport } : undefined}
                sessions={sliverSessions}
                beacons={sliverBeacons}
                connected={true}
                pluginGraphs={Object.keys(pluginGraphs).length > 0 ? pluginGraphs : undefined}
              />
            </div>
          </div>
        )}

        {/* Right column: Recent Interactions (top) + Flagged Requests (bottom) */}
        <div className="flex-1 min-w-0 flex flex-col gap-2">
        {/* Recent Interactions */}
        <div className="flex-1 min-h-0 flex flex-col bg-surface-card border border-border rounded">
          <div className="shrink-0 px-3 py-2 border-b border-border">
            <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
              Recent Interactions
            </span>
            {unifiedEvents.length > 0 && (
              <span className="ml-2 text-content-muted text-xs">{unifiedEvents.length}</span>
            )}
          </div>
          <div className="flex-1 overflow-y-auto">
            {unifiedEvents.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <span className="text-content-muted text-xs">No interactions yet</span>
              </div>
            ) : (
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-surface-card">
                  <tr className="text-content-secondary text-left">
                    <th className="px-3 py-1.5 font-medium">Type</th>
                    <th className="px-3 py-1.5 font-medium">Name</th>
                    <th className="px-3 py-1.5 font-medium">Source</th>
                    <th className="px-3 py-1.5 font-medium">Detail</th>
                    <th className="px-3 py-1.5 font-medium">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {unifiedEvents.map((e) => (
                    <tr key={e.id} className="border-t border-border-subtle hover:bg-surface-hover">
                      <td className="px-3 py-1.5">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            e.kind === 'dns'
                              ? 'bg-accent-secondary/20 text-accent-secondary'
                              : e.kind === 'xss'
                              ? 'bg-semantic-special/20 text-semantic-special'
                              : 'bg-accent/20 text-accent'
                          }`}
                        >
                          {e.kind}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 text-content-primary">{e.label}</td>
                      <td className="px-3 py-1.5 text-content-secondary">{e.source}</td>
                      <td className="px-3 py-1.5 text-content-secondary truncate max-w-[200px]">
                        {e.detail}
                      </td>
                      <td className="px-3 py-1.5 text-content-muted">{timeAgo(e.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Flagged Requests (team mode only) */}
        {teamMode && (
          <div className="flex-1 min-h-0 flex flex-col bg-surface-card border border-border rounded">
            <div className="shrink-0 px-3 py-2 border-b border-border">
              <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
                Flagged Requests
              </span>
              {flaggedItems.length > 0 && (
                <span className="ml-2 text-content-muted text-xs">{flaggedItems.length}</span>
              )}
            </div>
            <div className="flex-1 overflow-y-auto">
              {flaggedItems.length === 0 ? (
                <div className="flex items-center justify-center h-full">
                  <span className="text-content-muted text-xs">No flagged requests yet</span>
                </div>
              ) : (
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-surface-card">
                    <tr className="text-content-secondary text-left">
                      <th className="px-3 py-1.5 font-medium">Method</th>
                      <th className="px-3 py-1.5 font-medium">URL</th>
                      <th className="px-3 py-1.5 font-medium">Status</th>
                      <th className="px-3 py-1.5 font-medium">By</th>
                      <th className="px-3 py-1.5 font-medium">Time</th>
                      <th className="px-3 py-1.5 font-medium"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {flaggedItems.map((f) => (
                      <tr
                        key={f.id}
                        onClick={() => openFlagged(f.id)}
                        className="border-t border-border-subtle hover:bg-surface-hover cursor-pointer"
                      >
                        <td className="px-3 py-1.5 font-bold text-accent-secondary">{f.method}</td>
                        <td className="px-3 py-1.5 text-content-primary truncate max-w-[240px]" title={f.note || f.url}>
                          {f.url}
                        </td>
                        <td
                          className={`px-3 py-1.5 ${
                            f.status < 300
                              ? 'text-semantic-success'
                              : f.status < 400
                              ? 'text-semantic-warning'
                              : 'text-semantic-error'
                          }`}
                        >
                          {f.status || '-'}
                        </td>
                        <td className="px-3 py-1.5 text-content-secondary">{f.author}</td>
                        <td className="px-3 py-1.5 text-content-muted">{timeAgo(f.createdAt)}</td>
                        <td className="px-3 py-1.5 text-right">
                          <button
                            onClick={(e) => { e.stopPropagation(); deleteFlagged(f.id) }}
                            className="text-content-muted hover:text-semantic-error"
                            title="Delete flagged request"
                          >
                            ✕
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}
        </div>
      </div>

      {/* Drag handle */}
      <div
        onMouseDown={handleDragStart}
        className="shrink-0 h-1.5 cursor-row-resize rounded-full bg-border hover:bg-accent-secondary transition-colors"
      />

      {/* Team Chat */}
      <div className="shrink-0 flex bg-surface-terminal border border-border rounded" style={{ height: chatHeight }}>
        <div className="flex-1 min-w-0 flex flex-col">
          <div className="shrink-0 px-3 py-2 border-b border-border">
            <span className="text-xs font-semibold text-content-terminal uppercase tracking-wide">
              Team Chat
            </span>
            {!teamMode && <span className="ml-2 text-content-muted text-xs">(local only)</span>}
          </div>
          <div className="flex-1 overflow-y-auto px-3 py-2 space-y-1">
            {teamMode ? (
              teamMessages.length === 0 ? (
                <div className="flex items-center justify-center h-full">
                  <span className="text-content-muted text-xs">No messages yet</span>
                </div>
              ) : (
                teamMessages.map((m) => (
                  <div key={m.id} className="text-xs">
                    {m.author === '*' ? (
                      <span className="text-content-muted italic">[*] {m.text}</span>
                    ) : (
                      <>
                        <span className="text-accent-secondary font-medium">{m.author}</span>
                        <span className="text-content-muted ml-1.5">
                          {new Date(m.createdAt).toLocaleTimeString('en-US', { timeZone: 'UTC' }) + ' UTC'}
                        </span>
                        {m.refId ? (
                          <button
                            onClick={() => openFlagged(m.refId!)}
                            className="ml-2 text-accent-tertiary hover:underline font-medium text-left"
                            title="Review flagged request"
                          >
                            {m.text}
                          </button>
                        ) : (
                          <span className="text-content-terminal ml-2">{m.text}</span>
                        )}
                      </>
                    )}
                  </div>
                ))
              )
            ) : (
              <>
                {localMessages.length === 0 && (
                  <div className="flex items-center justify-center h-full">
                    <span className="text-content-muted text-xs">No messages yet</span>
                  </div>
                )}
                {localMessages.map((m) => (
                  <div key={m.id} className="text-xs">
                    <span className="text-accent-secondary font-medium">{m.author}</span>
                    <span className="text-content-muted ml-1.5">
                      {new Date(m.timestamp).toLocaleTimeString('en-US', { timeZone: 'UTC' }) + ' UTC'}
                    </span>
                    <span className="text-content-terminal ml-2">{m.text}</span>
                  </div>
                ))}
              </>
            )}
            <div ref={chatEndRef} />
          </div>
          {flagError && (
            <div className="shrink-0 px-3 py-1 text-[10px] text-semantic-error border-t border-border">
              {flagError}
            </div>
          )}
          <div className="shrink-0 flex gap-2 px-3 py-2 border-t border-border">
            <input
              type="text"
              value={draft}
              onChange={(e) => { setDraft(e.target.value); if (flagError) setFlagError('') }}
              onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
              placeholder={teamMode ? 'Type a message… (/flag <seq> to flag a request)' : 'Type a message...'}
              className="flex-1 bg-surface-input text-content-primary text-xs px-2 py-1.5 rounded border border-border placeholder:text-content-muted focus:outline-none focus:border-accent-secondary"
            />
            <button
              onClick={sendMessage}
              className="px-3 py-1.5 bg-accent-secondary text-black text-xs font-medium rounded hover:bg-accent-secondary-hover"
            >
              Send
            </button>
          </div>
        </div>

        {/* Active Users sidebar */}
        <div className="w-36 shrink-0 border-l border-border flex flex-col">
          <div className="shrink-0 px-3 py-2 border-b border-border">
            <span className="text-xs font-semibold text-content-terminal uppercase tracking-wide">
              Active Users
            </span>
          </div>
          <div className="flex-1 overflow-y-auto px-3 py-2 space-y-2">
            {teamMode ? (
              activeUsers.length === 0 ? (
                <p className="text-[10px] text-content-muted italic">No users connected</p>
              ) : (
                activeUsers.map((user) => (
                  <div key={user} className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-semantic-success shrink-0" />
                    <span className="text-xs text-content-terminal truncate">{user}</span>
                  </div>
                ))
              )
            ) : (
              <>
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-semantic-success shrink-0" />
                  <span className="text-xs text-content-terminal truncate">operator</span>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {flaggedModal && (
        <FlaggedRequestModal flagged={flaggedModal} onClose={() => setFlaggedModal(null)} />
      )}
    </div>
  )
}
