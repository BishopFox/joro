import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { CapturedWSMessage } from '../lib/api'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { oneDark } from '@codemirror/theme-one-dark'
import { api } from '../lib/api'
import { ResponseRender, usePrettyJson } from '../components/ResponseRender'
import { rawToCurl } from '../lib/httpTransform'
import { RequestDetail, RequestSummary, SortColumn, useRequestStore } from '../stores/requestStore'
import { useDeadDropStore } from '../stores/deadDropStore'
import { useWSStore } from '../stores/wsStore'
import { useResizable } from '../lib/useResizable'
import ContextMenu from '../components/ContextMenu'
import ConfirmModal from '../components/ConfirmModal'
import { Tooltip } from '../components/Tooltip'
import { getSelectionMenuItems } from '../lib/selectionMenu'
import { copyText } from '../lib/clipboard'
import { useSettingsStore } from '../stores/settingsStore'
import { useToastStore } from '../stores/toastStore'
import { CONTENT_TYPE_OPTIONS } from '../lib/contentTypes'

const HIGHLIGHT_COLORS: { key: string; label: string; swatch: string; bg: string }[] = [
  { key: 'red', label: 'Red', swatch: '#E53935', bg: 'rgba(229, 57, 53, 0.18)' },
  { key: 'orange', label: 'Orange', swatch: '#FB8C00', bg: 'rgba(251, 140, 0, 0.18)' },
  { key: 'yellow', label: 'Yellow', swatch: '#FDD835', bg: 'rgba(253, 216, 53, 0.12)' },
  { key: 'green', label: 'Green', swatch: '#43A047', bg: 'rgba(67, 160, 71, 0.18)' },
  { key: 'cyan', label: 'Cyan', swatch: '#00ACC1', bg: 'rgba(0, 172, 193, 0.18)' },
  { key: 'blue', label: 'Blue', swatch: '#1E88E5', bg: 'rgba(30, 136, 229, 0.18)' },
  { key: 'purple', label: 'Purple', swatch: '#8E24AA', bg: 'rgba(142, 36, 170, 0.18)' },
  { key: 'pink', label: 'Pink', swatch: '#D81B60', bg: 'rgba(216, 27, 96, 0.18)' },
  { key: 'gray', label: 'Gray', swatch: '#757575', bg: 'rgba(117, 117, 117, 0.18)' },
]

const HIGHLIGHT_BG_MAP: Record<string, string> = Object.fromEntries(
  HIGHLIGHT_COLORS.map((c) => [c.key, c.bg])
)

function methodBadge(method: string) {
  const colors: Record<string, string> = {
    GET: 'text-semantic-success',
    POST: 'text-semantic-info',
    PUT: 'text-semantic-warning',
    DELETE: 'text-semantic-error',
    PATCH: 'text-semantic-special',
  }
  return <span className={`font-bold ${colors[method] ?? 'text-content-secondary'}`}>{method}</span>
}

function statusBadge(code: number) {
  const color = code < 300 ? 'text-semantic-success' : code < 400 ? 'text-semantic-warning' : 'text-semantic-error'
  return <span className={color}>{code}</span>
}

function protocolBadge(proto?: string) {
  if (!proto || proto === 'HTTP/1.1') return null
  const label = proto.replace('HTTP/', 'h')
  return (
    <span className="inline-block mr-1.5 px-1 py-px rounded-sm bg-surface-input text-accent-secondary text-[10px] font-semibold uppercase tracking-wide align-middle">
      {label}
    </span>
  )
}

function b64Decode(s: string) {
  try { return atob(s) } catch { return s }
}


function formatSize(bytes: number): string {
  if (bytes === 0) return '0'
  if (bytes < 1024) return `${bytes}`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}k`
  return `${(bytes / (1024 * 1024)).toFixed(1)}M`
}

function shortenContentType(ct: string): string {
  if (!ct) return ''
  const semi = ct.indexOf(';')
  return semi >= 0 ? ct.substring(0, semi).trim() : ct.trim()
}


type HistoryTab = 'http' | 'ws'

export default function History() {
  const [historyTab, setHistoryTab] = useState<HistoryTab>('http')

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {/* Sub-tab bar */}
      <div className="flex items-center gap-0.5 px-2 py-1 bg-surface-card border-b border-border shrink-0">
        <button
          onClick={() => setHistoryTab('http')}
          className={`px-3 py-1 rounded-sm text-xs font-semibold transition-colors ${
            historyTab === 'http'
              ? 'bg-accent text-content-primary'
              : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
          }`}
        >
          HTTP
        </button>
        <button
          onClick={() => setHistoryTab('ws')}
          className={`px-3 py-1 rounded-sm text-xs font-semibold transition-colors ${
            historyTab === 'ws'
              ? 'bg-accent text-content-primary'
              : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
          }`}
        >
          WebSocket
        </button>
      </div>

      {historyTab === 'http' ? <HTTPHistory /> : <WSHistory />}
    </div>
  )
}

function WSHistory() {
  const { items, total, loading, selectedConnectionId, selectedMessage, setItems, setSelectedConnectionId, setSelectedMessage, setLoading, clear } = useWSStore()
  const [hostFilter, setHostFilter] = useState('')
  const [msgMenu, setMsgMenu] = useState<{ x: number; y: number; msg: CapturedWSMessage } | null>(null)
  const [confirmClear, setConfirmClear] = useState(false)
  const vSplit = useResizable('vertical', 0.4)
  const navigate = useNavigate()

  function sendWSToManipulate(msg: CapturedWSMessage) {
    // Infer scheme from the stored host (":443" → wss, else ws).
    const port = msg.host.includes(':') ? msg.host.split(':').pop() : ''
    const scheme: 'ws' | 'wss' = port === '80' ? 'ws' : 'wss'
    const bareHost = msg.host.replace(/:(80|443)$/, '')
    const path = msg.url || '/'
    const fullURL = `${scheme}://${msg.host}${path.startsWith('/') ? path : '/' + path}`
    const origin = (scheme === 'wss' ? 'https://' : 'http://') + bareHost
    const rawUpgrade =
      `GET ${path} HTTP/1.1\r\n` +
      `Host: ${bareHost}\r\n` +
      `Upgrade: websocket\r\n` +
      `Connection: Upgrade\r\n` +
      `Sec-WebSocket-Version: 13\r\n` +
      `Origin: ${origin}\r\n` +
      `User-Agent: Joro/1.0\r\n` +
      `\r\n`
    // Text messages use their stored payload verbatim; binary messages are
    // stored hex-encoded so they drop straight into the hex input.
    const sendOpcode = msg.isText ? 'text' : 'binary'
    const sendPayload = msg.isText ? msg.payload : msg.payload.replace(/(..)/g, '$1 ').trim()
    navigate('/manipulate', {
      state: {
        subTab: 'ws',
        url: fullURL,
        scheme,
        host: msg.host,
        rawUpgrade,
        sendOpcode,
        sendPayload,
      },
    })
  }

  async function load() {
    setLoading(true)
    try {
      const data = await api.listWSMessages({
        offset: 0,
        limit: 200,
        ...(hostFilter && { host: hostFilter }),
      })
      setItems(data.items, data.total)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [hostFilter]) // eslint-disable-line

  // Group messages by connectionId for connection list
  const connections = useMemo(() => {
    const map = new Map<string, { connectionId: string; host: string; url: string; count: number; firstTime: string }>()
    for (const m of items) {
      const existing = map.get(m.connectionId)
      if (existing) {
        existing.count++
      } else {
        map.set(m.connectionId, {
          connectionId: m.connectionId,
          host: m.host,
          url: m.url,
          count: 1,
          firstTime: m.timestamp,
        })
      }
    }
    return Array.from(map.values())
  }, [items])

  const filteredMessages = useMemo(() => {
    if (!selectedConnectionId) return []
    return items.filter((m) => m.connectionId === selectedConnectionId)
  }, [items, selectedConnectionId])

  return (
    <div className="flex flex-col flex-1 min-h-0" ref={vSplit.containerRef}>
      {/* Top: connections */}
      <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: vSplit.fraction }}>
        <div className="flex items-center gap-3 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
          <label className="flex items-center gap-1.5">
            <span className="text-xs text-content-muted">Host</span>
            <input
              className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-40"
              value={hostFilter}
              onChange={(e) => setHostFilter(e.target.value)}
            />
          </label>
          <button
            onClick={() => setConfirmClear(true)}
            className="text-xs px-3 py-1 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold shrink-0"
          >
            Clear
          </button>
          <span className="text-content-muted text-xs ml-auto">
            {connections.length} connections, {total} messages
          </span>
        </div>

        <div className="flex-1 overflow-auto min-h-0">
          {loading && <div className="text-content-muted text-sm p-4">Loading...</div>}
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-surface-card text-content-muted uppercase">
              <tr>
                <th className="px-2 py-1 text-left">Host</th>
                <th className="px-2 py-1 text-left">URL</th>
                <th className="px-2 py-1 text-right w-20">Messages</th>
                <th className="px-2 py-1 text-left w-20">Time</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((conn) => (
                <tr
                  key={conn.connectionId}
                  className={`border-b border-border-subtle cursor-pointer hover:bg-surface-hover ${
                    selectedConnectionId === conn.connectionId ? 'bg-surface-hover' : ''
                  }`}
                  onClick={() => setSelectedConnectionId(conn.connectionId)}
                >
                  <td className="px-2 py-1 text-content-secondary">{conn.host}</td>
                  <td className="px-2 py-1 truncate max-w-xs text-content-secondary">{conn.url}</td>
                  <td className="px-2 py-1 text-right text-content-muted">{conn.count}</td>
                  <td className="px-2 py-1 text-content-muted">{conn.firstTime ? new Date(conn.firstTime).toISOString().slice(11, 19) + ' UTC' : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="drag-handle-v" onMouseDown={vSplit.onMouseDown} />

      {/* Bottom: messages */}
      <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: 1 - vSplit.fraction }}>
        {selectedConnectionId ? (
          <>
            <div className="px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
              <span className="text-xs font-semibold text-content-primary">Messages</span>
            </div>
            <div className="flex flex-1 min-h-0">
              <div className="flex-1 overflow-auto min-h-0">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-surface-card text-content-muted uppercase">
                    <tr>
                      <th className="px-2 py-1 text-left w-8">Dir</th>
                      <th className="px-2 py-1 text-left w-20">Time</th>
                      <th className="px-2 py-1 text-right w-16">Size</th>
                      <th className="px-2 py-1 text-left">Preview</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredMessages.map((msg) => (
                      <tr
                        key={msg.id}
                        className={`border-b border-border-subtle cursor-pointer hover:bg-surface-hover ${
                          selectedMessage?.id === msg.id ? 'bg-surface-hover' : ''
                        }`}
                        onClick={() => setSelectedMessage(msg)}
                        onContextMenu={(e) => {
                          e.preventDefault()
                          setMsgMenu({ x: e.clientX, y: e.clientY, msg })
                        }}
                      >
                        <td className="px-2 py-1">
                          <span className={msg.direction === 'client_to_server' ? 'text-semantic-info' : 'text-semantic-warning'}>
                            {msg.direction === 'client_to_server' ? '\u2192' : '\u2190'}
                          </span>
                        </td>
                        <td className="px-2 py-1 text-content-muted">{msg.timestamp ? new Date(msg.timestamp).toISOString().slice(11, 19) + ' UTC' : ''}</td>
                        <td className="px-2 py-1 text-right text-content-muted">{msg.payloadLength}</td>
                        <td className="px-2 py-1 truncate max-w-md text-content-secondary font-mono">
                          {msg.isText ? msg.payload.slice(0, 120) : `[binary ${msg.payloadLength}B]`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {selectedMessage && (
                <div className="w-1/2 border-l border-border flex flex-col min-h-0">
                  <div className="px-2 py-1.5 border-b border-border bg-surface-card shrink-0 flex items-center gap-2">
                    <span className={`text-xs font-semibold ${selectedMessage.direction === 'client_to_server' ? 'text-semantic-info' : 'text-semantic-warning'}`}>
                      {selectedMessage.direction === 'client_to_server' ? 'Client \u2192 Server' : 'Server \u2192 Client'}
                    </span>
                    <span className="text-xs text-content-muted">{selectedMessage.payloadLength}B</span>
                  </div>
                  <div className="flex-1 relative min-h-0">
                    <div className="absolute inset-0 overflow-hidden">
                      <CodeMirror
                        value={selectedMessage.payload}
                        theme={oneDark}
                        readOnly={true}
                        height="100%"
                        extensions={[EditorView.lineWrapping]}
                        basicSetup={{ lineNumbers: true, foldGutter: false }}
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-content-muted text-sm">
            Select a connection to view messages
          </div>
        )}
      </div>

      {msgMenu && (
        <ContextMenu
          x={msgMenu.x}
          y={msgMenu.y}
          onClose={() => setMsgMenu(null)}
          items={[
            { label: 'Manipulate', onClick: () => sendWSToManipulate(msgMenu.msg) },
            {
              label: 'Copy Payload',
              onClick: () => copyText(msgMenu.msg.payload),
            },
          ]}
        />
      )}
      {confirmClear && (
        <ConfirmModal
          title="Clear WebSocket history"
          message="Are you sure you want to delete all WebSocket history? This cannot be undone."
          confirmLabel="Clear"
          onConfirm={async () => {
            setConfirmClear(false)
            await api.clearWSMessages()
            clear()
          }}
          onClose={() => setConfirmClear(false)}
        />
      )}
    </div>
  )
}

function HTTPHistory() {
  const { items, total, filter, loading, selectedDetail, highlights, reloadCounter, sortColumn, sortDir, setSort, setFilter, setItems, setSelectedDetail, setLoading, clear, loadHighlights, setHighlight, removeHighlight } =
    useRequestStore()
  const navigate = useNavigate()
  const [confirmClearAll, setConfirmClearAll] = useState(false)

  const toggleSort = (col: SortColumn) => {
    if (sortColumn === col) {
      setSort(col, sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSort(col, 'asc')
    }
  }

  const sortIndicator = (col: SortColumn) =>
    sortColumn === col ? (sortDir === 'asc' ? ' ▲' : ' ▼') : ''

  const sortedItems = useMemo(() => {
    const sorted = [...items]
    sorted.sort((a, b) => {
      let cmp = 0
      switch (sortColumn) {
        case 'seq': cmp = a.seq - b.seq; break
        case 'statusCode': cmp = a.statusCode - b.statusCode; break
        case 'method': cmp = a.method.localeCompare(b.method); break
        case 'contentType': cmp = (a.contentType || '').localeCompare(b.contentType || ''); break
        case 'url': cmp = a.url.localeCompare(b.url); break
        case 'timestamp': cmp = (a.timestamp || '').localeCompare(b.timestamp || ''); break
        case 'responseSize': cmp = a.responseSize - b.responseSize; break
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
    return sorted
  }, [items, sortColumn, sortDir])

  const [wrapReq, setWrapReq] = useState(true)
  const [wrapResp, setWrapResp] = useState(true)
  const [respTab, setRespTab] = useState<'raw' | 'render'>('raw')
  const [prettyJson, setPrettyJson] = usePrettyJson()
  const [rowMenu, setRowMenu] = useState<{ x: number; y: number; itemId: string } | null>(null)
  const [detailMenu, setDetailMenu] = useState<{ x: number; y: number } | null>(null)

  const settings = useSettingsStore((s) => s.settings)
  const teamMode = !!(settings?.listenerUrl && settings?.teamToken && settings?.teamNickname)
  const addToast = useToastStore((s) => s.addToast)

  const tableRef = useRef<HTMLDivElement>(null)
  const selectedRowRef = useRef<HTMLTableRowElement>(null)
  const vSplit = useResizable('vertical', 0.5)
  const hSplit = useResizable('horizontal', 0.5)

  // Arrow key navigation
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return
      // Don't hijack if user is in an input
      if ((e.target as HTMLElement).tagName === 'INPUT') return
      e.preventDefault()

      const currentIndex = selectedDetail
        ? sortedItems.findIndex((item) => item.id === selectedDetail.id)
        : -1

      let nextIndex: number
      if (e.key === 'ArrowDown') {
        nextIndex = currentIndex < sortedItems.length - 1 ? currentIndex + 1 : currentIndex
      } else {
        nextIndex = currentIndex > 0 ? currentIndex - 1 : 0
      }

      if (nextIndex !== currentIndex && sortedItems[nextIndex]) {
        selectRequest(sortedItems[nextIndex])
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [sortedItems, selectedDetail]) // eslint-disable-line

  // Scroll selected row into view
  useEffect(() => {
    selectedRowRef.current?.scrollIntoView({ block: 'nearest' })
  }, [selectedDetail?.id])

  // Load highlights on mount.
  useEffect(() => { loadHighlights() }, []) // eslint-disable-line

  function sendToManipulate() {
    if (!selectedDetail) return
    let scheme = 'https'
    let host = ''
    try {
      const u = new URL(selectedDetail.url)
      scheme = u.protocol.replace(':', '')
      host = u.host
    } catch {
      host = selectedDetail.host ?? ''
    }
    navigate('/manipulate', { state: { scheme, host, rawReq: selectedDetail.reqRaw } })
  }

  async function flagToTeam() {
    if (!selectedDetail) return
    try {
      await api.flagRequest({
        host: selectedDetail.host,
        method: selectedDetail.method,
        url: selectedDetail.url,
        status: selectedDetail.statusCode,
        reqRaw: selectedDetail.reqRaw,
        respRaw: selectedDetail.respRaw,
      })
      addToast('Flagged to team', 'info')
    } catch {
      addToast('Failed to flag request')
    }
  }

  function stageDetailForDeadDrop(d: RequestDetail) {
    useDeadDropStore.getState().add({
      id: d.id,
      host: d.host,
      method: d.method,
      url: d.url,
      status: d.statusCode,
      reqRaw: d.reqRaw,
      respRaw: d.respRaw,
      truncated: false,
      note: '',
    })
    addToast('Staged for Dead Drop', 'info')
  }

  // Row menu carries only the request id, so fetch the raw bytes on demand.
  async function stageForDeadDrop(id: string) {
    try {
      const d = (await api.getRequest(id)) as RequestDetail
      stageDetailForDeadDrop(d)
    } catch {
      addToast('Failed to stage request')
    }
  }

  function sendToFuzz() {
    if (!selectedDetail) return
    let scheme = 'https'
    let host = ''
    try {
      const u = new URL(selectedDetail.url)
      scheme = u.protocol.replace(':', '')
      host = u.host
    } catch {
      host = selectedDetail.host ?? ''
    }
    navigate('/fuzz', { state: { scheme, host, rawReq: selectedDetail.reqRaw } })
  }

  function copyUrl() {
    if (!selectedDetail) return
    copyText(selectedDetail.url)
  }

  function copyCurl() {
    if (!selectedDetail) return
    const raw = b64Decode(selectedDetail.reqRaw)
    copyText(rawToCurl(raw, selectedDetail.url))
  }

  function copyRaw(tab: 'request' | 'response') {
    if (!selectedDetail) return
    const raw = tab === 'request' ? selectedDetail.reqRaw : selectedDetail.respRaw
    copyText(b64Decode(raw))
  }

  async function load() {
    setLoading(true)
    try {
      const data = await api.listRequests({
        offset: filter.offset,
        limit: filter.limit,
        ...(filter.host && { host: filter.host }),
        ...(filter.method && { method: filter.method }),
        ...(filter.search && { search: filter.search }),
        ...(filter.status && { status: filter.status }),
        ...(filter.exclude && filter.extMode && { exclude: filter.exclude }),
        ...(filter.exclude && filter.extMode && { extMode: filter.extMode }),
        ...(filter.content && filter.contentMode && { content: filter.content }),
        ...(filter.content && filter.contentMode && { contentMode: filter.contentMode }),
        ...(filter.content && filter.contentMode && filter.contentRegex && { contentRegex: 'true' }),
        ...(filter.contentTypes.length > 0 && { contentType: filter.contentTypes.join(',') }),
        ...(filter.scopeOnly && { scope_only: 'true' }),
      })
      setItems(data.items as RequestSummary[], data.total)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [filter, reloadCounter]) // eslint-disable-line

  async function selectRequest(item: RequestSummary) {
    const detail = await api.getRequest(item.id)
    setSelectedDetail(detail as RequestDetail)
  }

  function clearAll() {
    setConfirmClearAll(true)
  }

  return (
    <div className="flex flex-col flex-1 min-h-0" ref={vSplit.containerRef}>
      {/* Top: request table */}
      <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: vSplit.fraction }}>
        {/* Filter bar */}
        <div className="border-b border-border bg-surface-card shrink-0">
          {/* Row 0: Section label */}
          <div className="px-2 pt-1.5 pb-0.5">
            <span className="text-xs text-content-muted font-semibold">Filters</span>
          </div>
          {/* Row 1: Primary filters */}
          <div className="flex flex-wrap items-center gap-2 lg:gap-3 px-2 py-1.5">
            <label className="flex items-center gap-1.5">
              <span className="text-xs text-content-muted">Host</span>
              <Tooltip content="Filter by hostname (substring match)">
                <input
                  className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-24 lg:w-32"
                  value={filter.host}
                  onChange={(e) => setFilter({ host: e.target.value })}
                />
              </Tooltip>
            </label>
            <label className="flex items-center gap-1.5">
              <span className="text-xs text-content-muted">Method</span>
              <Tooltip content="Filter by HTTP method (e.g. GET, POST)">
                <input
                  className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-20 lg:w-24"
                  value={filter.method}
                  onChange={(e) => setFilter({ method: e.target.value })}
                />
              </Tooltip>
            </label>
            <label className="flex items-center gap-1.5">
              <span className="text-xs text-content-muted">Status</span>
              <Tooltip content="Filter by response status code (e.g. 200, 404)">
                <input
                  className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-20"
                  value={filter.status}
                  onChange={(e) => setFilter({ status: e.target.value })}
                />
              </Tooltip>
            </label>
            <label className="flex items-center gap-1.5 flex-1 min-w-0">
              <span className="text-xs text-content-muted">URL</span>
              <Tooltip content="Search within request URLs">
                <input
                  className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border flex-1 min-w-24"
                  value={filter.search}
                  onChange={(e) => setFilter({ search: e.target.value })}
                />
              </Tooltip>
            </label>
          </div>
          {/* Row 2: Response filters */}
          <div className="flex flex-wrap items-center gap-2 lg:gap-3 px-2 py-1.5 border-t border-border-subtle">
            <Tooltip content="Show only responses matching selected content types"><span className="text-xs text-content-muted shrink-0">Response Type</span></Tooltip>
            <div className="flex flex-wrap items-center gap-2">
              {CONTENT_TYPE_OPTIONS.map((opt) => (
                <label key={opt.key} className="flex items-center gap-1 cursor-pointer">
                  <input
                    type="checkbox"
                    className="accent-accent"
                    checked={filter.contentTypes.includes(opt.key)}
                    onChange={(e) => {
                      const next = e.target.checked
                        ? [...filter.contentTypes, opt.key]
                        : filter.contentTypes.filter((k) => k !== opt.key)
                      setFilter({ contentTypes: next })
                    }}
                  />
                  <span className="text-xs text-content-secondary">{opt.label}</span>
                </label>
              ))}
            </div>
            <div className="w-px h-5 bg-border mx-1 shrink-0" />
            <Tooltip content="Filter requests by file extension"><span className="text-xs text-content-muted shrink-0">Extensions</span></Tooltip>
            <Tooltip content="Hide requests matching these extensions">
              <label className="flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={filter.extMode === 'exclude'}
                  onChange={(e) => {
                    const next = e.target.checked ? 'exclude' : ''
                    setFilter({ extMode: next })
                    localStorage.setItem('joro-history-extMode', next)
                  }}
                />
                <span className="text-xs text-content-secondary">Exclude</span>
              </label>
            </Tooltip>
            <Tooltip content="Show only requests matching these extensions">
              <label className="flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={filter.extMode === 'include'}
                  onChange={(e) => {
                    const next = e.target.checked ? 'include' : ''
                    setFilter({ extMode: next })
                    localStorage.setItem('joro-history-extMode', next)
                  }}
                />
                <span className="text-xs text-content-secondary">Include</span>
              </label>
            </Tooltip>
            <Tooltip content="Comma-separated extensions (e.g. .css,.png,.jpg)">
              <input
                className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-40 lg:w-56"
                placeholder=".css,.png,.jpg,.jpeg,.gif,.svg,.ico"
                value={filter.exclude}
                onChange={(e) => {
                  const v = e.target.value
                  setFilter({ exclude: v })
                  localStorage.setItem('joro-history-exclude', v)
                }}
              />
            </Tooltip>
            <div className="w-px h-5 bg-border mx-1 shrink-0" />
            <Tooltip content="Show only requests matching active scope rules">
              <label className="flex items-center gap-1 cursor-pointer shrink-0">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={filter.scopeOnly}
                  onChange={(e) => setFilter({ scopeOnly: e.target.checked })}
                />
                <span className="text-xs text-content-secondary">In Scope</span>
              </label>
            </Tooltip>
          </div>
          {/* Row 3: Content search (raw request + response bytes) */}
          <div className="flex flex-wrap items-center gap-2 lg:gap-3 px-2 py-1.5 border-t border-border-subtle">
            <Tooltip content="Match a string or regex against the raw request and response bytes"><span className="text-xs text-content-muted shrink-0">Content</span></Tooltip>
            <Tooltip content="Hide requests whose request/response contains this">
              <label className="flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={filter.contentMode === 'exclude'}
                  onChange={(e) => {
                    const next = e.target.checked ? 'exclude' : ''
                    setFilter({ contentMode: next })
                    localStorage.setItem('joro-history-contentMode', next)
                  }}
                />
                <span className="text-xs text-content-secondary">Exclude</span>
              </label>
            </Tooltip>
            <Tooltip content="Show only requests whose request/response contains this">
              <label className="flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={filter.contentMode === 'include'}
                  onChange={(e) => {
                    const next = e.target.checked ? 'include' : ''
                    setFilter({ contentMode: next })
                    localStorage.setItem('joro-history-contentMode', next)
                  }}
                />
                <span className="text-xs text-content-secondary">Include</span>
              </label>
            </Tooltip>
            <Tooltip content="Treat the search term as a regular expression">
              <label className="flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={filter.contentRegex}
                  onChange={(e) => {
                    setFilter({ contentRegex: e.target.checked })
                    localStorage.setItem('joro-history-contentRegex', String(e.target.checked))
                  }}
                />
                <span className="text-xs text-content-secondary">Regex</span>
              </label>
            </Tooltip>
            <Tooltip content="Search string (case-insensitive) or regex; matched against raw request + response">
              <input
                className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border flex-1 min-w-24"
                placeholder={filter.contentRegex ? 'e.g. (password|token)=\\w+' : 'e.g. Set-Cookie, admin, error'}
                value={filter.content}
                onChange={(e) => {
                  setFilter({ content: e.target.value })
                  localStorage.setItem('joro-history-content', e.target.value)
                }}
              />
            </Tooltip>
          </div>
        </div>

        {/* Info bar */}
        <div className="flex items-center gap-3 text-content-muted text-xs px-2 py-1 border-b border-border bg-surface-card shrink-0">
          <span>Showing {items.length} of {total}</span>
          <label className="flex items-center gap-1.5 ml-auto">
            <span>Limit</span>
            <select
              className="bg-surface-input text-xs px-1.5 py-0.5 rounded-sm border border-border text-content-primary"
              value={filter.limit}
              onChange={(e) => setFilter({ limit: Number(e.target.value) })}
            >
              <option value={0}>All</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
              <option value={500}>500</option>
              <option value={1000}>1000</option>
            </select>
          </label>
          <Tooltip content="Delete all captured requests">
            <button
              onClick={clearAll}
              className="text-xs px-3 py-1 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold shrink-0"
            >
              Clear
            </button>
          </Tooltip>
        </div>

        {/* Table */}
        <div className="flex-1 overflow-auto min-h-0" ref={tableRef}>
          {loading && <div className="text-content-muted text-sm p-4">Loading...</div>}
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-surface-card text-content-muted uppercase">
              <tr>
                <th className="px-2 py-1 text-right w-12 cursor-pointer select-none hover:text-content-primary" onClick={() => toggleSort('seq')}>#{sortIndicator('seq')}</th>
                <th className="px-2 py-1 text-left w-16 cursor-pointer select-none hover:text-content-primary" onClick={() => toggleSort('method')}>Method{sortIndicator('method')}</th>
                <th className="px-2 py-1 text-left w-16 cursor-pointer select-none hover:text-content-primary" onClick={() => toggleSort('statusCode')}>Status{sortIndicator('statusCode')}</th>
                <th className="px-2 py-1 text-left w-32 cursor-pointer select-none hover:text-content-primary" onClick={() => toggleSort('contentType')}>Type{sortIndicator('contentType')}</th>
                <th className="px-2 py-1 text-left cursor-pointer select-none hover:text-content-primary" onClick={() => toggleSort('url')}>URL{sortIndicator('url')}</th>
                <th className="px-2 py-1 text-left w-20 cursor-pointer select-none hover:text-content-primary" onClick={() => toggleSort('timestamp')}>Time{sortIndicator('timestamp')}</th>
                <th className="px-2 py-1 text-right w-16 cursor-pointer select-none hover:text-content-primary" onClick={() => toggleSort('responseSize')}>Size{sortIndicator('responseSize')}</th>
                <th className="px-2 py-1 text-right w-16">ms</th>
              </tr>
            </thead>
            <tbody>
              {sortedItems.map((item) => (
                <tr
                  key={item.id}
                  ref={selectedDetail?.id === item.id ? selectedRowRef : undefined}
                  className={`border-b border-border-subtle cursor-pointer hover:bg-surface-hover ${
                    selectedDetail?.id === item.id && !highlights[item.id] ? 'bg-surface-hover' : ''
                  }`}
                  style={highlights[item.id] ? { backgroundColor: HIGHLIGHT_BG_MAP[highlights[item.id]] } : undefined}
                  onClick={() => selectRequest(item)}
                  onContextMenu={(e) => {
                    e.preventDefault()
                    setDetailMenu(null)
                    setRowMenu({ x: e.clientX, y: e.clientY, itemId: item.id })
                  }}
                >
                  <td className="px-2 py-1 text-right text-content-muted">{item.seq}</td>
                  <td className="px-2 py-1">{methodBadge(item.method)}</td>
                  <td className="px-2 py-1">{statusBadge(item.statusCode)}</td>
                  <td className="px-2 py-1 truncate max-w-[8rem] text-content-muted">{shortenContentType(item.contentType)}</td>
                  <td className="px-2 py-1 truncate max-w-xs text-content-secondary">{protocolBadge(item.protocol)}{item.url}</td>
                  <td className="px-2 py-1 text-content-muted">{item.timestamp ? new Date(item.timestamp).toISOString().slice(11, 19) + ' UTC' : ''}</td>
                  <td className="px-2 py-1 text-right text-content-muted">{formatSize(item.responseSize)}</td>
                  <td className="px-2 py-1 text-right text-content-muted">{item.durationMs}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Vertical drag handle */}
      <div className="drag-handle-v" onMouseDown={vSplit.onMouseDown} />

      {/* Bottom: detail panels side by side */}
      <div
        className="flex min-h-0 overflow-hidden"
        ref={hSplit.containerRef}
        style={{ flex: 1 - vSplit.fraction }}
        onContextMenu={(e) => {
          if (!selectedDetail) return
          e.preventDefault()
          setRowMenu(null)
          setDetailMenu({ x: e.clientX, y: e.clientY })
        }}
      >
        {selectedDetail ? (
          <>
            {/* Request panel */}
            <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: hSplit.fraction }}>
              <div className="flex items-center gap-1 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
                <span className="text-xs font-semibold text-content-primary">Request</span>
                <div className="flex items-center gap-1 ml-auto">
                  <Tooltip content="Line wrapping">
                    <button
                      onClick={() => setWrapReq(w => !w)}
                      className={`w-6 h-5 flex items-center justify-center text-[10px] rounded-sm font-semibold leading-none ${
                        wrapReq ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                      }`}
                    >
                      ↩
                    </button>
                  </Tooltip>
                </div>
              </div>
              <div className="flex-1 relative min-h-0">
                <div className="absolute inset-0 overflow-hidden">
                  <CodeMirror
                    value={b64Decode(selectedDetail.reqRaw)}
                    theme={oneDark}
                    readOnly={true}
                    height="100%"
                    extensions={wrapReq ? [EditorView.lineWrapping] : []}
                    basicSetup={{ lineNumbers: true, foldGutter: false }}
                  />
                </div>
              </div>
            </div>

            {/* Horizontal drag handle */}
            <div className="drag-handle-h" onMouseDown={hSplit.onMouseDown} />

            {/* Response panel */}
            <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: 1 - hSplit.fraction }}>
              <div className="flex items-center gap-1 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
                <span className="text-xs font-semibold text-content-primary">Response</span>
                <div className="flex items-center gap-0.5 ml-2">
                  <button
                    onClick={() => setRespTab('raw')}
                    className={`px-2 py-0.5 rounded-sm text-[10px] font-semibold transition-colors ${
                      respTab === 'raw'
                        ? 'bg-accent text-content-primary'
                        : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
                    }`}
                  >
                    Raw
                  </button>
                  <button
                    onClick={() => setRespTab('render')}
                    className={`px-2 py-0.5 rounded-sm text-[10px] font-semibold transition-colors ${
                      respTab === 'render'
                        ? 'bg-accent text-content-primary'
                        : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
                    }`}
                  >
                    Render
                  </button>
                </div>
                <div className="flex items-center gap-1 ml-auto">
                  {respTab === 'raw' ? (
                    <Tooltip content="Line wrapping">
                      <button
                        onClick={() => setWrapResp(w => !w)}
                        className={`w-6 h-5 flex items-center justify-center text-[10px] rounded-sm font-semibold leading-none ${
                          wrapResp ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                        }`}
                      >
                        ↩
                      </button>
                    </Tooltip>
                  ) : (
                    <Tooltip content="Pretty-print JSON">
                      <button
                        onClick={() => setPrettyJson(!prettyJson)}
                        className={`w-6 h-5 flex items-center justify-center text-[10px] rounded-sm font-semibold leading-none ${
                          prettyJson ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                        }`}
                      >
                        {'{ }'}
                      </button>
                    </Tooltip>
                  )}
                </div>
              </div>
              <div className="flex-1 relative min-h-0">
                {respTab === 'raw' ? (
                  <div className="absolute inset-0 overflow-hidden">
                    <CodeMirror
                      value={b64Decode(selectedDetail.respRaw)}
                      theme={oneDark}
                      readOnly={true}
                      height="100%"
                      extensions={wrapResp ? [EditorView.lineWrapping] : []}
                      basicSetup={{ lineNumbers: true, foldGutter: false }}
                    />
                  </div>
                ) : selectedDetail.respRaw ? (
                  <ResponseRender raw={b64Decode(selectedDetail.respRaw)} prettyJson={prettyJson} />
                ) : null}
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-content-muted text-sm">
            Select a request to view details
          </div>
        )}
      </div>

      {/* Row context menu — highlight colors */}
      {rowMenu && (
        <ContextMenu
          x={rowMenu.x}
          y={rowMenu.y}
          onClose={() => setRowMenu(null)}
          items={[
            {
              label: 'Highlight',
              children: HIGHLIGHT_COLORS.map((c) => ({
                label: c.label,
                checked: highlights[rowMenu.itemId] === c.key,
                onClick: () => setHighlight(rowMenu.itemId, c.key),
              })),
            },
            ...(highlights[rowMenu.itemId]
              ? [{ label: 'Clear Highlight', onClick: () => removeHighlight(rowMenu.itemId) }]
              : []),
            { label: 'Stage for Dead Drop', onClick: () => stageForDeadDrop(rowMenu.itemId) },
          ]}
        />
      )}

      {/* Detail panel context menu — actions */}
      {detailMenu && selectedDetail && (
        <ContextMenu
          x={detailMenu.x}
          y={detailMenu.y}
          onClose={() => setDetailMenu(null)}
          items={[
            ...getSelectionMenuItems(navigate),
            { label: 'Manipulate', onClick: sendToManipulate },
            { label: 'Fuzz', onClick: sendToFuzz },
            { label: 'Stage for Dead Drop', onClick: () => stageDetailForDeadDrop(selectedDetail) },
            ...(teamMode ? [{ label: '🚩 Flag to team', onClick: flagToTeam }] : []),
            { label: 'Copy URL', onClick: copyUrl },
            { label: 'Copy as curl', onClick: copyCurl },
            { label: 'Copy Raw Request', onClick: () => copyRaw('request') },
            { label: 'Copy Raw Response', onClick: () => copyRaw('response') },
          ]}
        />
      )}
      {confirmClearAll && (
        <ConfirmModal
          title="Clear request history"
          message="Are you sure you want to delete all request history? This cannot be undone."
          confirmLabel="Clear"
          onConfirm={async () => {
            setConfirmClearAll(false)
            await api.clearRequests()
            clear()
          }}
          onClose={() => setConfirmClearAll(false)}
        />
      )}
    </div>
  )
}
