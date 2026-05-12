import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { oneDark } from '@codemirror/theme-one-dark'
import { api } from '../lib/api'
import { useResizable } from '../lib/useResizable'
import {
  useManipulateWSStore,
  type ManipulateWSTab,
  type WSFrameEntry,
  type WSOpcode,
} from '../stores/manipulateWSStore'
import { Tooltip } from '../components/Tooltip'
import { copyText } from '../lib/clipboard'

function b64Encode(s: string) { try { return btoa(unescape(encodeURIComponent(s))) } catch { return btoa(s) } }
function b64Decode(s: string) {
  try { return decodeURIComponent(escape(atob(s))) } catch { return atob(s) }
}
function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
function bytesToB64(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
  return btoa(s)
}
function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join(' ')
}
function hexToBytes(hex: string): Uint8Array | null {
  const clean = hex.replace(/\s+|0x/g, '')
  if (clean.length % 2 !== 0) return null
  if (!/^[0-9a-fA-F]*$/.test(clean)) return null
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16)
  return out
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(ts: string): string {
  try {
    const d = new Date(ts)
    return d.toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch {
    return ts
  }
}

function framePreview(f: WSFrameEntry): string {
  try {
    const bytes = b64ToBytes(f.payload)
    if (f.isText) {
      const s = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
      return s.length > 120 ? s.slice(0, 120) + '…' : s
    }
    return `[${f.opcode} ${bytes.length}B]`
  } catch {
    return `[${f.opcode} ${f.size}B]`
  }
}

// Infer scheme + host:port from a URL typed into the toolbar input. Any parse
// failure falls back to the previous tab values so the user sees their input
// preserved in the editor.
function parseWSURL(url: string, prev: { scheme: 'ws' | 'wss'; host: string; path: string }) {
  try {
    const u = new URL(url)
    const scheme: 'ws' | 'wss' = u.protocol === 'wss:' ? 'wss' : 'ws'
    const port = u.port || (scheme === 'wss' ? '443' : '80')
    const host = `${u.hostname}:${port}`
    const path = u.pathname + u.search
    return { scheme, host, path: path || '/' }
  } catch {
    return prev
  }
}

// Update the request-target (path) and Host header in a raw upgrade request
// so they match what the user typed into the URL bar.
function rewriteUpgradeTarget(raw: string, path: string, host: string): string {
  const lines = raw.split(/\r?\n/)
  if (lines.length === 0) return raw
  const first = lines[0].split(' ')
  if (first.length >= 2) {
    first[1] = path
    lines[0] = first.join(' ')
  }
  let foundHost = false
  for (let i = 1; i < lines.length; i++) {
    if (/^host:/i.test(lines[i])) {
      lines[i] = `Host: ${host.replace(/:(80|443)$/, '')}`
      foundHost = true
      break
    }
    if (lines[i] === '') break
  }
  if (!foundHost) {
    lines.splice(1, 0, `Host: ${host.replace(/:(80|443)$/, '')}`)
  }
  return lines.join('\r\n')
}

export default function ManipulateWS() {
  const location = useLocation()
  const navigate = useNavigate()
  const {
    tabs,
    activeTabId,
    addTab,
    removeTab,
    renameTab,
    updateTab,
    setActiveTab,
    clearFrames,
  } = useManipulateWSStore()
  const tab = tabs.find((t) => t.id === activeTabId) ?? tabs[0]

  const [editingTabId, setEditingTabId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')
  const renameInputRef = useRef<HTMLInputElement>(null)

  const hSplit = useResizable('horizontal', 0.45)

  // Location-state hydration: "Send to Manipulate" from History.
  useEffect(() => {
    const state = location.state as {
      subTab?: string
      url?: string
      scheme?: string
      host?: string
      rawUpgrade?: string
      sendPayload?: string
      sendOpcode?: WSOpcode
    } | null
    if (state?.subTab !== 'ws') return
    addTab({
      url: state.url || 'wss://example.com/',
      scheme: state.scheme === 'ws' ? 'ws' : 'wss',
      host: state.host || 'example.com',
      rawUpgrade: state.rawUpgrade || undefined,
      sendPayload: state.sendPayload || '',
      sendOpcode: state.sendOpcode || 'text',
    })
    navigate('/manipulate', { replace: true, state: { subTab: 'ws' } })
  }, [location.state]) // eslint-disable-line

  useEffect(() => {
    if (editingTabId && renameInputRef.current) {
      renameInputRef.current.focus()
      renameInputRef.current.select()
    }
  }, [editingTabId])

  function commitRename() {
    if (editingTabId && editName.trim()) renameTab(editingTabId, editName.trim())
    setEditingTabId(null)
  }

  async function connect() {
    updateTab(tab.id, { state: 'connecting', error: '', upgradeResponse: '' })
    try {
      const parsed = parseWSURL(tab.url, { scheme: tab.scheme, host: tab.host, path: '/' })
      const patchedUpgrade = rewriteUpgradeTarget(tab.rawUpgrade, parsed.path, parsed.host)
      const res = await api.manipulateWSConnect(b64Encode(patchedUpgrade), parsed.scheme, parsed.host)
      const rawResp = res.rawResp ? b64Decode(res.rawResp) : ''
      if (!res.sessionId) {
        updateTab(tab.id, {
          scheme: parsed.scheme,
          host: parsed.host,
          rawUpgrade: patchedUpgrade,
          state: 'error',
          upgradeResponse: rawResp,
          error: res.error || 'connect failed',
        })
        return
      }
      updateTab(tab.id, {
        scheme: parsed.scheme,
        host: parsed.host,
        rawUpgrade: patchedUpgrade,
        sessionId: res.sessionId,
        state: 'connected',
        upgradeResponse: rawResp,
        error: '',
      })
    } catch (e) {
      updateTab(tab.id, { state: 'error', error: String(e) })
    }
  }

  async function disconnect() {
    if (!tab.sessionId) return
    updateTab(tab.id, { state: 'closing' })
    try {
      await api.manipulateWSDisconnect(tab.sessionId)
    } catch (e) {
      // Still flip the tab back — the backend may already be gone.
      updateTab(tab.id, { state: 'disconnected', sessionId: null, error: String(e) })
      return
    }
    updateTab(tab.id, { state: 'disconnected', sessionId: null })
  }

  async function sendFrame() {
    if (!tab.sessionId || tab.state !== 'connected') return
    let bytes: Uint8Array | null = null
    if (tab.sendOpcode === 'binary') {
      bytes = hexToBytes(tab.sendPayload)
      if (!bytes) {
        updateTab(tab.id, { error: 'invalid hex payload' })
        return
      }
    } else {
      bytes = new TextEncoder().encode(tab.sendPayload)
    }
    try {
      await api.manipulateWSSend(tab.sessionId, tab.sendOpcode, bytesToB64(bytes))
      updateTab(tab.id, { error: '' })
      // Optimistically append the sent frame locally — the backend will also
      // broadcast a manipulate.ws.frame event so we may see a second copy,
      // but the broadcast is the source of truth. To avoid the duplicate,
      // rely on the broadcast only. (No local append here.)
    } catch (e) {
      updateTab(tab.id, { error: String(e) })
    }
  }

  const selectedFrame = useMemo(
    () => tab.frames.find((f) => f.id === tab.selectedFrameId) ?? null,
    [tab.frames, tab.selectedFrameId]
  )
  const selectedFramePayload = useMemo(() => {
    if (!selectedFrame) return ''
    try {
      const bytes = b64ToBytes(selectedFrame.payload)
      return selectedFrame.isText
        ? new TextDecoder('utf-8', { fatal: false }).decode(bytes)
        : bytesToHex(bytes)
    } catch {
      return ''
    }
  }, [selectedFrame])

  const upgradeEditable = tab.state === 'disconnected' || tab.state === 'error'

  const wrapExt = useMemo(() => (tab.wrapUpgrade ? [EditorView.lineWrapping] : []), [tab.wrapUpgrade])
  const wrapRespExt = useMemo(() => (tab.wrapResponse ? [EditorView.lineWrapping] : []), [tab.wrapResponse])
  const wrapPayloadExt = useMemo(() => (tab.wrapPayload ? [EditorView.lineWrapping] : []), [tab.wrapPayload])

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {/* Tab bar */}
      <div className="flex items-center border-b border-border bg-surface-card shrink-0 overflow-x-auto">
        {tabs.map((t) => (
          <div
            key={t.id}
            className={`flex items-center gap-1 px-3 py-1.5 text-xs cursor-pointer border-b-2 shrink-0 ${
              t.id === activeTabId
                ? 'text-accent border-accent'
                : 'text-content-muted hover:text-content-secondary border-transparent'
            }`}
            onClick={() => setActiveTab(t.id)}
            onDoubleClick={() => { setEditingTabId(t.id); setEditName(t.name) }}
          >
            {editingTabId === t.id ? (
              <input
                ref={renameInputRef}
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                onBlur={commitRename}
                onKeyDown={(e) => { if (e.key === 'Enter') commitRename(); if (e.key === 'Escape') setEditingTabId(null) }}
                onClick={(e) => e.stopPropagation()}
                className="bg-surface-input text-xs px-1 py-0 rounded-sm border border-border w-16 outline-none"
              />
            ) : (
              <span>{t.name}</span>
            )}
            {tabs.length > 1 && (
              <button
                onClick={(e) => { e.stopPropagation(); removeTab(t.id) }}
                className="text-content-muted hover:text-semantic-error ml-1 leading-none"
              >
                &times;
              </button>
            )}
          </div>
        ))}
        <button
          onClick={() => addTab()}
          className="px-2 py-1.5 text-xs text-content-muted hover:text-content-secondary shrink-0"
        >
          +
        </button>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
        <input
          value={tab.url}
          onChange={(e) => updateTab(tab.id, { url: e.target.value })}
          disabled={tab.state === 'connected' || tab.state === 'connecting'}
          className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border flex-1 font-mono disabled:opacity-60"
          placeholder="wss://host:port/path"
        />
        <StateBadge state={tab.state} />
        {tab.state === 'connected' || tab.state === 'closing' ? (
          <button
            onClick={disconnect}
            disabled={tab.state === 'closing'}
            className="text-xs px-4 py-1.5 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold disabled:opacity-50"
          >
            Disconnect
          </button>
        ) : (
          <button
            onClick={connect}
            disabled={tab.state === 'connecting'}
            className="text-xs px-4 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-50"
          >
            {tab.state === 'connecting' ? 'Connecting…' : 'Connect'}
          </button>
        )}
        {tab.error && <Tooltip content={tab.error}><span className="text-xs text-semantic-error truncate max-w-sm">{tab.error}</span></Tooltip>}
      </div>

      {/* Horizontal split: LEFT upgrade, RIGHT transcript+send */}
      <div className="flex flex-1 overflow-hidden min-h-0" ref={hSplit.containerRef}>
        {/* LEFT: upgrade request (top) + upgrade response (bottom) */}
        <div className="flex flex-col overflow-hidden min-h-0" style={{ flex: hSplit.fraction }}>
          <div className="flex items-center gap-1 px-2 py-1 bg-surface-card border-b border-border shrink-0">
            <span className="text-xs text-content-muted">Upgrade Request</span>
            <div className="flex items-center gap-1 ml-auto">
              <SquareToggle label="↩" title="Line wrapping" active={tab.wrapUpgrade} onClick={() => updateTab(tab.id, { wrapUpgrade: !tab.wrapUpgrade })} />
            </div>
          </div>
          <div className="flex-1 relative min-h-0" style={{ flex: 1 }}>
            <div className="absolute inset-0 overflow-hidden">
              <CodeMirror
                value={tab.rawUpgrade}
                theme={oneDark}
                height="100%"
                readOnly={!upgradeEditable}
                onChange={(v) => updateTab(tab.id, { rawUpgrade: v })}
                extensions={wrapExt}
                basicSetup={{ lineNumbers: true, foldGutter: false }}
              />
            </div>
          </div>
          <div className="flex items-center gap-1 px-2 py-1 bg-surface-card border-y border-border shrink-0">
            <span className="text-xs text-content-muted">Upgrade Response</span>
            <div className="flex items-center gap-1 ml-auto">
              <SquareToggle label="↩" title="Line wrapping" active={tab.wrapResponse} onClick={() => updateTab(tab.id, { wrapResponse: !tab.wrapResponse })} />
            </div>
          </div>
          <div className="relative min-h-0" style={{ flex: 1 }}>
            <div className="absolute inset-0 overflow-hidden">
              <CodeMirror
                value={tab.upgradeResponse}
                theme={oneDark}
                height="100%"
                readOnly={true}
                extensions={wrapRespExt}
                basicSetup={{ lineNumbers: true, foldGutter: false }}
              />
            </div>
          </div>
        </div>

        <div className="drag-handle-h" onMouseDown={hSplit.onMouseDown} />

        {/* RIGHT: transcript + detail + send */}
        <div className="flex flex-col overflow-hidden min-h-0" style={{ flex: 1 - hSplit.fraction }}>
          <div className="flex items-center gap-1 px-2 py-1 bg-surface-card border-b border-border shrink-0">
            <span className="text-xs text-content-muted">Transcript</span>
            <span className="text-[10px] text-content-muted ml-2">{tab.frames.length} frame{tab.frames.length === 1 ? '' : 's'}</span>
            <button
              onClick={() => clearFrames(tab.id)}
              className="ml-auto text-[10px] px-2 py-0.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
            >
              Clear
            </button>
          </div>
          <div className="flex-1 overflow-auto min-h-0 font-mono text-[11px]">
            {tab.frames.length === 0 ? (
              <div className="p-3 text-content-muted text-xs italic">No frames yet.</div>
            ) : (
              <table className="w-full border-collapse">
                <tbody>
                  {tab.frames.map((f) => (
                    <tr
                      key={f.id}
                      onClick={() => updateTab(tab.id, { selectedFrameId: f.id })}
                      className={`cursor-pointer border-b border-border-subtle hover:bg-surface-hover ${
                        tab.selectedFrameId === f.id ? 'bg-surface-hover' : ''
                      }`}
                    >
                      <td className="px-2 py-0.5 w-6 text-center">
                        {f.direction === 'sent'
                          ? <span className="text-accent-secondary">→</span>
                          : <span className="text-accent-tertiary">←</span>}
                      </td>
                      <td className="px-2 py-0.5 w-20 text-content-muted">{formatTime(f.ts)}</td>
                      <td className="px-2 py-0.5 w-14 text-content-secondary">{f.opcode}</td>
                      <td className="px-2 py-0.5 w-16 text-content-muted">{formatSize(f.size)}</td>
                      <td className="px-2 py-0.5 text-content-primary truncate max-w-0">{framePreview(f)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          {selectedFrame && (
            <div className="flex flex-col border-t border-border" style={{ flex: '0 0 auto', maxHeight: '30%' }}>
              <div className="flex items-center gap-2 px-2 py-1 bg-surface-card shrink-0">
                <span className="text-xs text-content-muted">Frame detail</span>
                <span className="text-[10px] text-content-muted">{selectedFrame.direction}</span>
                <span className="text-[10px] text-content-muted">{selectedFrame.opcode}</span>
                <span className="text-[10px] text-content-muted">{formatSize(selectedFrame.size)}</span>
                <button
                  onClick={() => copyText(selectedFramePayload)}
                  className="ml-auto text-[10px] px-2 py-0.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
                >
                  Copy
                </button>
              </div>
              <div className="relative overflow-hidden" style={{ minHeight: 80 }}>
                <CodeMirror
                  value={selectedFramePayload}
                  theme={oneDark}
                  readOnly={true}
                  height="120px"
                  extensions={[EditorView.lineWrapping]}
                  basicSetup={{ lineNumbers: false, foldGutter: false }}
                />
              </div>
            </div>
          )}
          <div className="flex flex-col border-t border-border shrink-0">
            <div className="flex items-center gap-2 px-2 py-1 bg-surface-card shrink-0">
              <span className="text-xs text-content-muted">Send</span>
              <select
                value={tab.sendOpcode}
                onChange={(e) => updateTab(tab.id, { sendOpcode: e.target.value as WSOpcode })}
                className="bg-surface-input text-xs px-2 py-1 rounded-sm border border-border"
              >
                <option value="text">Text</option>
                <option value="binary">Binary (hex)</option>
                <option value="ping">Ping</option>
                <option value="pong">Pong</option>
                <option value="close">Close</option>
              </select>
              <div className="ml-auto flex items-center gap-1">
                <SquareToggle label="↩" title="Line wrapping" active={tab.wrapPayload} onClick={() => updateTab(tab.id, { wrapPayload: !tab.wrapPayload })} />
                <button
                  onClick={sendFrame}
                  disabled={tab.state !== 'connected'}
                  className="text-xs px-4 py-1 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black font-semibold disabled:opacity-50"
                >
                  Send
                </button>
              </div>
            </div>
            <div className="relative" style={{ height: 140 }}>
              <div className="absolute inset-0 overflow-hidden">
                <CodeMirror
                  value={tab.sendPayload}
                  theme={oneDark}
                  height="100%"
                  onChange={(v) => updateTab(tab.id, { sendPayload: v })}
                  extensions={wrapPayloadExt}
                  basicSetup={{ lineNumbers: true, foldGutter: false }}
                  placeholder={tab.sendOpcode === 'binary' ? 'de ad be ef' : '{"hello":"world"}'}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function StateBadge({ state }: { state: ManipulateWSTab['state'] }) {
  const map: Record<ManipulateWSTab['state'], { label: string; cls: string }> = {
    disconnected: { label: 'disconnected', cls: 'bg-surface-input text-content-muted' },
    connecting: { label: 'connecting',  cls: 'bg-surface-input text-semantic-warning' },
    connected: { label: 'connected',    cls: 'bg-surface-input text-semantic-success' },
    closing: { label: 'closing',        cls: 'bg-surface-input text-content-muted' },
    error: { label: 'error',            cls: 'bg-surface-input text-semantic-error' },
  }
  const m = map[state]
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-sm font-semibold uppercase tracking-wide ${m.cls}`}>
      {m.label}
    </span>
  )
}

function SquareToggle({ label, title, active, onClick }: { label: string; title: string; active: boolean; onClick: () => void }) {
  return (
    <Tooltip content={title}>
      <button
        onClick={onClick}
        className={`w-6 h-5 flex items-center justify-center text-[10px] rounded-sm font-semibold leading-none ${
          active ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
        }`}
      >
        {label}
      </button>
    </Tooltip>
  )
}

