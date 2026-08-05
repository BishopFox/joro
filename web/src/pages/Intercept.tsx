import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { oneDark } from '@codemirror/theme-one-dark'
import { ArrowDown, ArrowUp } from 'lucide-react'
import { api } from '../lib/api'
import { PendingItem, useInterceptStore } from '../stores/interceptStore'
import { useToastStore } from '../stores/toastStore'
import { useResizable } from '../lib/useResizable'
import ContextMenu from '../components/ContextMenu'
import { getSelectionMenuItems } from '../lib/selectionMenu'
import { copyText } from '../lib/clipboard'
import { rawToCurl } from '../lib/httpTransform'

function b64Decode(s: string) {
  try { return atob(s) } catch { return s }
}
function b64Encode(s: string) {
  try { return btoa(s) } catch { return s }
}

// The queue is server-owned and every pause auto-forwards on a timeout, so the
// UI reconciles on a slow interval rather than trusting the event stream alone:
// a dropped WS frame would otherwise leave a phantom row (or hide a real one)
// until the operator navigated away.
const RECONCILE_MS = 5000

// The raw bytes an operator edits, by phase.
function rawFor(item: PendingItem) {
  return item.kind === 'response' ? (item.respRaw ?? '') : item.reqRaw
}

function TogglePill({ label, on, onClick }: { label: string; on: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={on}
      className={`text-xs px-2 py-0.5 rounded-sm font-semibold ${
        on ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
      }`}
    >
      {label}
    </button>
  )
}

// Ticks so the operator can see the auto-forward timeout approaching, and
// understands afterwards why something forwarded itself.
function PausedAge({ pausedAt, now }: { pausedAt?: string; now: number }) {
  if (!pausedAt) return null
  const secs = Math.max(0, Math.round((now - new Date(pausedAt).getTime()) / 1000))
  if (!Number.isFinite(secs)) return null
  return <span className="text-content-muted tabular-nums">{secs}s</span>
}

export default function Intercept() {
  const {
    enabled, responsesEnabled, items, selected,
    setEnabled, setResponsesEnabled, setItems, setSelected, removeItem,
  } = useInterceptStore()
  const navigate = useNavigate()
  const addToast = useToastStore((s) => s.addToast)
  const [editedRaw, setEditedRaw] = useState('')
  const [wrap, setWrap] = useState(false)
  const [now, setNow] = useState(() => Date.now())

  const hSplit = useResizable('horizontal', 0.2)

  const isResponse = selected?.kind === 'response'
  const anyEnabled = enabled || responsesEnabled

  const refresh = useCallback(async () => {
    const data = await api.getIntercept()
    setEnabled(data.enabled)
    setResponsesEnabled(data.responsesEnabled)
    setItems(data.items)
  }, [setEnabled, setResponsesEnabled, setItems])

  useEffect(() => {
    refresh().catch(() => { /* transient; the reconcile below retries */ })
    window.addEventListener('joro:ws-reconnected', refresh)
    return () => window.removeEventListener('joro:ws-reconnected', refresh)
  }, [refresh])

  // Reconcile only while a phase is on — an idle tab costs no requests.
  useEffect(() => {
    if (!anyEnabled) return
    const t = setInterval(() => {
      refresh().catch(() => { /* ignore */ })
    }, RECONCILE_MS)
    return () => clearInterval(t)
  }, [anyEnabled, refresh])

  // One timer for the whole list, not one per row.
  useEffect(() => {
    if (items.length === 0) return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [items.length])

  useEffect(() => {
    if (selected) setEditedRaw(b64Decode(rawFor(selected)))
  }, [selected])

  async function toggle(phase: 'requests' | 'responses') {
    const isReq = phase === 'requests'
    const next = !(isReq ? enabled : responsesEnabled)
    const apply = isReq ? setEnabled : setResponsesEnabled
    apply(next)
    try {
      await (isReq ? api.setInterceptEnabled(next) : api.setInterceptResponses(next))
    } catch (err) {
      apply(!next)
      addToast(err instanceof Error ? err.message : 'Failed to toggle intercept', 'error')
    }
  }

  async function forward() {
    if (!selected) return
    const patch = isResponse
      ? { respRaw: b64Encode(editedRaw) }
      : { reqRaw: b64Encode(editedRaw) }
    try {
      await api.forwardIntercept(selected.id, patch)
    } catch {
      // A 404 means the pause already timed out or was released; the row is
      // stale either way, so clear it rather than nagging.
    }
    removeItem(selected.id)
  }

  async function drop() {
    if (!selected) return
    try {
      await api.dropRequest(selected.id)
    } catch { /* already resolved — see forward() */ }
    removeItem(selected.id)
  }

  async function releaseAll() {
    try {
      const { released } = await api.releaseIntercepts()
      addToast(`Released ${released} paused item${released === 1 ? '' : 's'}`, 'info')
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to release', 'error')
    }
  }

  function targetFor(item: PendingItem) {
    let scheme = 'https'
    let host = item.host
    try {
      const u = new URL(item.url)
      scheme = u.protocol.replace(':', '')
      host = u.host
    } catch { /* use defaults */ }
    return { scheme, host, rawReq: item.reqRaw }
  }

  function sendToManipulate() {
    if (!selected) return
    navigate('/manipulate', { state: targetFor(selected) })
  }

  function sendToFuzz() {
    if (!selected) return
    navigate('/fuzz', { state: targetFor(selected) })
  }

  // Context menu for CodeMirror editor
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null)
  const ctxMenuCbRef = useRef<(x: number, y: number) => void>(() => {})
  ctxMenuCbRef.current = (x: number, y: number) => setCtxMenu({ x, y })

  const contextMenuExt = useMemo(
    () => EditorView.domEventHandlers({
      contextmenu(event) {
        event.preventDefault()
        ctxMenuCbRef.current(event.clientX, event.clientY)
        return true
      },
    }),
    []
  )

  const handleCloseCtxMenu = useCallback(() => setCtxMenu(null), [])

  function copyUrl() { if (selected) copyText(selected.url) }
  function copyCurl() { if (selected) copyText(rawToCurl(editedRaw, selected.url)) }
  function copyRaw() { copyText(editedRaw) }

  return (
    <div className="flex flex-1 min-h-0" ref={hSplit.containerRef}>
      {/* Left: queue */}
      <div className="flex flex-col shrink-0 overflow-hidden" style={{ flex: hSplit.fraction }}>
        <div className="px-3 py-2 border-b border-border bg-surface-card shrink-0 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wide">Intercept</span>
            {items.length > 0 && (
              <button
                onClick={releaseAll}
                title="Forward every paused request and response unmodified"
                className="text-xs px-2 py-0.5 rounded-sm font-semibold bg-surface-input text-content-secondary hover:bg-surface-hover"
              >
                Release all
              </button>
            )}
          </div>
          <div className="flex items-center gap-2">
            <TogglePill label="Requests" on={enabled} onClick={() => toggle('requests')} />
            <TogglePill label="Responses" on={responsesEnabled} onClick={() => toggle('responses')} />
          </div>
        </div>
        <div className="flex-1 overflow-auto min-h-0">
          {items.length === 0 ? (
            <div className="text-content-muted text-xs p-3">
              {anyEnabled
                ? `Waiting for ${enabled && responsesEnabled ? 'requests and responses' : enabled ? 'requests' : 'responses'}...`
                : 'Intercept is disabled'}
            </div>
          ) : (
            items.map((item) => (
              <button
                key={`${item.kind}:${item.id}`}
                onClick={() => setSelected(item)}
                className={`w-full text-left p-2 border-b border-border-subtle text-xs hover:bg-surface-hover ${
                  selected?.kind === item.kind && selected?.id === item.id ? 'bg-surface-hover' : ''
                }`}
              >
                <div className="flex items-center gap-1.5">
                  {item.kind === 'response' ? (
                    <ArrowDown size={12} className="text-semantic-info shrink-0" />
                  ) : (
                    <ArrowUp size={12} className="text-accent-tertiary shrink-0" />
                  )}
                  <span className="font-bold text-accent">{item.method}</span>
                  {item.kind === 'response' && item.status ? (
                    <span className="text-content-secondary">{item.status}</span>
                  ) : null}
                  <span className="ml-auto"><PausedAge pausedAt={item.pausedAt} now={now} /></span>
                </div>
                <div className="text-content-secondary truncate">{item.host}</div>
                <div className="text-content-muted truncate">{item.url}</div>
              </button>
            ))
          )}
        </div>
      </div>

      {/* Horizontal drag handle */}
      <div className="drag-handle-h" onMouseDown={hSplit.onMouseDown} />

      {/* Right: editor + actions */}
      <div className="flex flex-col overflow-hidden" style={{ flex: 1 - hSplit.fraction }}>
        {selected ? (
          <>
            <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
              <button
                onClick={forward}
                className="text-xs px-3 py-1 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black font-semibold"
              >
                Forward
              </button>
              <button
                onClick={drop}
                title={isResponse
                  ? 'Discard this response — the request was already sent upstream'
                  : 'Discard this request without sending it'}
                className="text-xs px-3 py-1 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold"
              >
                Drop
              </button>
              <button
                onClick={sendToManipulate}
                disabled={isResponse}
                title={isResponse ? 'Manipulate replays a request, not a response' : undefined}
                className="text-xs px-3 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Manipulate
              </button>
              <button
                onClick={() => setWrap(w => !w)}
                className={`text-xs px-2 py-0.5 rounded-sm font-semibold ${
                  wrap ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                }`}
              >
                Wrap
              </button>
              <span className="text-content-muted text-xs self-center ml-2 truncate">
                {isResponse ? 'Response to' : ''} {selected.method} {selected.url}
                {selected.protocol ? ` (${selected.protocol})` : ''}
              </span>
            </div>
            <div className="flex-1 relative min-h-0">
              <div className="absolute inset-0 overflow-hidden">
                <CodeMirror
                  value={editedRaw}
                  theme={oneDark}
                  height="100%"
                  onChange={setEditedRaw}
                  extensions={wrap ? [contextMenuExt, EditorView.lineWrapping] : [contextMenuExt]}
                  basicSetup={{ lineNumbers: true, foldGutter: false }}
                />
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-content-muted text-sm">
            {anyEnabled ? 'Select an intercepted item' : 'Enable intercept to pause traffic'}
          </div>
        )}
      </div>

      {ctxMenu && (
        <ContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          onClose={handleCloseCtxMenu}
          items={[
            ...getSelectionMenuItems(navigate),
            { label: 'Manipulate', onClick: sendToManipulate, disabled: !selected || isResponse },
            { label: 'Fuzz', onClick: sendToFuzz, disabled: !selected || isResponse },
            { label: 'Copy URL', onClick: copyUrl, disabled: !selected },
            { label: 'Copy as curl', onClick: copyCurl, disabled: !selected || isResponse },
            { label: isResponse ? 'Copy Raw Response' : 'Copy Raw Request', onClick: copyRaw, disabled: !selected },
          ]}
        />
      )}
    </div>
  )
}
