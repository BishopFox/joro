import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { oneDark } from '@codemirror/theme-one-dark'
import { ArrowDown, ArrowUp } from 'lucide-react'
import { api, ApiError } from '../lib/api'
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

// How long Forward and Drop stay inert after the pane loads an item on its own.
//
// Resolving an item pulls the next one in under the pointer, and a forward or a drop
// has no undo, so without this a double-click or a held key resolves an item the
// operator never saw. Long enough to break the second click of a double-click, short
// enough to stay under the time it takes to read the row that just appeared.
const SETTLE_MS = 200

// The raw bytes an operator edits, by phase.
function rawFor(item: PendingItem) {
  return item.kind === 'response' ? (item.respRaw ?? '') : item.reqRaw
}

const keyOf = (item: PendingItem) => `${item.kind}:${item.id}`

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
  const [wrap, setWrap] = useState(false)
  const [now, setNow] = useState(() => Date.now())

  const hSplit = useResizable('horizontal', 0.2)

  const isResponse = selected?.kind === 'response'
  const anyEnabled = enabled || responsesEnabled
  const selKey = selected ? keyOf(selected) : ''

  // Edits are held per item rather than mirrored into one buffer by an effect. The
  // pane now changes item on its own, and an effect writes after paint — so for a
  // frame the header would name the item that just arrived while the editor still
  // showed the bytes of the one just resolved. Deriving it during render makes that
  // disagreement unrepresentable, and keys the work an operator has already done to
  // the item it belongs to, so leaving an item and coming back does not discard it.
  const [edits, setEdits] = useState<Record<string, string>>({})
  const editedRaw = selected ? (edits[selKey] ?? b64Decode(rawFor(selected))) : ''
  const onEdit = useCallback(
    (v: string) => setEdits((e) => ({ ...e, [selKey]: v })),
    [selKey]
  )

  // Forget the edits of items the queue has let go of.
  useEffect(() => {
    setEdits((e) => {
      const live = new Set(items.map(keyOf))
      const kept = Object.keys(e).filter((k) => live.has(k))
      if (kept.length === Object.keys(e).length) return e
      return Object.fromEntries(kept.map((k) => [k, e[k]]))
    })
  }, [items])

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

  const [armedFor, setArmedFor] = useState('')
  useEffect(() => {
    if (!selKey) return
    const t = setTimeout(() => setArmedFor(selKey), SETTLE_MS)
    return () => clearTimeout(t)
  }, [selKey])
  const canResolve = !!selected && armedFor === selKey

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

  // Resolving is awaited before the row goes: the endpoint only hands the decision to
  // the goroutine already parked on it, so the wait is a loopback round trip, and it
  // keeps the buttons pointed at this item until they are pointed at the next one.
  async function resolve(kind: 'forward' | 'drop') {
    if (!selected || !canResolve) return
    const id = selected.id
    try {
      if (kind === 'drop') {
        await api.dropRequest(id)
      } else {
        // Re-encoding is skipped on a drop: the bytes are discarded, and a response
        // body can be large.
        const raw = b64Encode(editedRaw)
        await api.forwardIntercept(id, isResponse ? { respRaw: raw } : { reqRaw: raw })
      }
    } catch (err) {
      // A 404 means the pause already timed out or was released; the row is stale
      // either way, so clear it rather than nagging. Anything else has to be said out
      // loud — the pane moves on to the next item regardless, and an operator who is
      // already reading that one has nothing else to tell them this one never went.
      if (!(err instanceof ApiError && err.status === 404)) {
        addToast(err instanceof Error ? err.message : `Failed to ${kind}`, 'error')
      }
    }
    removeItem(id)
  }

  const forward = () => resolve('forward')
  const drop = () => resolve('drop')

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
                key={keyOf(item)}
                onClick={() => setSelected(item)}
                className={`w-full text-left p-2 border-b border-border-subtle text-xs hover:bg-surface-hover ${
                  selKey === keyOf(item) ? 'bg-surface-hover' : ''
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
                disabled={!canResolve}
                className="text-xs px-3 py-1 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Forward
              </button>
              <button
                onClick={drop}
                disabled={!canResolve}
                title={isResponse
                  ? 'Discard this response — the request was already sent upstream'
                  : 'Discard this request without sending it'}
                className="text-xs px-3 py-1 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
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
                {/* Keyed on the item so the cursor and scroll reset with it: without
                    the remount CodeMirror replaces the document in place and leaves the
                    caret at its old offset, now inside a different request. */}
                <CodeMirror
                  key={selKey}
                  value={editedRaw}
                  theme={oneDark}
                  height="100%"
                  onChange={onEdit}
                  extensions={wrap ? [contextMenuExt, EditorView.lineWrapping] : [contextMenuExt]}
                  basicSetup={{ lineNumbers: true, foldGutter: false }}
                />
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-content-muted text-sm">
            {anyEnabled
              ? `Waiting for ${enabled && responsesEnabled ? 'requests and responses' : enabled ? 'requests' : 'responses'}...`
              : 'Enable intercept to pause traffic'}
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
