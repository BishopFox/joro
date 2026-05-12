import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { oneDark } from '@codemirror/theme-one-dark'
import { api } from '../lib/api'
import { PendingRequest, useInterceptStore } from '../stores/interceptStore'
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

export default function Intercept() {
  const { enabled, items, selected, setEnabled, setItems, setSelected, removeItem } = useInterceptStore()
  const navigate = useNavigate()
  const [editedReq, setEditedReq] = useState('')
  const [wrap, setWrap] = useState(false)

  const hSplit = useResizable('horizontal', 0.2)

  useEffect(() => {
    api.getIntercept().then((data) => {
      setEnabled(data.enabled)
      setItems(data.items as PendingRequest[])
    })
  }, []) // eslint-disable-line

  useEffect(() => {
    if (selected) setEditedReq(b64Decode(selected.reqRaw))
  }, [selected])

  async function toggleIntercept() {
    const newVal = !enabled
    await api.setInterceptEnabled(newVal)
    setEnabled(newVal)
  }

  async function forward() {
    if (!selected) return
    await api.forwardRequest(selected.id, b64Encode(editedReq))
    removeItem(selected.id)
  }

  async function drop() {
    if (!selected) return
    await api.dropRequest(selected.id)
    removeItem(selected.id)
  }

  function sendToManipulate() {
    if (!selected) return
    let scheme = 'https'
    let host = selected.host
    try {
      const u = new URL(selected.url)
      scheme = u.protocol.replace(':', '')
      host = u.host
    } catch { /* use defaults */ }
    navigate('/manipulate', { state: { scheme, host, rawReq: selected.reqRaw } })
  }

  function sendToFuzz() {
    if (!selected) return
    let scheme = 'https'
    let host = selected.host
    try {
      const u = new URL(selected.url)
      scheme = u.protocol.replace(':', '')
      host = u.host
    } catch { /* use defaults */ }
    navigate('/fuzz', { state: { scheme, host, rawReq: selected.reqRaw } })
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
  function copyCurl() { if (selected) copyText(rawToCurl(editedReq, selected.url)) }
  function copyRawRequest() { copyText(editedReq) }

  return (
    <div className="flex flex-1 min-h-0" ref={hSplit.containerRef}>
      {/* Left: queue */}
      <div className="flex flex-col shrink-0 overflow-hidden" style={{ flex: hSplit.fraction }}>
        <div className="flex items-center justify-between px-3 py-2 border-b border-border bg-surface-card shrink-0">
          <span className="text-xs font-semibold uppercase tracking-wide">Intercept</span>
          <button
            onClick={toggleIntercept}
            className={`text-xs px-3 py-1 rounded-sm font-semibold ${
              enabled ? 'bg-accent text-content-primary' : 'bg-surface-hover text-content-secondary hover:bg-content-muted'
            }`}
          >
            {enabled ? 'ON' : 'OFF'}
          </button>
        </div>
        <div className="flex-1 overflow-auto min-h-0">
          {items.length === 0 ? (
            <div className="text-content-muted text-xs p-3">
              {enabled ? 'Waiting for requests...' : 'Intercept is disabled'}
            </div>
          ) : (
            items.map((item) => (
              <button
                key={item.id}
                onClick={() => setSelected(item)}
                className={`w-full text-left p-2 border-b border-border-subtle text-xs hover:bg-surface-hover ${
                  selected?.id === item.id ? 'bg-surface-hover' : ''
                }`}
              >
                <div className="font-bold text-accent">{item.method}</div>
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
                className="text-xs px-3 py-1 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold"
              >
                Drop
              </button>
              <button
                onClick={sendToManipulate}
                className="text-xs px-3 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold"
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
              <span className="text-content-muted text-xs self-center ml-2">
                {selected.method} {selected.url}
              </span>
            </div>
            <div className="flex-1 relative min-h-0">
              <div className="absolute inset-0 overflow-hidden">
                <CodeMirror
                  value={editedReq}
                  theme={oneDark}
                  height="100%"
                  onChange={setEditedReq}
                  extensions={wrap ? [contextMenuExt, EditorView.lineWrapping] : [contextMenuExt]}
                  basicSetup={{ lineNumbers: true, foldGutter: false }}
                />
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-content-muted text-sm">
            {enabled ? 'Select an intercepted request' : 'Enable intercept to pause requests'}
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
            { label: 'Manipulate', onClick: sendToManipulate, disabled: !selected },
            { label: 'Fuzz', onClick: sendToFuzz, disabled: !selected },
            { label: 'Copy URL', onClick: copyUrl, disabled: !selected },
            { label: 'Copy as curl', onClick: copyCurl, disabled: !selected },
            { label: 'Copy Raw Request', onClick: copyRawRequest, disabled: !selected },
          ]}
        />
      )}
    </div>
  )
}
