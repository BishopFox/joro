import { useEffect, useState, useRef, useMemo, useCallback, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ChevronLeft, ChevronRight, Flag, WrapText, Pilcrow, CornerDownRight, X, Plus } from 'lucide-react'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView, Decoration, DecorationSet, ViewPlugin, ViewUpdate, WidgetType } from '@codemirror/view'
import type { Range } from '@codemirror/state'
import { oneDark } from '@codemirror/theme-one-dark'
import { api } from '../lib/api'
import { ResponseRender, usePrettyJson } from '../components/ResponseRender'
import { useResizable } from '../lib/useResizable'
import { useManipulateStore } from '../stores/manipulateStore'
import { changeRequestType, changeContentType, getMethod, getContentType, rawToCurl, updateContentLengthInRaw } from '../lib/httpTransform'
import ContextMenu from '../components/ContextMenu'
import { Tooltip } from '../components/Tooltip'
import { getSelectionMenuItems } from '../lib/selectionMenu'
import { copyText } from '../lib/clipboard'
import { useSettingsStore } from '../stores/settingsStore'
import { useToastStore } from '../stores/toastStore'
import { useDeadDropStore } from '../stores/deadDropStore'

function b64Encode(s: string) { try { return btoa(s) } catch { return s } }
function b64Decode(s: string) { try { return atob(s) } catch { return s } }

function parseResponseMeta(raw: string) {
  const crlfIdx = raw.indexOf('\r\n\r\n')
  const lfIdx = raw.indexOf('\n\n')
  let headerEnd: number
  let bodySepLen: number
  if (crlfIdx >= 0 && (lfIdx < 0 || crlfIdx <= lfIdx)) {
    headerEnd = crlfIdx; bodySepLen = 4
  } else if (lfIdx >= 0) {
    headerEnd = lfIdx; bodySepLen = 2
  } else {
    headerEnd = -1; bodySepLen = 0
  }
  const headerBlock = headerEnd >= 0 ? raw.slice(0, headerEnd) : raw
  const body = headerEnd >= 0 ? raw.slice(headerEnd + bodySepLen) : ''
  let contentType = ''
  for (const line of headerBlock.split(/\r?\n/)) {
    if (line.toLowerCase().startsWith('content-type:')) {
      contentType = line.slice('content-type:'.length).trim().split(';')[0]
      break
    }
  }
  return { bodySize: body.length, contentType }
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}


// Widget that renders a non-printable character marker inline
class NPWidget extends WidgetType {
  constructor(readonly label: string) { super() }
  toDOM() {
    const span = document.createElement('span')
    span.className = 'cm-nonprintable'
    span.textContent = this.label
    return span
  }
  ignoreEvent() { return false }
}

const crlfWidget = new NPWidget('\\r\\n')
const tabWidget = new NPWidget('\\t')
const nulWidget = new NPWidget('\\0')

// CodeMirror plugin: shows \r\n at line ends, \t for tabs, and other control chars
function nonPrintablePlugin() {
  return ViewPlugin.fromClass(class {
    decorations: DecorationSet
    constructor(view: EditorView) { this.decorations = this.build(view) }
    update(update: ViewUpdate) {
      if (update.docChanged || update.viewportChanged) this.decorations = this.build(update.view)
    }
    build(view: EditorView): DecorationSet {
      const ranges: Range<Decoration>[] = []
      const doc = view.state.doc

      for (const { from, to } of view.visibleRanges) {
        const startLine = doc.lineAt(from).number
        const endLine = doc.lineAt(to).number

        for (let ln = startLine; ln <= endLine; ln++) {
          const line = doc.line(ln)
          const lineText = line.text

          // Inline: tabs and other control chars within the line
          for (let i = 0; i < lineText.length; i++) {
            const code = lineText.charCodeAt(i)
            if (code === 9) { // tab
              ranges.push(Decoration.widget({ widget: tabWidget, side: 0 }).range(line.from + i))
            } else if (code === 0) { // null
              ranges.push(Decoration.widget({ widget: nulWidget, side: 0 }).range(line.from + i))
            } else if (code < 32 && code !== 10 && code !== 13 && code !== 9) {
              // Other control chars
              const w = new NPWidget('\\x' + code.toString(16).padStart(2, '0'))
              ranges.push(Decoration.widget({ widget: w, side: 0 }).range(line.from + i))
            }
          }

          // End-of-line marker: show \r\n for all lines except the last (which has no newline).
          // HTTP raw requests use CRLF, so we show \r\n to reflect what will actually be sent.
          if (ln < doc.lines) {
            ranges.push(Decoration.widget({ widget: crlfWidget, side: 1 }).range(line.to))
          }
        }
      }

      // Sort by position for DecorationSet
      ranges.sort((a, b) => a.from - b.from || a.value.startSide - b.value.startSide)
      return Decoration.set(ranges)
    }
  }, { decorations: v => v.decorations })
}

export default function ManipulateHTTP() {
  const location = useLocation()
  const navigate = useNavigate()
  const { tabs, activeTabId, addTab, removeTab, renameTab, updateTab, setActiveTab, pushHistory, goBack, goForward } = useManipulateStore()
  const tab = tabs.find((t) => t.id === activeTabId) ?? tabs[0]

  const [editingTabId, setEditingTabId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')
  const renameInputRef = useRef<HTMLInputElement>(null)

  const hSplit = useResizable('horizontal', 0.5)
  const [respTab, setRespTab] = useState<'raw' | 'render'>('raw')
  const [prettyJson, setPrettyJson] = usePrettyJson()

  const settings = useSettingsStore((s) => s.settings)
  const teamMode = !!(settings?.listenerUrl && settings?.teamToken && settings?.teamNickname)
  const addToast = useToastStore((s) => s.addToast)

  useEffect(() => {
    const state = location.state as { subTab?: string; scheme?: string; host?: string; rawReq?: string } | null
    if (state?.rawReq && state?.subTab !== 'ws') {
      addTab({
        scheme: state.scheme || 'https',
        host: state.host || 'example.com',
        rawReq: b64Decode(state.rawReq),
        response: '',
        status: null,
        duration: null,
      })
      navigate('/manipulate', { replace: true })
    }
  }, [location.state]) // eslint-disable-line

  useEffect(() => {
    if (editingTabId && renameInputRef.current) {
      renameInputRef.current.focus()
      renameInputRef.current.select()
    }
  }, [editingTabId])

  async function send() {
    const rawToSend = tab.updateContentLength ? updateContentLengthInRaw(tab.rawReq) : tab.rawReq
    updateTab(tab.id, { sending: true, error: '', rawReq: rawToSend })
    try {
      const res = await api.send(b64Encode(rawToSend), tab.scheme, tab.host, {
        updateContentLength: tab.updateContentLength,
        followRedirects: tab.followRedirects,
        decompress: tab.decompress,
      })
      const response = b64Decode(res.rawResp)
      updateTab(tab.id, { status: res.status, duration: res.durationMs, response, sending: false })
      pushHistory(tab.id, { scheme: tab.scheme, host: tab.host, rawReq: rawToSend, response, status: res.status, duration: res.durationMs })
    } catch (e) {
      updateTab(tab.id, { error: String(e), sending: false })
    }
  }

  const canGoBack = tab.history.length > 0 && tab.historyIndex > 0
  const canGoForward = tab.history.length > 0 && tab.historyIndex < tab.history.length - 1

  function commitRename() {
    if (editingTabId && editName.trim()) {
      renameTab(editingTabId, editName.trim())
    }
    setEditingTabId(null)
  }

  const npPlugin = useMemo(() => nonPrintablePlugin(), [])

  // Context menu
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

  function sendToFuzz() {
    navigate('/fuzz', { state: { scheme: tab.scheme, host: tab.host, rawReq: b64Encode(tab.rawReq) } })
  }

  function getRequestUrl(): string {
    const firstLine = tab.rawReq.split('\n')[0] || ''
    const path = firstLine.split(/\s+/)[1] || '/'
    return `${tab.scheme}://${tab.host}${path}`
  }

  async function flagToTeam() {
    try {
      await api.flagRequest({
        host: tab.host,
        method: getMethod(tab.rawReq),
        url: getRequestUrl(),
        status: tab.status ?? 0,
        reqRaw: b64Encode(tab.rawReq),
        respRaw: b64Encode(tab.response || ''),
      })
      addToast('Flagged to team', 'info')
    } catch {
      addToast('Failed to flag request')
    }
  }

  function stageForDeadDrop() {
    // Manipulate requests have no source history id, so synthesize a unique
    // staging key (the store dedupes by id — a fresh key stages each snapshot).
    const key = `manip-${tab.id}-${Date.now()}`
    useDeadDropStore.getState().add({
      id: key,
      host: tab.host,
      method: getMethod(tab.rawReq),
      url: getRequestUrl(),
      status: tab.status ?? 0,
      reqRaw: b64Encode(tab.rawReq),
      respRaw: b64Encode(tab.response || ''),
      truncated: false,
      note: '',
    })
    addToast('Staged for Dead Drop', 'info')
  }

  function copyUrl() { copyText(getRequestUrl()) }
  function copyCurl() { copyText(rawToCurl(tab.rawReq, getRequestUrl())) }
  function copyRawRequest() { copyText(tab.rawReq) }
  function copyRawResponse() { copyText(tab.response || '') }

  const reqExtensions = useMemo(() => {
    const exts: any[] = [contextMenuExt]
    if (tab.wrapReq) exts.push(EditorView.lineWrapping)
    if (tab.showNonPrintable) exts.push(npPlugin)
    return exts
  }, [tab.wrapReq, tab.showNonPrintable, npPlugin, contextMenuExt])

  const respExtensions = useMemo(() => {
    const exts: any[] = [contextMenuExt]
    if (tab.wrapResp) exts.push(EditorView.lineWrapping)
    if (tab.showNonPrintable) exts.push(npPlugin)
    return exts
  }, [tab.wrapResp, tab.showNonPrintable, npPlugin, contextMenuExt])

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
                className="text-content-muted hover:text-semantic-error ml-1 leading-none inline-flex items-center"
              >
                <X size={12} />
              </button>
            )}
          </div>
        ))}
        <button
          onClick={() => addTab()}
          className="px-2 py-1.5 text-content-muted hover:text-content-secondary shrink-0 inline-flex items-center"
        >
          <Plus size={14} />
        </button>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
        <select
          value={tab.scheme}
          onChange={(e) => updateTab(tab.id, { scheme: e.target.value })}
          className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
        >
          <option value="https">HTTPS</option>
          <option value="http">HTTP</option>
        </select>
        <input
          value={tab.host}
          onChange={(e) => updateTab(tab.id, { host: e.target.value })}
          className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border flex-1 max-w-xs"
          placeholder="host:port"
        />
        <Tooltip content="Previous request">
          <button
            onClick={() => goBack(tab.id)}
            disabled={!canGoBack}
            className="px-1.5 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-30 inline-flex items-center"
          >
            <ChevronLeft size={14} />
          </button>
        </Tooltip>
        <Tooltip content="Next request">
          <button
            onClick={() => goForward(tab.id)}
            disabled={!canGoForward}
            className="px-1.5 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-30 inline-flex items-center"
          >
            <ChevronRight size={14} />
          </button>
        </Tooltip>
        <button
          onClick={send}
          disabled={tab.sending}
          className="text-xs px-4 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-50"
        >
          {tab.sending ? 'Sending...' : 'Send'}
        </button>
        {teamMode && (
          <Tooltip content="Flag this request to the team">
            <button
              onClick={flagToTeam}
              className="text-xs px-2 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary font-semibold inline-flex items-center gap-1"
            >
              <Flag size={13} /> Flag
            </button>
          </Tooltip>
        )}
        {tab.error && <span className="text-xs text-semantic-error">{tab.error}</span>}
      </div>

      {/* Split editor */}
      <div className="flex flex-1 overflow-hidden min-h-0" ref={hSplit.containerRef}>
        <div className="flex flex-col overflow-hidden min-h-0" style={{ flex: hSplit.fraction }}>
          <div className="flex items-center gap-1 px-2 py-1 bg-surface-card border-b border-border shrink-0">
            <span className="text-xs text-content-muted">Request</span>
            <div className="flex items-center gap-1 ml-auto">
              <SquareToggle label={<WrapText size={12} />} title="Line wrapping" active={tab.wrapReq} onClick={() => updateTab(tab.id, { wrapReq: !tab.wrapReq })} />
              <SquareToggle label="CL" title="Auto-update Content-Length" active={tab.updateContentLength} onClick={() => updateTab(tab.id, { updateContentLength: !tab.updateContentLength })} />
              <SquareToggle label={<Pilcrow size={12} />} title="Show non-printable characters" active={tab.showNonPrintable} onClick={() => updateTab(tab.id, { showNonPrintable: !tab.showNonPrintable })} />
              <SquareToggle label={<CornerDownRight size={12} />} title="Follow redirects" active={tab.followRedirects} onClick={() => updateTab(tab.id, { followRedirects: !tab.followRedirects })} />
              <SquareToggle label="gz" title="Decompress response" active={tab.decompress} onClick={() => updateTab(tab.id, { decompress: !tab.decompress })} />
            </div>
          </div>
          <div className="flex-1 relative min-h-0">
            <div className="absolute inset-0 overflow-hidden">
              <CodeMirror
                value={tab.rawReq}
                theme={oneDark}
                height="100%"
                onChange={(v) => updateTab(tab.id, { rawReq: v })}
                extensions={reqExtensions}
                basicSetup={{ lineNumbers: true, foldGutter: false }}
              />
            </div>
          </div>
        </div>

        {/* Horizontal drag handle */}
        <div className="drag-handle-h" onMouseDown={hSplit.onMouseDown} />

        <div className="flex flex-col overflow-hidden min-h-0" style={{ flex: 1 - hSplit.fraction }}>
          <div className="flex items-center gap-1 px-2 py-1 bg-surface-card border-b border-border shrink-0">
            <span className="text-xs text-content-muted">Response</span>
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
                <SquareToggle label={<WrapText size={12} />} title="Line wrapping" active={tab.wrapResp} onClick={() => updateTab(tab.id, { wrapResp: !tab.wrapResp })} />
              ) : (
                <SquareToggle label="{ }" title="Pretty-print JSON" active={prettyJson} onClick={() => setPrettyJson(!prettyJson)} />
              )}
            </div>
          </div>
          <div className="flex-1 relative min-h-0">
            {respTab === 'raw' ? (
              <div className="absolute inset-0 overflow-hidden">
                <CodeMirror
                  value={tab.response}
                  theme={oneDark}
                  readOnly={true}
                  height="100%"
                  extensions={respExtensions}
                  basicSetup={{ lineNumbers: true, foldGutter: false }}
                />
              </div>
            ) : tab.response ? (
              <ResponseRender raw={tab.response} prettyJson={prettyJson} />
            ) : null}
          </div>
          {tab.status !== null && tab.response && (() => {
            const meta = parseResponseMeta(tab.response)
            return (
              <div className="flex items-center gap-3 px-2 py-1 bg-surface-card border-t border-border shrink-0 text-[10px] text-content-muted">
                <span className={tab.status < 300 ? 'text-semantic-success' : tab.status < 400 ? 'text-semantic-warning' : 'text-semantic-error'}>
                  {tab.status}
                </span>
                <span>{tab.duration}ms</span>
                <span>{formatSize(meta.bodySize)}</span>
                {meta.contentType && <span>{meta.contentType}</span>}
              </div>
            )
          })()}
        </div>
      </div>
      {ctxMenu && (() => {
        const method = getMethod(tab.rawReq)
        const currentFormat = getContentType(tab.rawReq)
        return (
          <ContextMenu x={ctxMenu.x} y={ctxMenu.y} onClose={handleCloseCtxMenu} items={[
            ...getSelectionMenuItems(navigate),
            { label: 'Fuzz', onClick: sendToFuzz },
            {
              label: method === 'GET' ? 'Change to POST' : 'Change to GET',
              onClick: () => updateTab(tab.id, { rawReq: changeRequestType(tab.rawReq) }),
            },
            ...(method !== 'GET' ? [{
              label: 'Change Content Type',
              children: [
                { label: 'URL Encoded', checked: currentFormat === 'urlencoded', onClick: () => updateTab(tab.id, { rawReq: changeContentType(tab.rawReq, 'urlencoded') }) },
                { label: 'JSON', checked: currentFormat === 'json', onClick: () => updateTab(tab.id, { rawReq: changeContentType(tab.rawReq, 'json') }) },
                { label: 'XML', checked: currentFormat === 'xml', onClick: () => updateTab(tab.id, { rawReq: changeContentType(tab.rawReq, 'xml') }) },
              ],
            }] : []),
            { label: 'Stage for Dead Drop', onClick: stageForDeadDrop },
            { label: 'Copy URL', onClick: copyUrl },
            { label: 'Copy as curl', onClick: copyCurl },
            { label: 'Copy Raw Request', onClick: copyRawRequest },
            { label: 'Copy Raw Response', onClick: copyRawResponse, disabled: !tab.response },
          ]} />
        )
      })()}
    </div>
  )
}

function SquareToggle({ label, title, active, onClick }: { label: ReactNode; title: string; active: boolean; onClick: () => void }) {
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
