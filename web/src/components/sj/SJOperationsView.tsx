import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import CodeMirror from '@uiw/react-codemirror'
import { oneDark } from '@codemirror/theme-one-dark'
import { ChevronRight, Send, RotateCcw, AlertTriangle } from 'lucide-react'
import { api } from '../../lib/api'
import { useSJStore, makeDraft, type SJTab, type SJDraft } from '../../stores/sjStore'
import type { SJOperation, SJParam } from '../../lib/sjTypes'
import { useResizable } from '../../lib/useResizable'
import { b64DecodeUTF8 as b64Decode, b64EncodeUTF8 as b64Encode } from '../../lib/bytes'
import { methodClass, triagePill, formatSize } from '../../lib/sjStatus'
import { ResponseRender, usePrettyJson } from '../ResponseRender'
import TabButton from '../TabButton'
import ContextMenu, { type MenuItem } from '../ContextMenu'
import { getSelectionMenuItems } from '../../lib/selectionMenu'
import { copyText } from '../../lib/clipboard'
import { rawToCurl } from '../../lib/httpTransform'
import { useToastStore } from '../../stores/toastStore'
import SJParamRow from './SJParamRow'

const RENDER_DEBOUNCE_MS = 250

export default function SJOperationsView({ tab }: { tab: SJTab }) {
  const store = useSJStore()
  const navigate = useNavigate()
  const addToast = useToastStore((s) => s.addToast)
  const hSplit = useResizable('horizontal', 0.22)
  const vSplit = useResizable('horizontal', 0.56)
  const [prettyJson, setPrettyJson] = usePrettyJson()
  const [respTab, setRespTab] = useState<'render' | 'raw'>('render')
  const [menu, setMenu] = useState<{ x: number; y: number; items: MenuItem[] } | null>(null)
  const renderTimer = useRef<number | null>(null)
  const renderCtrl = useRef<AbortController | null>(null)

  const spec = tab.spec!
  const op = spec.operations.find((o) => o.id === tab.selectedOpId) ?? null
  const draft = (op && tab.drafts[op.id]) || makeDraft()

  const groups = useMemo(() => groupOperations(spec.operations, tab), [spec.operations, tab.groupBy, tab.opFilter, tab.methodFilter])

  /** The methods this document actually declares, so the filter row offers only
   *  what is there rather than a fixed list of eight. */
  const methodsPresent = useMemo(() => {
    const seen = new Set(spec.operations.map((o) => o.method))
    return [...seen].sort()
  }, [spec.operations])

  /** sj's `endpoints` command: raw routes, one per line, for piping into other
   *  tooling. Unique and sorted, since a path with three methods is one route. */
  function copyEndpoints() {
    const base = tab.basePath ?? ''
    const routes = [...new Set(spec.operations.map((o) => base + o.path))].sort()
    void copyText(routes.join('\n'))
    addToast(`Copied ${routes.length} endpoints`, 'info')
  }

  /** Copy as curl, matching what every other request-bearing tab offers. The
   *  bytes are whatever would actually be sent, so an edited raw request copies
   *  as the operator edited it. */
  async function copyAsCurl() {
    if (!op) return
    try {
      const raw = draft.rawDirty
        ? draft.rawEdited
        : b64Decode((await api.sjRender(renderBody(op))).raw)
      const url = `${tab.scheme}://${tab.host}${firstLineTarget(raw)}`
      void copyText(rawToCurl(raw, url))
      addToast('Copied as curl', 'info')
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  function patchDraft(updates: Partial<SJDraft>) {
    if (!op) return
    store.updateDraft(tab.id, op.id, updates)
  }

  // Render is a preview, not a send path — see send(). It runs only while the
  // Raw pane is open, so typing in the form costs nothing.
  useEffect(() => {
    if (!op || draft.view !== 'raw' || draft.rawDirty) return
    if (renderTimer.current) window.clearTimeout(renderTimer.current)
    renderTimer.current = window.setTimeout(() => void doRender(), RENDER_DEBOUNCE_MS)
    return () => {
      if (renderTimer.current) window.clearTimeout(renderTimer.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [op?.id, draft.view, draft.rawDirty, JSON.stringify(draft.values), JSON.stringify(draft.omit), draft.contentType, draft.profileId, tab.scheme, tab.host, tab.basePath, tab.userAgent])

  async function doRender() {
    if (!op) return
    renderCtrl.current?.abort()
    const ctrl = new AbortController()
    renderCtrl.current = ctrl
    const seq = draft.renderSeq + 1
    patchDraft({ rendering: true, renderSeq: seq, renderError: '' })
    try {
      const res = await api.sjRender(renderBody(op))
      // A reply older than the newest request is dropped, so a slow render
      // cannot overwrite a newer one.
      const cur = useSJStore.getState().tabs.find((t) => t.id === tab.id)?.drafts[op.id]
      if (cur && cur.renderSeq > seq) return
      store.updateDraft(tab.id, op.id, { rendered: b64Decode(res.raw), rendering: false })
    } catch (e) {
      store.updateDraft(tab.id, op.id, { rendering: false, renderError: String((e as Error).message ?? e) })
    }
  }

  function renderBody(o: SJOperation) {
    const values: Record<string, string> = {}
    for (const [k, v] of Object.entries(draft.values)) {
      if (v !== undefined) values[k] = v
    }
    if (draft.contentType) values.contentType = draft.contentType
    const bodyText = draft.bodyByContentType[draft.contentType || defaultContentType(o)]
    if (bodyText !== undefined) values.body = bodyText
    return {
      specId: spec.id,
      operationId: o.id,
      serverIndex: tab.serverIndex,
      scheme: tab.scheme,
      host: tab.host,
      basePath: tab.basePath,
      values,
      omit: Object.keys(draft.omit),
      profileId: draft.profileId || tab.activeProfileId,
      userAgent: tab.userAgent || undefined,
    }
  }

  async function send() {
    if (!op) return
    patchDraft({ sending: true, error: '' })
    try {
      // When the bytes are clean the server renders again and sends in one call,
      // so a stale or in-flight preview can never become the request that goes
      // out. When they are dirty they go verbatim, and the profile is NOT
      // re-applied: it is already baked into what the operator edited.
      const body = draft.rawDirty
        ? { ...renderBody(op), raw: b64Encode(draft.rawEdited), profileId: '' }
        : renderBody(op)
      const res = await api.sjSend(body)
      patchDraft({
        sending: false,
        response: b64Decode(res.rawResp),
        status: res.status,
        durationMs: res.durationMs,
        seq: res.seq,
        requestId: res.requestId ?? '',
        seqNote: res.seqNote ?? '',
        triage: res.triage,
        rendered: draft.rawDirty ? draft.rendered : b64Decode(res.raw),
      })
    } catch (e) {
      patchDraft({ sending: false, error: String((e as Error).message ?? e) })
    }
  }

  async function sendToFuzz(param?: SJParam) {
    if (!op) return
    try {
      // The marker is placed server-side, after encoding. Searching the rendered
      // bytes for the value would break on a percent-encoded value, on one that
      // appears twice, and on one inside a JSON body.
      const res = await api.sjRender({
        ...renderBody(op),
        fuzzParam: param ? `${param.in}:${param.name}` : undefined,
        fuzzKeyword: param ? '§' : undefined,
      })
      navigate('/fuzz', { state: { scheme: res.scheme, host: res.host, rawReq: res.raw } })
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  async function sendToManipulate() {
    if (!op) return
    try {
      const res = draft.rawDirty
        ? { raw: b64Encode(draft.rawEdited), scheme: tab.scheme, host: tab.host }
        : await api.sjRender(renderBody(op))
      navigate('/manipulate', { state: { scheme: res.scheme, host: res.host, rawReq: res.raw } })
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  function paramMenu(param: SJParam): MenuItem[] {
    const key = `${param.in}:${param.name}`
    return [
      ...getSelectionMenuItems(navigate),
      { label: 'Send to Fuzz - mark here', onClick: () => void sendToFuzz(param) },
      { label: 'Reset to generated value', onClick: () => patchDraft({ values: { ...draft.values, [key]: param.default } }) },
      { label: 'Clear value', onClick: () => patchDraft({ values: { ...draft.values, [key]: '' } }) },
      { label: 'Copy parameter name', onClick: () => void copyText(param.name) },
    ]
  }

  const bodies = op?.bodies ?? []
  const activeCT = draft.contentType || (bodies[0]?.contentType ?? '')
  const activeBody =
    draft.bodyByContentType[activeCT] ??
    (bodies.find((b) => b.contentType === activeCT)?.content
      ? b64Decode(bodies.find((b) => b.contentType === activeCT)!.content)
      : '')

  return (
    <div ref={hSplit.containerRef} className="flex flex-1 min-h-0">
      {/* Operation tree */}
      <div style={{ flex: hSplit.fraction }} className="min-w-0 flex flex-col border-r border-border">
        <div className="p-1.5 border-b border-border shrink-0 space-y-1.5">
          <input
            value={tab.opFilter}
            onChange={(e) => store.updateTab(tab.id, { opFilter: e.target.value })}
            placeholder="Filter operations…"
            className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
          />
          <div className="flex items-center gap-1 flex-wrap">
            {methodsPresent.map((m) => {
              const on = tab.methodFilter.includes(m)
              return (
                <button
                  key={m}
                  onClick={() =>
                    store.updateTab(tab.id, {
                      methodFilter: on
                        ? tab.methodFilter.filter((x) => x !== m)
                        : [...tab.methodFilter, m],
                    })
                  }
                  className={`px-1.5 py-0.5 rounded-sm text-[10px] font-semibold transition-colors ${
                    on
                      ? 'bg-accent text-content-primary'
                      : `bg-surface-input hover:bg-surface-hover ${methodClass(m)}`
                  }`}
                >
                  {m}
                </button>
              )
            })}
          </div>
          <div className="flex items-center gap-1">
            <select
              value={tab.groupBy}
              onChange={(e) => store.updateTab(tab.id, { groupBy: e.target.value as 'tag' | 'path' })}
              className="bg-surface-input text-[10px] px-1.5 py-1 rounded-sm border border-border"
            >
              <option value="tag">by tag</option>
              <option value="path">by path</option>
            </select>
            <span className="text-[10px] text-content-muted">{spec.operations.length} ops</span>
            <button
              onClick={copyEndpoints}
              title="Copy every route, one per line - sj's endpoints command, for piping elsewhere"
              className="ml-auto text-[10px] text-accent-secondary hover:underline"
            >
              Copy endpoints
            </button>
          </div>
        </div>

        <div className="flex-1 min-h-0 overflow-auto">
          {groups.map(([group, ops]) => {
            const collapsed = !!tab.collapsed[group]
            return (
              <div key={group}>
                <button
                  onClick={() =>
                    store.updateTab(tab.id, {
                      collapsed: collapsed
                        ? Object.fromEntries(Object.entries(tab.collapsed).filter(([k]) => k !== group))
                        : { ...tab.collapsed, [group]: true },
                    })
                  }
                  className="w-full flex items-center gap-1 px-1.5 py-1 text-[11px] text-content-secondary hover:bg-surface-hover"
                >
                  <ChevronRight size={11} className={collapsed ? '' : 'rotate-90'} />
                  <span className="truncate">{group}</span>
                  <span className="ml-auto text-content-muted">{ops.length}</span>
                </button>
                {!collapsed &&
                  ops.map((o) => (
                    <div
                      key={o.id}
                      onClick={() => store.updateTab(tab.id, { selectedOpId: o.id })}
                      className={`flex items-center gap-1 pl-3 pr-1.5 py-0.5 cursor-pointer text-[11px] ${
                        o.id === tab.selectedOpId ? 'bg-surface-hover' : 'hover:bg-surface-hover'
                      }`}
                    >
                      <span className={`w-12 shrink-0 font-bold text-[9px] ${methodClass(o.method)}`}>{o.method}</span>
                      <span className="truncate text-content-secondary" title={o.summary || o.path}>
                        {o.path}
                      </span>
                      {o.destructive && (
                        <AlertTriangle
                          size={10}
                          className="text-semantic-warning shrink-0 ml-auto"
                          aria-label={`destructive: ${o.destructiveReasons?.join(', ')}`}
                        />
                      )}
                    </div>
                  ))}
              </div>
            )
          })}
        </div>
      </div>

      <div className="drag-handle-h" {...hSplit.handleProps} />

      {/* Request + response */}
      {!op ? (
        <div className="flex-1 flex items-center justify-center text-[11px] text-content-muted">
          Select an operation.
        </div>
      ) : (
        <div ref={vSplit.containerRef} className="flex flex-1 min-w-0">
          <div style={{ flex: vSplit.fraction }} className="min-w-0 flex flex-col">
            <div className="px-2 py-1.5 border-b border-border shrink-0">
              <div className="flex items-center gap-2">
                <span className={`font-bold text-xs ${methodClass(op.method)}`}>{op.method}</span>
                <span className="text-xs font-mono text-content-primary truncate">{op.path}</span>
                <div className="ml-auto flex items-center gap-1">
                  {tab.profiles.length > 0 && (
                    <select
                      value={draft.profileId || tab.activeProfileId}
                      onChange={(e) => patchDraft({ profileId: e.target.value })}
                      className="bg-surface-input border border-border rounded-sm px-1 py-0.5 text-[10px]"
                    >
                      <option value="">no auth</option>
                      {tab.profiles.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.label || p.id}
                        </option>
                      ))}
                    </select>
                  )}
                  <button
                    onClick={() => void send()}
                    disabled={draft.sending}
                    className="flex items-center gap-1 px-2 py-0.5 rounded-sm bg-accent-tertiary text-black text-[11px] font-semibold disabled:opacity-50"
                  >
                    <Send size={11} />
                    {draft.sending ? 'Sending…' : 'Send'}
                  </button>
                </div>
              </div>
              {op.summary && <div className="text-[10px] text-content-muted truncate">{op.summary}</div>}
              {op.destructive && (
                <div className="flex items-center gap-1 text-[10px] text-semantic-warning mt-0.5">
                  <AlertTriangle size={10} />
                  <span>Looks destructive ({op.destructiveReasons?.join(', ')}). A scan skips it unless you allow it.</span>
                </div>
              )}
            </div>

            <div className="flex items-center gap-1 px-2 py-1 border-b border-border shrink-0">
              <TabButton active={draft.view === 'form'} onClick={() => patchDraft({ view: 'form' })}>
                Form
              </TabButton>
              <TabButton active={draft.view === 'raw'} onClick={() => patchDraft({ view: 'raw' })}>
                <span className="flex items-center gap-1">
                  Raw
                  {draft.rawDirty && <span className="w-1.5 h-1.5 rounded-full bg-accent-secondary" />}
                </span>
              </TabButton>
              {draft.rendering && <span className="text-[10px] text-content-muted">rendering…</span>}
            </div>

            <div className="flex-1 min-h-0 overflow-auto">
              {draft.view === 'form' ? (
                <FormPane
                  op={op}
                  draft={draft}
                  activeCT={activeCT}
                  activeBody={activeBody}
                  onValue={(k, v) => patchDraft({ values: { ...draft.values, [k]: v } })}
                  onToggle={(k, on) => {
                    const next = { ...draft.omit }
                    if (on) delete next[k]
                    else next[k] = true
                    patchDraft({ omit: next })
                  }}
                  onContentType={(ct) => patchDraft({ contentType: ct })}
                  onBody={(text) =>
                    patchDraft({ bodyByContentType: { ...draft.bodyByContentType, [activeCT]: text } })
                  }
                  onMenu={(x, y, param) => setMenu({ x, y, items: paramMenu(param) })}
                />
              ) : (
                <div className="flex flex-col h-full">
                  {draft.rawDirty && (
                    <div className="flex items-center gap-2 px-2 py-1 bg-surface-input border-b border-border text-[10px] shrink-0">
                      <span className="text-content-secondary">
                        Raw edited - the form no longer drives this request, and the auth profile is not re-applied.
                      </span>
                      <button
                        onClick={() => {
                          patchDraft({ rawDirty: false, rawRetained: draft.rawEdited, rawEdited: '' })
                          void doRender()
                        }}
                        className="ml-auto flex items-center gap-1 text-accent-secondary hover:underline"
                      >
                        <RotateCcw size={10} /> Revert to form
                      </button>
                      {draft.rawRetained && (
                        <button
                          onClick={() => patchDraft({ rawDirty: true, rawEdited: draft.rawRetained })}
                          className="text-content-muted hover:underline"
                        >
                          Restore edits
                        </button>
                      )}
                    </div>
                  )}
                  {draft.renderError && (
                    <div className="px-2 py-1 text-[10px] text-semantic-error border-b border-border shrink-0">
                      {draft.renderError}
                    </div>
                  )}
                  <CodeMirror
                    value={draft.rawDirty ? draft.rawEdited : draft.rendered}
                    theme={oneDark}
                    height="100%"
                    basicSetup={{ lineNumbers: true, foldGutter: false }}
                    onChange={(v) => patchDraft({ rawDirty: true, rawEdited: v })}
                    className="flex-1 min-h-0 text-xs"
                  />
                </div>
              )}
            </div>
          </div>

          <div className="drag-handle-h" {...vSplit.handleProps} />

          <div style={{ flex: 1 - vSplit.fraction }} className="min-w-0 flex flex-col">
            <div className="flex items-center gap-1 px-2 py-1 border-b border-border shrink-0">
              <TabButton active={respTab === 'render'} onClick={() => setRespTab('render')}>
                Render
              </TabButton>
              <TabButton active={respTab === 'raw'} onClick={() => setRespTab('raw')}>
                Raw
              </TabButton>
              <label className="ml-auto flex items-center gap-1 text-[10px] text-content-secondary">
                <input type="checkbox" checked={prettyJson} onChange={(e) => setPrettyJson(e.target.checked)} />
                pretty
              </label>
            </div>
            <div className="flex-1 relative min-h-0 overflow-auto p-2">
              {draft.error ? (
                <div className="text-[11px] text-semantic-error">{draft.error}</div>
              ) : !draft.response ? (
                <div className="text-[11px] text-content-muted">No response yet.</div>
              ) : respTab === 'render' ? (
                <ResponseRender raw={draft.response} prettyJson={prettyJson} />
              ) : (
                <pre className="text-[10px] font-mono whitespace-pre-wrap break-all text-content-secondary">
                  {draft.response}
                </pre>
              )}
            </div>
            {draft.status !== null && (
              <div className="flex items-center gap-2 px-2 py-1 border-t border-border text-[10px] shrink-0">
                {triagePill(draft.triage ?? undefined, draft.status)}
                <span className="text-content-muted">{draft.durationMs} ms</span>
                <span className="text-content-muted">{formatSize(draft.response.length)}</span>
                {draft.requestId ? (
                  <button
                    onClick={() => navigate('/history', { state: { focusRequestId: draft.requestId } })}
                    className="ml-auto text-accent-secondary hover:underline"
                    title="Open this request in History"
                  >
                    seq #{draft.seq} ↗
                  </button>
                ) : (
                  <span className="ml-auto text-content-muted" title={draft.seqNote}>
                    not captured
                  </span>
                )}
              </div>
            )}
            <div className="flex items-center gap-2 px-2 py-1 border-t border-border shrink-0">
              <button onClick={() => void sendToManipulate()} className="text-[10px] text-accent-secondary hover:underline">
                Manipulate
              </button>
              <button onClick={() => void sendToFuzz()} className="text-[10px] text-accent-secondary hover:underline">
                Fuzz
              </button>
              <button onClick={() => void copyAsCurl()} className="text-[10px] text-accent-secondary hover:underline">
                Copy as curl
              </button>
            </div>
          </div>
        </div>
      )}

      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
    </div>
  )
}

function FormPane({
  op, draft, activeCT, activeBody, onValue, onToggle, onContentType, onBody, onMenu,
}: {
  op: SJOperation
  draft: SJDraft
  activeCT: string
  activeBody: string
  onValue: (key: string, v: string) => void
  onToggle: (key: string, on: boolean) => void
  onContentType: (ct: string) => void
  onBody: (text: string) => void
  onMenu: (x: number, y: number, param: SJParam) => void
}) {
  const byIn = ['path', 'query', 'header', 'cookie'] as const
  const disabled = draft.rawDirty

  return (
    <div className={disabled ? 'opacity-60' : ''}>
      {disabled && (
        <div className="px-2 py-1 text-[10px] text-content-muted border-b border-border-subtle">
          Send uses the raw bytes while they are edited. Revert to form to use these fields again.
        </div>
      )}
      {byIn.map((where) => {
        const params = (op.params ?? []).filter((p) => p.in === where)
        if (params.length === 0) return null
        return (
          <div key={where}>
            <div className="px-2 py-0.5 text-[10px] text-content-muted uppercase tracking-wide bg-surface-card">
              {where}
            </div>
            {params.map((p) => {
              const key = `${p.in}:${p.name}`
              return (
                <SJParamRow
                  key={key}
                  param={p}
                  value={draft.values[key] ?? p.default}
                  enabled={!draft.omit[key]}
                  onChange={(v) => onValue(key, v)}
                  onToggle={(on) => onToggle(key, on)}
                  onMenu={(x, y) => onMenu(x, y, p)}
                />
              )
            })}
          </div>
        )
      })}

      {(op.bodies?.length ?? 0) > 0 && (
        <div>
          <div className="flex items-center gap-2 px-2 py-0.5 bg-surface-card">
            <span className="text-[10px] text-content-muted uppercase tracking-wide">body</span>
            {op.bodyRequired && <span className="text-semantic-error text-[10px]">*</span>}
            <select
              value={activeCT}
              onChange={(e) => onContentType(e.target.value)}
              className="ml-auto bg-surface-input border border-border rounded-sm px-1 py-0.5 text-[10px]"
            >
              {op.bodies!.map((b) => (
                <option key={b.contentType} value={b.contentType}>
                  {b.contentType}
                </option>
              ))}
            </select>
          </div>
          <textarea
            value={activeBody}
            onChange={(e) => onBody(e.target.value)}
            className="w-full h-44 bg-surface-input border-0 px-2 py-1 text-xs font-mono"
            spellCheck={false}
          />
        </div>
      )}
    </div>
  )
}

function defaultContentType(op: SJOperation): string {
  return op.bodies?.[0]?.contentType ?? ''
}

/** groupOperations buckets the filtered operation list for the tree. */
function groupOperations(ops: SJOperation[], tab: SJTab): [string, SJOperation[]][] {
  const filter = tab.opFilter.toLowerCase()
  const map = new Map<string, SJOperation[]>()
  for (const op of ops) {
    if (tab.methodFilter.length > 0 && !tab.methodFilter.includes(op.method)) continue
    if (
      filter &&
      !op.path.toLowerCase().includes(filter) &&
      !(op.summary ?? '').toLowerCase().includes(filter) &&
      !op.id.toLowerCase().includes(filter)
    ) {
      continue
    }
    const key =
      tab.groupBy === 'tag'
        ? op.tags?.[0] ?? 'untagged'
        : '/' + (op.path.split('/').filter(Boolean)[0] ?? '')
    const list = map.get(key) ?? []
    list.push(op)
    map.set(key, list)
  }
  return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]))
}

/** firstLineTarget pulls the request target out of raw bytes, so a curl command
 *  carries the query string the render actually produced. */
function firstLineTarget(raw: string): string {
  const line = raw.split('\r\n')[0] ?? ''
  return line.split(' ')[1] ?? '/'
}
