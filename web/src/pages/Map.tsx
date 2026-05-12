import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { oneDark } from '@codemirror/theme-one-dark'
import { api } from '../lib/api'
import type { SitemapHost, SitemapEndpoint, SitemapVariant } from '../lib/api'
import { rawToCurl } from '../lib/httpTransform'
import { RequestDetail } from '../stores/requestStore'
import { useRequestStore } from '../stores/requestStore'
import { ResponseRender, usePrettyJson } from '../components/ResponseRender'
import { useResizable } from '../lib/useResizable'
import ContextMenu from '../components/ContextMenu'
import { Tooltip } from '../components/Tooltip'
import { getSelectionMenuItems } from '../lib/selectionMenu'
import { copyText } from '../lib/clipboard'

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-semantic-success',
  POST: 'text-semantic-info',
  PUT: 'text-semantic-warning',
  DELETE: 'text-semantic-error',
  PATCH: 'text-semantic-special',
}

function b64Decode(s: string) {
  try { return atob(s) } catch { return s }
}

export default function Map() {
  const navigate = useNavigate()
  const [hosts, setHosts] = useState<SitemapHost[]>([])
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set())
  const [expandedEndpoints, setExpandedEndpoints] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(true)

  // Detail panel state.
  const [selectedDetail, setSelectedDetail] = useState<RequestDetail | null>(null)
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [detailError, setDetailError] = useState<string | null>(null)
  const [wrapReq, setWrapReq] = useState(true)
  const [wrapResp, setWrapResp] = useState(true)
  const [respTab, setRespTab] = useState<'raw' | 'render'>('raw')
  const [prettyJson, setPrettyJson] = usePrettyJson()
  const [detailMenu, setDetailMenu] = useState<{ x: number; y: number } | null>(null)

  // Resizable splits.
  const mainSplit = useResizable('horizontal', 0.35)
  const detailSplit = useResizable('horizontal', 0.5)

  const fetchSitemap = useCallback(async () => {
    try {
      const data = await api.getSitemap()
      setHosts(data.hosts ?? [])
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  // Fetch on mount.
  useEffect(() => {
    fetchSitemap()
  }, [fetchSitemap])

  // Re-fetch when new requests arrive (debounced).
  const total = useRequestStore((s) => s.total)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const mountedRef = useRef(false)

  useEffect(() => {
    if (!mountedRef.current) {
      mountedRef.current = true
      return
    }
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(fetchSitemap, 1000)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [total, fetchSitemap])

  function toggleHost(origin: string) {
    setExpandedHosts((prev) => {
      const next = new Set(prev)
      if (next.has(origin)) next.delete(origin)
      else next.add(origin)
      return next
    })
  }

  function toggleEndpoint(key: string) {
    setExpandedEndpoints((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  async function selectVariant(variant: SitemapVariant, key: string) {
    setSelectedKey(key)
    setLoadingDetail(true)
    setDetailError(null)
    try {
      const detail = await api.getRequest(variant.requestId)
      setSelectedDetail(detail as RequestDetail)
    } catch {
      setSelectedDetail(null)
      setDetailError('Request no longer available')
    } finally {
      setLoadingDetail(false)
    }
  }

  function handleEndpointClick(host: SitemapHost, ep: SitemapEndpoint) {
    const epKey = `${host.origin}${ep.path}`
    if (ep.variants.length <= 1) {
      const variant = ep.variants[0]
      if (variant) {
        selectVariant(variant, `${epKey}:0`)
      }
    } else {
      toggleEndpoint(epKey)
    }
  }

  const totalEndpoints = hosts.reduce((sum, h) => sum + h.endpoints.length, 0)

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

  return (
    <div className="flex flex-1 min-h-0" ref={mainSplit.containerRef}>
      {/* Left: Tree panel */}
      <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: mainSplit.fraction }}>
        {/* Top bar */}
        <div className="flex items-center gap-3 px-3 py-2 border-b border-border bg-surface-card shrink-0">
          <span className="text-xs font-semibold uppercase tracking-wide text-content-muted">Site Map</span>
          <span className="text-xs text-content-secondary">
            {hosts.length} {hosts.length === 1 ? 'host' : 'hosts'} &middot; {totalEndpoints} {totalEndpoints === 1 ? 'endpoint' : 'endpoints'}
          </span>
        </div>

        {/* Tree */}
        <div className="flex-1 overflow-auto p-3">
          {loading && hosts.length === 0 && (
            <div className="text-xs text-content-muted">Loading...</div>
          )}
          {!loading && hosts.length === 0 && (
            <div className="text-xs text-content-muted">No requests captured yet. Browse through the proxy to populate the site map.</div>
          )}
          <div className="space-y-0.5">
            {hosts.map((host) => {
              const hostExpanded = expandedHosts.has(host.origin)
              return (
                <div key={host.origin}>
                  {/* Host row */}
                  <button
                    onClick={() => toggleHost(host.origin)}
                    className="flex items-center gap-2 w-full text-left px-2 py-1.5 rounded-sm hover:bg-surface-hover transition-colors"
                  >
                    <span className={`text-[10px] text-content-muted transition-transform ${hostExpanded ? 'rotate-90' : ''}`}>&#9654;</span>
                    <span className="text-xs font-semibold text-content-primary">{host.origin}</span>
                    <span className="text-[10px] text-content-muted ml-1">({host.count})</span>
                    <span className="text-[10px] text-content-muted ml-auto">{host.endpoints.length} {host.endpoints.length === 1 ? 'endpoint' : 'endpoints'}</span>
                  </button>

                  {/* Endpoints */}
                  {hostExpanded && (
                    <div className="ml-5 border-l border-border-subtle">
                      {host.endpoints.map((ep) => {
                        const epKey = `${host.origin}${ep.path}`
                        const epExpanded = expandedEndpoints.has(epKey)
                        const hasMultipleVariants = ep.variants.length > 1
                        const singleVariantSelected = !hasMultipleVariants && ep.variants.length === 1 && selectedKey === `${epKey}:0`
                        return (
                          <div key={ep.path}>
                            <button
                              onClick={() => handleEndpointClick(host, ep)}
                              className={`flex items-center gap-2 w-full text-left px-2 py-1 rounded-sm transition-colors hover:bg-surface-hover cursor-pointer ${
                                singleVariantSelected ? 'bg-surface-hover' : ''
                              }`}
                            >
                              {hasMultipleVariants ? (
                                <span className={`text-[10px] text-content-muted transition-transform ${epExpanded ? 'rotate-90' : ''}`}>&#9654;</span>
                              ) : (
                                <span className="text-[10px] text-content-muted">&bull;</span>
                              )}
                              <span className="text-xs text-content-primary font-mono">{ep.path || '/'}</span>
                              <span className="flex items-center gap-1 ml-1">
                                {ep.methods.map((m) => (
                                  <span key={m} className={`text-[10px] font-bold ${METHOD_COLORS[m] ?? 'text-content-secondary'}`}>{m}</span>
                                ))}
                              </span>
                              <span className="text-[10px] text-content-muted ml-auto">({ep.count})</span>
                            </button>

                            {/* Variants */}
                            {epExpanded && hasMultipleVariants && (
                              <div className="ml-5 border-l border-border-subtle">
                                {ep.variants.map((v, vi) => {
                                  const vKey = `${epKey}:${vi}`
                                  const isSelected = selectedKey === vKey
                                  return (
                                    <button
                                      key={vi}
                                      onClick={() => selectVariant(v, vKey)}
                                      className={`flex items-center gap-2 w-full text-left px-2 py-1 rounded-sm transition-colors hover:bg-surface-hover cursor-pointer ${
                                        isSelected ? 'bg-surface-hover' : ''
                                      }`}
                                    >
                                      <span className="text-[10px] text-content-muted">&bull;</span>
                                      {v.params.length > 0 ? (
                                        <div className="flex flex-wrap gap-1">
                                          {v.params.map((p) => (
                                            <span key={p} className="text-[10px] font-mono text-content-secondary bg-surface-input px-1.5 py-0.5 rounded">{p}</span>
                                          ))}
                                        </div>
                                      ) : (
                                        <span className="text-[10px] text-content-muted italic">(no params)</span>
                                      )}
                                      <span className="text-[10px] text-content-muted ml-auto">({v.count})</span>
                                    </button>
                                  )
                                })}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Drag handle */}
      <div className="drag-handle-h" onMouseDown={mainSplit.onMouseDown} />

      {/* Right: Detail panel */}
      <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: 1 - mainSplit.fraction }}>
        {selectedDetail ? (
          <div
            className="flex flex-1 min-h-0"
            ref={detailSplit.containerRef}
            onContextMenu={(e) => {
              if (!selectedDetail) return
              e.preventDefault()
              setDetailMenu({ x: e.clientX, y: e.clientY })
            }}
          >
            {/* Request panel */}
            <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: detailSplit.fraction }}>
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

            {/* Drag handle */}
            <div className="drag-handle-h" onMouseDown={detailSplit.onMouseDown} />

            {/* Response panel */}
            <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: 1 - detailSplit.fraction }}>
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
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-content-muted text-sm">
            {loadingDetail ? 'Loading...' : detailError ? detailError : 'Select an endpoint to view request details'}
          </div>
        )}
      </div>

      {detailMenu && selectedDetail && (
        <ContextMenu
          x={detailMenu.x}
          y={detailMenu.y}
          onClose={() => setDetailMenu(null)}
          items={[
            ...getSelectionMenuItems(navigate),
            { label: 'Manipulate', onClick: sendToManipulate },
            { label: 'Fuzz', onClick: sendToFuzz },
            { label: 'Copy URL', onClick: copyUrl },
            { label: 'Copy as curl', onClick: copyCurl },
            { label: 'Copy Raw Request', onClick: () => copyRaw('request') },
            { label: 'Copy Raw Response', onClick: () => copyRaw('response') },
          ]}
        />
      )}
    </div>
  )
}
