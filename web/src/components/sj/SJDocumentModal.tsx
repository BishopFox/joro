import { useEffect, useState } from 'react'
import { Upload, Link2, ClipboardPaste, AlertTriangle, Search } from 'lucide-react'
import { api } from '../../lib/api'
import { b64DecodeUTF8 } from '../../lib/bytes'
import { useSJStore, type SJTab } from '../../stores/sjStore'
import TabButton from '../TabButton'

type Source = 'url' | 'file' | 'paste'
export type DocTab = 'load' | 'info' | 'diagnostics' | 'source'

/** Everything about the document in one place: how to load one, what was in it,
 *  what could not be resolved, and the bytes themselves. It was a sub-tab, which
 *  meant a whole working view was spent on a screen you visit once. */
export default function SJDocumentModal({
  tab,
  initialTab,
  onFailure,
  onClose,
  onBrute,
}: {
  tab: SJTab
  initialTab: DocTab
  onFailure: (tabId: string, e: unknown) => void
  onClose: () => void
  onBrute: () => void
}) {
  const store = useSJStore()
  const spec = tab.spec
  const [docTab, setDocTab] = useState<DocTab>(initialTab)
  const [source, setSource] = useState<Source>('url')
  const [text, setText] = useState('')
  const [url, setUrl] = useState('')
  const [fileName, setFileName] = useState('')
  const [specSource, setSpecSource] = useState('')

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onClose])

  useEffect(() => {
    if (docTab !== 'source' || !spec || specSource) return
    api
      .sjGetSpecSource(spec.id)
      .then((res) => setSpecSource(b64DecodeUTF8(res.source)))
      .catch(() => setSpecSource('(could not read the document source)'))
  }, [docTab, spec, specSource])

  // Read client-side, like the fuzzer's wordlist loader: the bytes have to reach
  // the server anyway, and a plain JSON post needs no multipart handling.
  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      setText(String(reader.result ?? ''))
      setFileName(file.name)
      setSource('file')
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  async function load() {
    store.updateTab(tab.id, { loading: true, loadError: '', htmlHint: null })
    try {
      const body =
        source === 'url'
          ? { url: url.trim(), userAgent: tab.userAgent || undefined }
          : { text, name: fileName || undefined }
      const res = await api.sjLoad(body)
      store.setSpec(tab.id, res.spec)
      setSpecSource('')
      onClose()
    } catch (e) {
      onFailure(tab.id, e)
      onClose()
    }
  }

  const diagnostics = spec?.diagnostics ?? []
  const canLoad = source === 'url' ? !!url.trim() : !!text.trim()

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
      onMouseDown={onClose}
    >
      <div
        className="flex flex-col w-full max-w-5xl h-[85vh] bg-surface-card border border-border rounded shadow-lg overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border">
          <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
            {spec ? spec.title : 'Load a document'}
          </span>
          <div className="ml-auto flex items-center gap-1">
            <TabButton active={docTab === 'load'} onClick={() => setDocTab('load')}>
              Load
            </TabButton>
            {spec && (
              <>
                <TabButton active={docTab === 'info'} onClick={() => setDocTab('info')}>
                  Info
                </TabButton>
                <TabButton active={docTab === 'diagnostics'} onClick={() => setDocTab('diagnostics')}>
                  Diagnostics{diagnostics.length > 0 ? ` (${diagnostics.length})` : ''}
                </TabButton>
                <TabButton active={docTab === 'source'} onClick={() => setDocTab('source')}>
                  Source
                </TabButton>
              </>
            )}
          </div>
        </div>

        <div className="flex-1 min-h-0 overflow-auto p-4">
          {docTab === 'load' && (
            <div className="max-w-xl space-y-3">
              <div className="flex items-center gap-1">
                {(['url', 'file', 'paste'] as Source[]).map((s) => (
                  <button
                    key={s}
                    onClick={() => setSource(s)}
                    className={`px-3 py-1.5 rounded-sm text-xs transition-colors ${
                      source === s
                        ? 'bg-accent text-content-primary'
                        : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
                    }`}
                  >
                    {s === 'url' ? 'URL' : s === 'file' ? 'File' : 'Paste'}
                  </button>
                ))}
              </div>

              {source === 'url' && (
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <Link2 size={14} className="text-content-muted shrink-0" />
                    <input
                      autoFocus
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && canLoad && void load()}
                      placeholder="https://target/api/v3/openapi.json"
                      className="flex-1 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                    />
                  </div>
                  <div className="text-[11px] text-content-muted">
                    Fetched through Joro's proxy, so the retrieval is captured in History and
                    obeys scope and Match &amp; Replace like any other request.
                  </div>
                </div>
              )}

              {source === 'file' && (
                <div className="space-y-1.5">
                  <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-sm bg-surface-input border border-border cursor-pointer text-xs hover:bg-surface-hover">
                    <Upload size={14} />
                    <span>{fileName || 'Choose a file…'}</span>
                    <input
                      type="file"
                      accept=".json,.yaml,.yml,application/json,text/yaml"
                      onChange={handleFile}
                      className="hidden"
                    />
                  </label>
                  {text && (
                    <div className="text-[11px] text-content-muted">
                      {text.length.toLocaleString()} bytes read
                    </div>
                  )}
                </div>
              )}

              {source === 'paste' && (
                <div className="flex items-start gap-2">
                  <ClipboardPaste size={14} className="text-content-muted shrink-0 mt-2" />
                  <textarea
                    value={text}
                    onChange={(e) => setText(e.target.value)}
                    placeholder="Paste a Swagger 2.0 or OpenAPI 3.x document"
                    className="flex-1 h-48 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border font-mono"
                  />
                </div>
              )}

              <div className="flex items-center gap-2">
                <button
                  onClick={() => void load()}
                  disabled={tab.loading || !canLoad}
                  className="px-4 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold disabled:opacity-50"
                >
                  {tab.loading ? 'Loading…' : 'Load document'}
                </button>
                <button
                  onClick={() => {
                    onClose()
                    onBrute()
                  }}
                  className="flex items-center gap-1.5 text-xs text-accent-secondary hover:underline"
                >
                  <Search size={12} /> Don't have one? Brute-force for it
                </button>
              </div>

              {tab.loadError && (
                <div className="flex items-start gap-2 text-xs text-semantic-error">
                  <AlertTriangle size={14} className="shrink-0 mt-px" />
                  <span>{tab.loadError}</span>
                </div>
              )}
            </div>
          )}

          {docTab === 'info' && spec && (
            <div className="max-w-xl space-y-1 text-xs">
              <Row label="Title" value={spec.title} />
              <Row label="Format" value={`${spec.format} ${spec.version}`} />
              {spec.apiVersion && <Row label="API version" value={spec.apiVersion} />}
              <Row label="Operations" value={String(spec.operations.length)} />
              <Row label="Servers" value={String(spec.servers.length)} />
              <Row label="Security schemes" value={String(spec.auth.length)} />
              <Row label="Size" value={`${spec.sizeBytes.toLocaleString()} bytes`} />
              {spec.sourceUrl && <Row label="Source" value={spec.sourceUrl} />}
              {spec.description && (
                <div className="pt-2 text-[11px] text-content-muted whitespace-pre-wrap">
                  {spec.description.slice(0, 2000)}
                </div>
              )}
            </div>
          )}

          {docTab === 'diagnostics' && spec && (
            <div>
              {diagnostics.length === 0 ? (
                <div className="text-xs text-content-muted">
                  Everything in this document resolved.
                </div>
              ) : (
                <>
                  <div className="text-[11px] text-content-muted mb-2 max-w-3xl">
                    These schemas were degraded to an empty object, so a request built from them
                    may be rejected for reasons that have nothing to do with authorization.
                  </div>
                  <table className="w-full text-[11px]">
                    <tbody>
                      {diagnostics.slice(0, 500).map((d, i) => (
                        <tr key={i} className="border-b border-border-subtle last:border-0">
                          <td className="py-1 pr-2 text-semantic-warning align-top whitespace-nowrap">
                            {d.kind}
                          </td>
                          <td className="py-1 pr-2 font-mono text-content-secondary break-all">
                            {d.ref}
                          </td>
                          <td className="py-1 font-mono text-content-muted break-all">{d.pointer}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </>
              )}
            </div>
          )}

          {docTab === 'source' && (
            <pre className="text-[11px] font-mono text-content-secondary whitespace-pre-wrap break-all">
              {specSource ? specSource.slice(0, 400_000) : 'Loading…'}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-3">
      <span className="text-content-muted w-32 shrink-0">{label}</span>
      <span className="text-content-secondary break-all">{value}</span>
    </div>
  )
}
