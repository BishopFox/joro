import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import { Play, Square, FileJson, AlertTriangle, Info } from 'lucide-react'
import { api } from '../../lib/api'
import { useSJStore, type SJTab } from '../../stores/sjStore'
import type { SJResult } from '../../lib/sjTypes'
import { formatSize } from '../../lib/sjStatus'
import { useToastStore } from '../../stores/toastStore'
import { copyText } from '../../lib/clipboard'
import { rawToCurl } from '../../lib/httpTransform'
import { b64DecodeUTF8 } from '../../lib/bytes'
import ContextMenu, { type MenuItem } from '../ContextMenu'
import { getSelectionMenuItems } from '../../lib/selectionMenu'

export default function SJBruteView({
  tab,
  onFailure,
}: {
  tab: SJTab
  onFailure: (tabId: string, e: unknown) => void
}) {
  const store = useSJStore()
  const navigate = useNavigate()
  const addToast = useToastStore((s) => s.addToast)
  const [loadingSpec, setLoadingSpec] = useState('')
  const [menu, setMenu] = useState<{ x: number; y: number; items: MenuItem[] } | null>(null)
  const [browser, setBrowser] = useState<{ available: boolean; browser: string } | null>(null)
  const run = tab.discoverRun
  const d = tab.discover

  // Asked once: the menu needs to say whether the managed browser exists rather
  // than offering an action that fails, the way TestingBrowserButton does.
  useEffect(() => {
    api.browserStatus().then(setBrowser).catch(() => {})
  }, [])

  function setDiscover(patch: Partial<SJTab['discover']>) {
    store.updateTab(tab.id, { discover: { ...d, ...patch } })
  }

  async function start() {
    try {
      const res = await api.sjDiscover({
        scheme: d.scheme,
        host: d.host.trim(),
        basePath: d.basePath,
        full: d.full,
        stopOnFirst: d.stopOnFirst,
        concurrency: tab.bruteThreads,
        ratePerSec: tab.ratePerSec,
        userAgent: tab.userAgent || undefined,
      })
      store.startRun(tab.id, 'discoverRun', res.runId, res.kind, res.total, res.warnings ?? [])
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  async function loadFound(url: string) {
    setLoadingSpec(url)
    // Into the current slot when it is empty, otherwise a new one — the same
    // rule the header loader uses, so finding a second document never replaces
    // the one already open.
    const id = tab.spec ? store.addTab() : tab.id
    // A document the sweep already parsed is in the spec store, so open it by
    // id: re-fetching would put a second request on a live target for bytes
    // Joro is holding. The fetch stays as the fallback, for a row the sweep
    // never classified as a document and the operator is trying by hand.
    const already = run?.found.find((f) => f.sourceUrl === url)
    try {
      const res = already ? await api.sjGetSpec(already.specId) : await api.sjLoad({ url, userAgent: tab.userAgent || undefined })
      store.setSpec(id, res.spec)
    } catch (e) {
      onFailure(id, e)
    } finally {
      setLoadingSpec('')
    }
  }

  /** Opens a discovered URL in the managed testing browser, which routes through
   *  Joro's proxy and trusts its CA — so a Swagger UI page found by the sweep is
   *  explorable with its traffic captured, rather than only readable as bytes. */
  async function openInBrowser(url: string) {
    try {
      const res = await api.launchBrowser({ url })
      addToast(`Opened in ${res.browser}`, 'info')
    } catch (e) {
      addToast(`Launch failed: ${(e as Error).message ?? e}`, 'error')
    }
  }

  function rowMenu(r: SJResult): MenuItem[] {
    const isDoc = r.bodyKind === 'spec'
    const browserLabel = browser && !browser.available
      ? 'Open in testing browser (none detected)'
      : 'Open in testing browser'
    return [
      ...getSelectionMenuItems(navigate),
      {
        label: isDoc ? 'Load as document' : 'Try loading as a document',
        disabled: !r.url,
        onClick: () => void loadFound(r.url ?? ''),
      },
      {
        label: browserLabel,
        disabled: !r.url || (browser !== null && !browser.available),
        onClick: () => void openInBrowser(r.url ?? ''),
      },
      {
        label: 'View in History',
        disabled: !r.requestId,
        onClick: () => navigate('/history', { state: { focusRequestId: r.requestId } }),
      },
      {
        label: 'Copy as curl',
        disabled: !r.url,
        onClick: () =>
          void (async () => {
            try {
              const detail = await api.sjGetResult(run!.id, r.index)
              await copyText(rawToCurl(b64DecodeUTF8(detail.reqRaw), r.url ?? ''))
            } catch (e) {
              addToast(String((e as Error).message ?? e), 'error')
            }
          })(),
      },
      { label: 'Copy URL', disabled: !r.url, onClick: () => void copyText(r.url ?? '') },
    ]
  }

  const results = (run?.results ?? []).filter(Boolean)
  const interesting = results.filter((r) => r.bodyKind === 'spec' || r.bodyKind === 'weak' || r.bodyKind === 'reference')

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {tab.htmlHint && (
        <div className="flex items-start gap-1.5 px-2 py-1.5 border-b border-border shrink-0 text-[11px]">
          <Info size={12} className="text-semantic-info shrink-0 mt-px" />
          <div className="min-w-0">
            <div className="text-content-secondary">{tab.htmlHint.message}</div>
            {tab.htmlHint.candidates.length > 0 && (
              <div className="flex items-center gap-1 flex-wrap mt-1">
                {tab.htmlHint.candidates.slice(0, 12).map((c) => (
                  <button
                    key={c}
                    onClick={() => void loadFound(absoluteCandidate(c, tab))}
                    className="px-1.5 py-0.5 rounded-sm bg-surface-input hover:bg-surface-hover text-[10px] font-mono text-content-secondary"
                    title="Load this one"
                  >
                    {c}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border shrink-0 flex-wrap text-[11px]">
        <select
          value={d.scheme}
          onChange={(e) => setDiscover({ scheme: e.target.value })}
          className="bg-surface-input border border-border rounded-sm px-1 py-0.5"
        >
          <option value="https">https</option>
          <option value="http">http</option>
        </select>
        <input
          value={d.host}
          onChange={(e) => setDiscover({ host: e.target.value })}
          onKeyDown={(e) => e.key === 'Enter' && d.host.trim() && void start()}
          placeholder="target host"
          className="bg-surface-input border border-border rounded-sm px-1.5 py-0.5 w-56"
        />
        <input
          value={d.basePath}
          onChange={(e) => setDiscover({ basePath: e.target.value })}
          placeholder="/base"
          className="bg-surface-input border border-border rounded-sm px-1.5 py-0.5 w-24"
        />
        <label
          className="flex items-center gap-1"
          title="The full sweep crosses every prefix with every name - thousands of requests, all of them captured into History, which can evict traffic already there."
        >
          <input type="checkbox" checked={d.full} onChange={(e) => setDiscover({ full: e.target.checked })} />
          full sweep
        </label>
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={d.stopOnFirst} onChange={(e) => setDiscover({ stopOnFirst: e.target.checked })} />
          stop at first
        </label>
        <div className="ml-auto">
          {run?.status === 'running' ? (
            <button
              onClick={() => void api.sjStopRun(run.id).catch(() => {})}
              className="flex items-center gap-1 px-2 py-0.5 rounded-sm bg-semantic-error-bg text-content-primary text-[11px]"
            >
              <Square size={10} /> Stop
            </button>
          ) : (
            <button
              onClick={() => void start()}
              disabled={!d.host.trim()}
              className="flex items-center gap-1 px-2 py-0.5 rounded-sm bg-accent-tertiary text-black text-[11px] font-semibold disabled:opacity-50"
            >
              <Play size={10} /> Discover
            </button>
          )}
        </div>
      </div>

      {d.full && !run && (
        <div className="flex items-center gap-1 px-2 py-1 text-[10px] text-semantic-warning border-b border-border shrink-0">
          <AlertTriangle size={10} />
          A full sweep is roughly 2,200 requests. Every one is captured in History and may evict
          traffic already there.
        </div>
      )}

      {run && (
        <>
          {run.warnings.length > 0 && (
            <div className="px-2 py-1 border-b border-border shrink-0">
              {run.warnings.map((wmsg, i) => (
                <div key={i} className="flex items-center gap-1 text-[10px] text-semantic-warning">
                  <AlertTriangle size={10} /> {wmsg}
                </div>
              ))}
            </div>
          )}
          <div className="flex items-center gap-2 px-2 py-1 border-b border-border shrink-0 text-[10px]">
            <div className="h-1.5 flex-1 bg-surface-input rounded-sm overflow-hidden">
              <div
                className="h-full bg-accent-secondary"
                style={{ width: `${run.total ? (run.completed / run.total) * 100 : 0}%` }}
              />
            </div>
            <span className="text-content-muted tabular-nums">
              {run.completed}/{run.total}
            </span>
            <span className="text-content-secondary">{run.status}</span>
            <span className="text-semantic-success">{run.hits} found</span>
          </div>
        </>
      )}

      <div className="flex-1 min-h-0 overflow-auto">
        {interesting.length === 0 ? (
          <div className="p-3 text-[11px] text-content-muted">
            {run
              ? run.status === 'running'
                ? 'Sweeping…'
                : 'Nothing that looked like a document. Try the full sweep, or a base path.'
              : 'Give a host and run Discover. Every candidate goes through Joro’s proxy, so hits land in History too.'}
          </div>
        ) : (
          <table className="w-full text-[11px]">
            <thead className="sticky top-0 bg-surface-card z-10">
              <tr className="text-content-muted text-left">
                <th className="px-2 py-1 font-normal">Path</th>
                <th className="px-2 py-1 font-normal w-16">Status</th>
                <th className="px-2 py-1 font-normal w-16 text-right">Size</th>
                <th className="px-2 py-1 font-normal w-24">Kind</th>
                <th className="px-2 py-1 font-normal">Document</th>
              </tr>
            </thead>
            <tbody>
              {interesting.map((r) => (
                <tr
                  key={r.index}
                  onContextMenu={(e) => {
                    e.preventDefault()
                    setMenu({ x: e.clientX, y: e.clientY, items: rowMenu(r) })
                  }}
                  className="border-b border-border-subtle hover:bg-surface-hover cursor-context-menu"
                >
                  <td className="px-2 py-0.5 font-mono truncate max-w-0" title={r.url}>
                    {r.bodyKind === 'spec' && <FileJson size={11} className="inline mr-1 text-accent-secondary" />}
                    {r.path}
                  </td>
                  <td className="px-2 py-0.5 text-content-secondary tabular-nums">{r.status}</td>
                  <td className="px-2 py-0.5 text-right text-content-muted tabular-nums">{formatSize(r.len)}</td>
                  <td className="px-2 py-0.5 text-content-muted">{r.bodyKind}</td>
                  <td className="px-2 py-0.5">
                    {r.bodyKind === 'spec' ? (
                      <span className="flex items-center gap-2">
                        <span className="text-content-secondary truncate">
                          {r.specTitle} · {r.specOps} ops
                        </span>
                        <button
                          onClick={() => void loadFound(r.url ?? '')}
                          disabled={loadingSpec === r.url}
                          className="text-accent-secondary hover:underline shrink-0"
                        >
                          {loadingSpec === r.url ? 'loading…' : 'Load'}
                        </button>
                      </span>
                    ) : (
                      <span className="text-content-muted">{r.contentType}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
    </div>
  )
}

/** absoluteCandidate turns a path the Swagger UI page referenced into a URL on
 *  the target this tab is pointed at. An already-absolute one is left alone. */
function absoluteCandidate(candidate: string, tab: SJTab): string {
  if (candidate.includes('://')) return candidate
  const base = `${tab.discover.scheme || 'https'}://${tab.discover.host}`
  return candidate.startsWith('/') ? base + candidate : `${base}/${candidate}`
}
