import { useState } from 'react'
import { useNavigate } from 'react-router'
import { Play, Square, AlertTriangle } from 'lucide-react'
import { api } from '../../lib/api'
import { useSJStore, resolveScope, type SJTab } from '../../stores/sjStore'
import SJScopePicker, { scopeLabel } from './SJScopePicker'
import { rawToCurl } from '../../lib/httpTransform'
import { b64DecodeUTF8 } from '../../lib/bytes'
import type { SJResult, SJTriage } from '../../lib/sjTypes'
import { triagePill, methodClass, formatSize } from '../../lib/sjStatus'
import { useResizable } from '../../lib/useResizable'
import ContextMenu, { type MenuItem } from '../ContextMenu'
import { getSelectionMenuItems } from '../../lib/selectionMenu'
import { copyText } from '../../lib/clipboard'
import { useToastStore } from '../../stores/toastStore'
import SJResultDetail from './SJResultDetail'

export default function SJAutomateView({ tab }: { tab: SJTab }) {
  const store = useSJStore()
  const navigate = useNavigate()
  const addToast = useToastStore((s) => s.addToast)
  const split = useResizable('horizontal', 0.55)
  const [menu, setMenu] = useState<{ x: number; y: number; items: MenuItem[] } | null>(null)
  const run = tab.scanRun
  const spec = tab.spec!
  const ops = spec.operations

  async function start() {
    try {
      const res = await api.sjScan({
        specId: spec.id,
        operationIds: resolveScope(tab.scope, ops),
        profileIds: tab.activeProfileId ? [tab.activeProfileId] : undefined,
        serverIndex: tab.serverIndex,
        scheme: tab.scheme,
        host: tab.host,
        basePath: tab.basePath,
        concurrency: tab.concurrency,
        ratePerSec: tab.ratePerSec,
        userAgent: tab.userAgent || undefined,
        allowDestructive: tab.allowDestructive,
      })
      store.startRun(tab.id, 'scanRun', res.runId, res.kind, res.total, res.warnings ?? [])
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  function rowMenu(r: SJResult): MenuItem[] {
    return [
      ...getSelectionMenuItems(navigate),
      {
        label: 'Open in form',
        disabled: !r.opId,
        onClick: () => store.updateTab(tab.id, { subTab: 'operations', selectedOpId: r.opId ?? null }),
      },
      {
        label: 'View in History',
        disabled: !r.requestId,
        onClick: () => navigate('/history', { state: { focusRequestId: r.requestId } }),
      },
      {
        // The bytes are fetched on demand rather than held in the row: a scan
        // keeps thousands of results and only one is ever copied.
        label: 'Copy as curl',
        disabled: !r.url || !!r.skipped,
        onClick: () =>
          void (async () => {
            try {
              const d = await api.sjGetResult(run!.id, r.index)
              await copyText(rawToCurl(b64DecodeUTF8(d.reqRaw), r.url ?? ''))
            } catch (e) {
              addToast(String((e as Error).message ?? e), 'error')
            }
          })(),
      },
      { label: 'Copy URL', disabled: !r.url, onClick: () => void copyText(r.url ?? '') },
    ]
  }

  const results = (run?.results ?? []).filter(Boolean)
  const counts = results.reduce<Record<SJTriage, number>>(
    (acc, r) => {
      if (!r.skipped) acc[r.triage] = (acc[r.triage] ?? 0) + 1
      return acc
    },
    { good: 0, warn: 0, bad: 0 }
  )
  const shown = run?.triageFilter ? results.filter((r) => r.triage === run.triageFilter && !r.skipped) : results

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border shrink-0 flex-wrap text-[11px]">
        <SJScopePicker
          scope={tab.scope}
          ops={ops}
          disabled={run?.status === 'running'}
          onChange={(next) => store.updateTab(tab.id, { scope: next })}
        />
        <label className="flex items-center gap-1">
          threads
          <input
            type="number"
            min={1}
            max={20}
            value={tab.concurrency}
            onChange={(e) => store.updateTab(tab.id, { concurrency: Number(e.target.value) })}
            className="w-12 bg-surface-input border border-border rounded-sm px-1 py-0.5"
          />
        </label>
        <label className="flex items-center gap-1">
          rate/s
          <input
            type="number"
            min={0}
            value={tab.ratePerSec}
            onChange={(e) => store.updateTab(tab.id, { ratePerSec: Number(e.target.value) })}
            className="w-12 bg-surface-input border border-border rounded-sm px-1 py-0.5"
          />
        </label>
        <label className="flex items-center gap-1" title="DELETE and PATCH, and operations whose name suggests they change something, are skipped unless this is ticked">
          <input
            type="checkbox"
            checked={tab.allowDestructive}
            onChange={(e) => store.updateTab(tab.id, { allowDestructive: e.target.checked })}
          />
          allow destructive
        </label>
        <div className="ml-auto flex items-center gap-1">
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
              disabled={!tab.host}
              className="flex items-center gap-1 px-2 py-0.5 rounded-sm bg-accent-tertiary text-black text-[11px] font-semibold disabled:opacity-50"
            >
              <Play size={10} /> Start scan
            </button>
          )}
        </div>
      </div>

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
            <span className="text-content-muted">· {scopeLabel(tab.scope, ops)}</span>
            {run.status !== 'running' && (
              <button
                onClick={() => store.clearRun(tab.id, 'scanRun')}
                className="text-content-muted hover:text-content-primary"
                title="Dismiss these results"
              >
                Clear
              </button>
            )}
            {(['good', 'warn', 'bad'] as SJTriage[]).map((t) => (
              <button
                key={t}
                onClick={() => store.updateRun(run.id, { triageFilter: run.triageFilter === t ? null : t })}
                className={`px-1 rounded-sm ${run.triageFilter === t ? 'bg-surface-hover' : ''}`}
              >
                {triagePill(t, 0)}
                <span className="ml-0.5 text-content-muted">{counts[t]}</span>
              </button>
            ))}
            {run.skipped > 0 && <span className="text-content-muted">{run.skipped} skipped</span>}
          </div>
        </>
      )}

      <div ref={split.containerRef} className="flex flex-1 min-h-0">
        <div style={{ flex: run?.selectedIndex != null ? split.fraction : 1 }} className="min-w-0 overflow-auto">
          <table className="w-full text-[11px]">
            <thead className="sticky top-0 bg-surface-card z-10">
              <tr className="text-content-muted text-left">
                <th className="px-2 py-1 font-normal w-16">Method</th>
                <th className="px-2 py-1 font-normal">Path</th>
                <th className="px-2 py-1 font-normal w-20">Status</th>
                <th className="px-2 py-1 font-normal w-16 text-right">Size</th>
                <th className="px-2 py-1 font-normal w-14 text-right">ms</th>
                <th className="px-2 py-1 font-normal w-40">Note</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => (
                <tr
                  key={r.index}
                  onClick={() => run && store.updateRun(run.id, { selectedIndex: r.index })}
                  onContextMenu={(e) => {
                    e.preventDefault()
                    setMenu({ x: e.clientX, y: e.clientY, items: rowMenu(r) })
                  }}
                  className={`border-b border-border-subtle cursor-pointer hover:bg-surface-hover ${
                    run?.selectedIndex === r.index ? 'bg-surface-hover' : ''
                  }`}
                >
                  <td className={`px-2 py-0.5 font-bold text-[10px] ${methodClass(r.method ?? '')}`}>{r.method}</td>
                  {/* The path as rendered, so the generated values are readable
                      without opening the row. A row skipped before it rendered
                      has none, and falls back to the document's template. */}
                  <td className="px-2 py-0.5 font-mono truncate max-w-0" title={r.url || r.path}>
                    {r.reqPath || r.path}
                  </td>
                  <td className="px-2 py-0.5">{triagePill(r.triage, r.status, r.skipped)}</td>
                  <td className="px-2 py-0.5 text-right text-content-muted tabular-nums">{r.skipped ? '' : formatSize(r.len)}</td>
                  <td className="px-2 py-0.5 text-right text-content-muted tabular-nums">{r.skipped ? '' : r.ms}</td>
                  <td className="px-2 py-0.5 text-content-muted truncate max-w-0" title={r.note || r.error || ''}>
                    {r.error || r.note}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!run && (
            <div className="p-3 text-[11px] text-content-muted">
              No scan yet. Every request goes through Joro's proxy, so results also land in History,
              the Site Map and Detect.
            </div>
          )}
        </div>

        {run?.selectedIndex != null && (
          <>
            <div className="drag-handle-h" {...split.handleProps} />
            <div style={{ flex: 1 - split.fraction }} className="min-w-0">
              <SJResultDetail runId={run.id} index={run.selectedIndex} />
            </div>
          </>
        )}
      </div>

      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
    </div>
  )
}
