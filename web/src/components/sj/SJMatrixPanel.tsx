import { useEffect, useState } from 'react'
import { Play, Square, Unlock, TriangleAlert, Equal, Settings2 } from 'lucide-react'
import { api } from '../../lib/api'
import { useSJStore, resolveScope, type SJTab, type SJProfile } from '../../stores/sjStore'
import type { SJMatrixRow } from '../../lib/sjTypes'
import { verdictPill, methodClass } from '../../lib/sjStatus'
import { useResizable } from '../../lib/useResizable'
import { useToastStore } from '../../stores/toastStore'
import SJScopePicker, { scopeLabel } from './SJScopePicker'
import SJResultDetail from './SJResultDetail'

export default function SJMatrixPanel({
  tab,
  onOpenProfiles,
}: {
  tab: SJTab
  onOpenProfiles: () => void
}) {
  const store = useSJStore()
  const addToast = useToastStore((s) => s.addToast)
  const [detail, setDetail] = useState<{ runId: string; index: number } | null>(null)
  const split = useResizable('vertical', 0.7)
  const spec = tab.spec!
  const ops = spec.operations
  const run = tab.matrixRun
  const matrix = run?.matrix ?? null

  function setProfiles(next: SJProfile[]) {
    store.updateTab(tab.id, { profiles: next })
    // Pushed immediately: credentials live only on the server for the session,
    // and the run reads them from there.
    void api
      .sjSetProfiles(spec.id, next.map((p, i) => ({ ...p, rank: i })))
      .catch((e) => addToast(String((e as Error).message ?? e), 'error'))
  }

  async function start() {
    const enabled = tab.profiles.filter((p) => p.enabled)
    if (enabled.length < 2) {
      addToast('A matrix compares authentication states - enable at least two profiles', 'error')
      onOpenProfiles()
      return
    }
    try {
      const res = await api.sjScan({
        specId: spec.id,
        operationIds: resolveScope(tab.scope, ops),
        profileIds: enabled.map((p) => p.id),
        serverIndex: tab.serverIndex,
        scheme: tab.scheme,
        host: tab.host,
        basePath: tab.basePath,
        concurrency: tab.concurrency,
        ratePerSec: tab.ratePerSec,
        userAgent: tab.userAgent || undefined,
        allowDestructive: tab.allowDestructive,
      })
      store.startRun(tab.id, 'matrixRun', res.runId, res.kind, res.total, res.warnings ?? [])
      setDetail(null)
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  async function loadMatrix(id: string) {
    try {
      const view = await api.sjGetMatrix(id)
      store.updateRun(id, { matrix: view })
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  // The grid builds itself when the run finishes. It used to need a click on a
  // button the operator had no reason to expect, and a matrix fetched mid-run
  // reports unsent operations as errors, so there is nothing to gain by asking.
  useEffect(() => {
    if (!run || run.status === 'running' || run.matrix) return
    void loadMatrix(run.id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [run?.id, run?.status, run?.matrix])

  const enabled = tab.profiles.filter((p) => p.enabled)
  const profiles = matrix?.profiles ?? enabled

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {/* Profiles as chips: which authentication states this run compares, in
          privilege order. Editing them is one click away rather than a panel
          that only existed here. */}
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border shrink-0 flex-wrap text-xs">
        <span className="text-content-muted">Profiles</span>
        {tab.profiles.length === 0 ? (
          <span className="text-content-muted italic">none defined</span>
        ) : (
          tab.profiles.map((p, i) => (
            <button
              key={p.id}
              onClick={() => {
                const next = tab.profiles.slice()
                next[i] = { ...p, enabled: !p.enabled }
                setProfiles(next)
              }}
              title={p.enabled ? 'Included in the matrix' : 'Excluded'}
              className={`px-2 py-1 rounded-sm transition-colors ${
                p.enabled
                  ? 'bg-accent text-content-primary'
                  : 'bg-surface-input text-content-muted hover:text-content-secondary'
              }`}
            >
              {i}. {p.label || p.id}
            </button>
          ))
        )}
        <button
          onClick={onOpenProfiles}
          className="flex items-center gap-1 px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
        >
          <Settings2 size={12} /> Manage…
        </button>
        <span className="text-[10px] text-content-muted">least to most privileged</span>
      </div>

      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border shrink-0 flex-wrap text-xs">
        <SJScopePicker
          scope={tab.scope}
          ops={ops}
          disabled={run?.status === 'running'}
          onChange={(next) => store.updateTab(tab.id, { scope: next })}
        />
        <span className="text-content-muted">× {enabled.length} profiles</span>
        <div className="ml-auto flex items-center gap-1">
          {run && run.status !== 'running' && (
            <button
              onClick={() => {
                store.clearRun(tab.id, 'matrixRun')
                setDetail(null)
              }}
              className="px-2 py-1 text-content-muted hover:text-content-primary"
            >
              Clear
            </button>
          )}
          {run?.status === 'running' ? (
            <button
              onClick={() => void api.sjStopRun(run.id).catch(() => {})}
              className="flex items-center gap-1 px-3 py-1.5 rounded-sm bg-semantic-error-bg text-content-primary font-semibold"
            >
              <Square size={11} /> Stop
            </button>
          ) : (
            <button
              onClick={() => void start()}
              disabled={!tab.host}
              className="flex items-center gap-1 px-3 py-1.5 rounded-sm bg-accent-tertiary text-black font-semibold disabled:opacity-50"
            >
              <Play size={11} /> Run matrix
            </button>
          )}
        </div>
      </div>

      {run && (
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
        </div>
      )}

      <div ref={split.containerRef} className="flex flex-col flex-1 min-h-0">
        <div
          style={{ flex: detail ? split.fraction : 1 }}
          className="min-h-0 overflow-auto"
        >
          {!matrix ? (
            <div className="p-3 text-xs text-content-muted">
              {tab.profiles.length < 2
                ? 'Define at least two auth profiles, then run the matrix. A cell that matches a higher-privilege cell while a lower one is refused is what broken access control looks like.'
                : run?.status === 'running'
                  ? 'Running…'
                  : 'Run the matrix to build the grid.'}
            </div>
          ) : (
            <table className="text-xs w-full">
              <thead className="sticky top-0 bg-surface-card z-10">
                <tr className="text-content-muted text-left">
                  <th className="px-2 py-1.5 font-normal sticky left-0 bg-surface-card">Operation</th>
                  {profiles.map((p) => (
                    <th key={p.id} className="px-2 py-1.5 font-normal w-24">
                      {p.label || p.id}
                    </th>
                  ))}
                  <th className="px-2 py-1.5 font-normal w-32">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {(matrix.rows ?? []).map((row) => (
                  <MatrixRow
                    key={row.opId}
                    row={row}
                    onCell={(i) => setDetail({ runId: run!.id, index: i })}
                  />
                ))}
              </tbody>
            </table>
          )}
        </div>

        {detail && (
          <>
            <div className="drag-handle-v" {...split.handleProps} />
            <div style={{ flex: 1 - split.fraction }} className="min-h-0">
              <SJResultDetail runId={detail.runId} index={detail.index} />
            </div>
          </>
        )}
      </div>

      {matrix && (
        <div className="flex items-center gap-3 px-2 py-1 border-t border-border shrink-0 text-[10px] text-content-muted flex-wrap">
          <span className="flex items-center gap-1">
            <Unlock size={10} className="text-semantic-error" /> served without credentials
          </span>
          <span className="flex items-center gap-1">
            <TriangleAlert size={10} className="text-semantic-error" /> lower privilege reached a
            higher-privilege response
          </span>
          <span className="flex items-center gap-1">
            <Equal size={10} /> every profile got the same answer
          </span>
          {matrix.interesting.length > 0 && (
            <span className="ml-auto text-semantic-error">
              {matrix.interesting.length} worth reading
            </span>
          )}
        </div>
      )}
    </div>
  )
}

function MatrixRow({ row, onCell }: { row: SJMatrixRow; onCell: (index: number) => void }) {
  const cells = row.cells ?? []
  const identical =
    cells.length > 1 &&
    cells.every((c) => c.status === cells[0].status && c.len === cells[0].len && !c.skipped)

  return (
    <tr
      className={`border-b border-border-subtle ${
        row.verdict === 'open' || row.verdict === 'broken' ? 'border-l-2 border-l-semantic-error' : ''
      }`}
    >
      <td className="px-2 py-1 sticky left-0 bg-surface-body">
        <span className={`font-bold text-[10px] mr-1.5 ${methodClass(row.method)}`}>{row.method}</span>
        <span className="font-mono text-content-secondary">{row.path}</span>
      </td>
      {cells.map((c) => (
        <td
          key={c.profileId}
          onClick={() => onCell(c.index)}
          className="px-2 py-1 cursor-pointer hover:bg-surface-hover tabular-nums"
          title={c.skipped ? `not sent: ${c.skipped}` : c.error || `${c.len} bytes, ${c.ms} ms`}
        >
          {c.skipped ? (
            <span className="text-content-muted">-</span>
          ) : (
            <span className="text-content-secondary">{c.status}</span>
          )}
        </td>
      ))}
      <td className="px-2 py-1">
        <span className="flex items-center gap-1">
          {row.verdict === 'open' && <Unlock size={11} className="text-semantic-error" />}
          {row.verdict === 'broken' && <TriangleAlert size={11} className="text-semantic-error" />}
          {identical && row.verdict !== 'open' && row.verdict !== 'broken' && (
            <Equal size={11} className="text-content-muted" />
          )}
          {verdictPill(row.verdict, row.detail)}
        </span>
      </td>
    </tr>
  )
}
