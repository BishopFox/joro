import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, Eye, Play, Square, Trash2 } from 'lucide-react'
import { api } from '../../lib/api'
import { b64DecodeUTF8 } from '../../lib/bytes'
import { useResizable } from '../../lib/useResizable'
import { useChainStore } from '../../stores/chainStore'
import { useToastStore } from '../../stores/toastStore'
import type { Chain, ChainPlan, ChainPreviewStep } from '../../lib/chainTypes'
import ChainGrid from './ChainGrid'
import ChainCellDetail from './ChainCellDetail'

const KINDS = [
  { id: 'omit', label: 'Skip each step', hint: 'Does the application enforce that the step happened?' },
  { id: 'repeat', label: 'Repeat each step', hint: 'Is the step idempotent, or does it stack?' },
  { id: 'move', label: 'Swap neighbours', hint: 'Is the order enforced, or only suggested?' },
]

export default function ChainSweepView({ chain }: { chain: Chain }) {
  const store = useChainStore()
  const addToast = useToastStore((s) => s.addToast)
  const split = useResizable('horizontal', 0.6)

  const [kinds, setKinds] = useState<string[]>(['omit'])
  const [armed, setArmed] = useState(false)
  const [delayMs, setDelayMs] = useState(250)
  const [plan, setPlan] = useState<ChainPlan | null>(null)
  const [preview, setPreview] = useState<ChainPreviewStep[] | null>(null)

  // activeRunId survives a chain switch, so without this check the grid renders
  // one chain's verdicts under another's name, and Stop stops the wrong sweep.
  const openRun = store.activeRunId ? store.runs[store.activeRunId] : null
  const run = openRun && openRun.chainId === chain.id ? openRun : null
  const running = run?.status === 'running'

  // The plan is fetched whenever the selection changes so the request count and
  // the warnings sit beside the arming checkbox, rather than arriving after the
  // operator has already committed to sending them.
  useEffect(() => {
    if (kinds.length === 0) {
      setPlan(null)
      return
    }
    let live = true
    api
      .chainPlan(chain.id, kinds)
      .then((p) => live && setPlan(p))
      .catch(() => live && setPlan(null))
    return () => {
      live = false
    }
  }, [chain.id, kinds, chain.updatedAt])

  const toggleKind = (id: string) =>
    setKinds((k) => (k.includes(id) ? k.filter((x) => x !== id) : [...k, id]))

  const start = useCallback(async () => {
    try {
      const res = await api.chainStartRun({
        chainId: chain.id,
        kinds,
        allowStateChanging: armed,
        delayMs,
      })
      store.startRun(res.runId, chain.id, chain.name, res.total, res.warnings ?? [])
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }, [chain, kinds, armed, delayMs, store, addToast])

  const doPreview = useCallback(async () => {
    try {
      const first = plan?.variants.find((v) => v.kind !== 'baseline') ?? plan?.variants[0]
      if (!first) return
      const res = await api.chainPreview(chain.id, first.id, kinds)
      setPreview(res.steps)
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }, [chain.id, kinds, plan, addToast])

  const needsArming = (plan?.methods.length ?? 0) > 0

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="px-3 py-2 border-b border-border bg-surface-card shrink-0">
        <div className="flex items-center gap-4 flex-wrap">
          {KINDS.map((k) => (
            <label key={k.id} className="flex items-center gap-1.5 cursor-pointer" title={k.hint}>
              <input
                type="checkbox"
                checked={kinds.includes(k.id)}
                onChange={() => toggleKind(k.id)}
                disabled={running}
              />
              <span className="text-xs text-content-primary">{k.label}</span>
            </label>
          ))}

          <label className="flex items-center gap-1.5 text-xs text-content-secondary">
            Delay
            <input
              type="number"
              min={0}
              max={60000}
              value={delayMs}
              onChange={(e) => setDelayMs(Number(e.target.value))}
              disabled={running}
              className="w-16 bg-surface-input border border-border rounded px-1.5 py-0.5 text-xs text-content-primary"
            />
            ms
          </label>

          <div className="flex-1" />

          <button
            onClick={doPreview}
            disabled={running || !plan}
            className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-surface-input text-content-primary disabled:opacity-40"
            title="Render one variant's requests without sending anything"
          >
            <Eye size={12} /> Preview
          </button>

          {running ? (
            <button
              onClick={() => run && api.chainStopRun(run.id).catch(() => {})}
              className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-semantic-error-bg text-content-primary"
            >
              <Square size={12} /> Stop
            </button>
          ) : (
            <button
              onClick={start}
              disabled={kinds.length === 0 || (needsArming && !armed)}
              className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-accent-tertiary text-black disabled:opacity-40"
            >
              <Play size={12} /> Run sweep
            </button>
          )}
        </div>

        {needsArming && (
          <label className="flex items-start gap-2 mt-2 cursor-pointer">
            <input
              type="checkbox"
              checked={armed}
              onChange={() => setArmed(!armed)}
              disabled={running}
              className="mt-0.5"
            />
            <span className="text-xs text-content-primary flex items-center gap-1">
              <AlertTriangle size={12} className="text-semantic-warning" />
              Allow state-changing requests ({plan?.methods.join(', ')})
            </span>
          </label>
        )}

        {plan?.warnings.map((warn) => (
          <div key={warn} className="text-[11px] text-semantic-warning mt-1.5 flex items-start gap-1">
            <AlertTriangle size={11} className="mt-0.5 shrink-0" />
            <span>{warn}</span>
          </div>
        ))}
        {plan?.error && <div className="text-[11px] text-semantic-error mt-1.5">{plan.error}</div>}
      </div>

      {preview && (
        <div className="px-3 py-2 border-b border-border bg-surface-input shrink-0 max-h-56 overflow-y-auto">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-content-secondary">
              Preview - nothing was sent
            </span>
            <button className="text-content-muted hover:text-content-primary" onClick={() => setPreview(null)}>
              <Trash2 size={12} />
            </button>
          </div>
          {preview.map((p) => (
            <div key={p.stepId + p.label} className="mb-2">
              <div className="text-[11px] text-content-primary">{p.label}</div>
              {p.error && <div className="text-[11px] text-semantic-error">{p.error}</div>}
              {p.missing && (
                <div className="text-[11px] text-semantic-warning">
                  unresolved: {p.missing.map((m) => m.var).join(', ')}
                </div>
              )}
              {p.raw && (
                <pre className="font-mono text-[10px] text-content-muted whitespace-pre-wrap break-all mt-0.5">
                  {b64DecodeUTF8(p.raw)}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}

      {run && (
        <div className="px-3 py-1.5 border-b border-border flex items-center gap-3 text-xs shrink-0">
          <div className="w-40 h-1.5 bg-surface-input rounded overflow-hidden">
            <div
              className="h-full bg-accent-secondary transition-all"
              style={{ width: `${run.total ? (run.completed / run.total) * 100 : 0}%` }}
            />
          </div>
          <span className="text-content-secondary">
            {run.completed}/{run.total}
          </span>
          <span className="text-content-muted">{run.status}</span>
          {run.bypassed > 0 && (
            <span className="text-semantic-error">{run.bypassed} to review</span>
          )}
          {run.unresolved > 0 && (
            <span className="text-semantic-warning">{run.unresolved} unresolved</span>
          )}
          {run.errors > 0 && <span className="text-semantic-error">{run.errors} errors</span>}
          <div className="flex-1" />
          {!running && (
            <button
              className="text-content-muted hover:text-content-primary"
              title="Clear this run"
              onClick={() => {
                api.chainDeleteRun(run.id).catch(() => {})
                store.clearRun(run.id)
              }}
            >
              <Trash2 size={12} />
            </button>
          )}
        </div>
      )}

      {run ? (
        <div ref={split.containerRef} className="flex flex-1 min-h-0">
          <div style={{ width: `${split.fraction * 100}%` }} className="flex flex-col min-h-0">
            <ChainGrid
              run={run}
              selectedIndex={run.selectedIndex}
              onSelect={(i) => store.updateRun(run.id, { selectedIndex: i })}
            />
          </div>
          <div className="drag-handle-h" {...split.handleProps} />
          <div className="flex-1 min-w-0 flex flex-col border-l border-border">
            <ChainCellDetail runId={run.id} index={run.selectedIndex} />
          </div>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-content-muted text-sm px-8 text-center">
          <div>
            <div>Pick which mutations to try, then run the sweep.</div>
            <div className="text-xs mt-2 max-w-md">
              Every run measures the chain unchanged first and compares each variant against
              that, so a fresh session token is not mistaken for the application behaving
              differently.
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
