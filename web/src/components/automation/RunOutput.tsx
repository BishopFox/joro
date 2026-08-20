import { X } from 'lucide-react'
import type { ScriptRun } from '../../lib/api'

/**
 * The run report: how it ended, what it logged, what it returned.
 *
 * Shared by the editor and by History's run-on-a-request menu, so a run reads the same
 * wherever it was started.
 */
export default function RunOutput({ run, onClose }: { run: ScriptRun; onClose: () => void }) {
  const r = run.result
  const bad = r.reason !== 'success'
  return (
    <div className="shrink-0 border-t border-border max-h-56 overflow-y-auto">
      <div className="flex items-center gap-2 px-3 py-1.5 sticky top-0 bg-surface-card border-b border-border-subtle">
        <span className={`text-[11px] font-semibold ${bad ? 'text-semantic-warning' : 'text-semantic-success'}`}>
          {r.reason}
        </span>
        {/* Counts against the budget they were held to: a bare "12 calls" says nothing
            about whether the run was cut short. */}
        <span className="text-[10px] text-content-muted font-mono">
          {run.durationMs}ms · {r.calls}
          {r.budget?.maxCalls ? `/${r.budget.maxCalls}` : ''} call{r.calls === 1 ? '' : 's'}
          {r.sendCalls > 0
            ? ` (${r.sendCalls}${r.budget?.maxSendCalls ? `/${r.budget.maxSendCalls}` : ''} sending)`
            : ''}
          {r.storageOps ? ` · ${r.storageOps} storage` : ''}
        </span>
        {/* The policy half of what the run was held to. A run inherits it rather than
            asking for one, so an operator whose sends were all refused reads why here.
            Only the exception is called out in warning colour: scope enforced and
            credentials masked are the ordinary states and earn no badge. */}
        <span className="text-[10px] font-mono">
          <span className={run.requireScope ? 'text-content-muted' : 'text-semantic-warning'}>
            scope {run.requireScope ? 'required' : 'exempt'}
          </span>
          {run.credentials && <span className="text-semantic-warning"> · credentials visible</span>}
        </span>
        <button onClick={onClose} className="ml-auto text-content-muted hover:text-content-primary" aria-label="Dismiss">
          <X size={13} strokeWidth={2} />
        </button>
      </div>
      <div className="p-3 space-y-2 text-[11px]">
        {r.err && <pre className="font-mono whitespace-pre-wrap text-semantic-error">{r.err}</pre>}
        {r.logs && r.logs.length > 0 && (
          <div className="font-mono bg-surface-input rounded p-2">
            {r.logs.map((l, i) => (
              <div
                key={i}
                className={
                  l.level === 'error'
                    ? 'text-semantic-error'
                    : l.level === 'warn'
                      ? 'text-semantic-warning'
                      : 'text-content-secondary'
                }
              >
                {l.text}
              </div>
            ))}
            {r.logsTruncated && <div className="text-content-muted">… log budget reached</div>}
          </div>
        )}
        {r.value !== undefined && r.value !== null && (
          <pre className="font-mono whitespace-pre-wrap bg-surface-input rounded p-2 overflow-x-auto">
            {JSON.stringify(r.value, null, 2)}
          </pre>
        )}
      </div>
    </div>
  )
}
