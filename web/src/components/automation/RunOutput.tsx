import { Download, X } from 'lucide-react'
import { api, type CommandValue, type ScriptRun } from '../../lib/api'

/**
 * The run report: how it ended, what it logged, what it returned.
 *
 * Shared by the editor and by History's run-on-a-request menu, so a run reads the same
 * wherever it was started — and shared by both kinds of automation, which is why the
 * header is assembled from what a run actually has rather than from a fixed list. A
 * command makes no SDK calls and holds no scope policy, so those parts are absent for one
 * rather than shown as zero.
 */
export default function RunOutput({ run, onClose }: { run: ScriptRun; onClose: () => void }) {
  const r = run.result
  // The code, not the prose beside it: reason is display text and free to be reworded.
  const bad = r.outcome !== 'success'
  // A command run carries no bundle, because there is no grant bundle behind it. That is
  // the one field that separates the two kinds in a run record.
  const isCommand = !run.bundle
  const cmd = isCommand ? readCommandValue(r.value) : null

  return (
    <div className="shrink-0 border-t border-border max-h-56 overflow-y-auto">
      <div className="flex items-center gap-2 px-3 py-1.5 sticky top-0 bg-surface-card border-b border-border-subtle">
        <span className={`text-[11px] font-semibold ${bad ? 'text-semantic-warning' : 'text-semantic-success'}`}>
          {r.reason}
        </span>

        {isCommand ? (
          <span className="text-[10px] text-content-muted font-mono">
            {run.durationMs}ms
            {cmd && (
              <>
                {' · '}
                <span className={cmd.exitCode === 0 ? 'text-content-muted' : 'text-semantic-warning'}>
                  exit {cmd.exitCode}
                </span>
              </>
            )}
            {cmd?.truncated && ' · output truncated'}
          </span>
        ) : (
          /* Counts against the budget they were held to: a bare "12 calls" says nothing
             about whether the run was cut short. */
          <span className="text-[10px] text-content-muted font-mono">
            {run.durationMs}ms · {r.calls}
            {r.budget?.maxCalls ? `/${r.budget.maxCalls}` : ''} call{r.calls === 1 ? '' : 's'}
            {r.sendCalls > 0
              ? ` (${r.sendCalls}${r.budget?.maxSendCalls ? `/${r.budget.maxSendCalls}` : ''} sending)`
              : ''}
            {r.storageOps ? ` · ${r.storageOps} storage` : ''}
          </span>
        )}

        {/* The policy half of what the run was held to. A run inherits it rather than
            asking for one, so an operator whose sends were all refused reads why here.
            Only the exception is called out in warning colour: scope enforced and
            credentials masked are the ordinary states and earn no badge.

            Absent for a command, and deliberately not shown as "scope exempt": a command
            makes no guarded call, so no scope decision was taken about it either way, and
            printing one would claim a check that never ran. Where its traffic can reach
            is stated in the editor instead, beside the setting that decides it. */}
        {!isCommand && (
          <span className="text-[10px] font-mono">
            <span className={run.requireScope ? 'text-content-muted' : 'text-semantic-warning'}>
              scope {run.requireScope ? 'required' : 'exempt'}
            </span>
            {run.credentials && <span className="text-semantic-warning"> · credentials visible</span>}
          </span>
        )}

        <button onClick={onClose} className="ml-auto text-content-muted hover:text-content-primary" aria-label="Dismiss">
          <X size={13} strokeWidth={2} />
        </button>
      </div>
      <div className="p-3 space-y-2 text-[11px]">
        {r.err && <pre className="font-mono whitespace-pre-wrap text-semantic-error">{r.err}</pre>}
        {r.logs && r.logs.length > 0 && (
          <div className="font-mono bg-surface-input rounded p-2">
            {/* For a command these lines are its stderr, which is where a tool writes its
                running commentary — the same place a script's console output goes. */}
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

        {cmd ? (
          <>
            {cmd.text !== '' && (
              <pre className="font-mono whitespace-pre-wrap bg-surface-input rounded p-2 overflow-x-auto">
                {cmd.binary ? '(binary output, base64)\n' : ''}
                {cmd.text}
              </pre>
            )}
            {cmd.artifacts && cmd.artifacts.length > 0 && (
              <div className="space-y-0.5">
                <div className="text-content-muted">Files this command wrote</div>
                {cmd.artifacts.map((a) => (
                  <div key={a.name} className="flex items-center gap-1.5 font-mono">
                    {a.dropped ? (
                      /* Listed but gone: past the artifact budget and deleted. Saying so
                         beats omitting it, since the operator would otherwise conclude the
                         tool never wrote it. */
                      <span className="text-content-muted">
                        {a.name} · {bytes(a.bytes)} · dropped, over the artifact budget
                      </span>
                    ) : (
                      <a
                        href={api.runArtifactUrl(run.id, a.name)}
                        className="text-accent-secondary hover:underline inline-flex items-center gap-1"
                      >
                        <Download size={11} strokeWidth={2} />
                        {a.name}
                        <span className="text-content-muted">{bytes(a.bytes)}</span>
                      </a>
                    )}
                  </div>
                ))}
              </div>
            )}
          </>
        ) : (
          r.value !== undefined &&
          r.value !== null && (
            <pre className="font-mono whitespace-pre-wrap bg-surface-input rounded p-2 overflow-x-auto">
              {JSON.stringify(r.value, null, 2)}
            </pre>
          )
        )}
      </div>
    </div>
  )
}

/** Reads a command run's value, or null if it is not one.
 *
 *  Defensive because `value` is typed `unknown` and a run record can outlive the client
 *  that renders it: a shape this build does not recognize falls back to the JSON dump
 *  rather than rendering blank.
 */
function readCommandValue(value: unknown): CommandValue | null {
  if (!value || typeof value !== 'object') return null
  const v = value as Partial<CommandValue>
  if (typeof v.text !== 'string' || typeof v.exitCode !== 'number') return null
  return v as CommandValue
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}
