import { useCallback, useEffect, useState } from 'react'
import { ChevronDown, ChevronRight, X } from 'lucide-react'
import { api, type ScriptRun } from '../lib/api'
import { useToastStore } from '../stores/toastStore'

/**
 * Recent sandboxed script runs.
 *
 * The reason this exists alongside Activity rather than inside it: Activity records one
 * row per capability call, and a script turns one grant into many of those. This is the
 * parent record — what ran, how it ended, and the source itself.
 *
 * Keeping the source is deliberate. For an installed automation a hash would do, since
 * there is an artifact to compare against; a one-shot script submitted over MCP has no
 * artifact, so a hash would leave an operator with a fingerprint of code nobody kept.
 * On a tool that sends traffic to a client's systems, being able to read exactly what an
 * agent ran is the point.
 *
 * Polled on expand rather than streamed, following Activity: a run event per invocation
 * would be a firehose the agent controls, on the channel that also carries proxy traffic.
 */
export default function ScriptRuns() {
  const [open, setOpen] = useState(false)
  const [runs, setRuns] = useState<ScriptRun[]>([])
  const [available, setAvailable] = useState<boolean | null>(null)
  const [selected, setSelected] = useState<ScriptRun | null>(null)
  const addToast = useToastStore((s) => s.addToast)

  const load = useCallback(async () => {
    try {
      const d = await api.listScriptRuns({ limit: 50 })
      setRuns(d.runs ?? [])
      setAvailable(true)
    } catch {
      // A 404 means Joro was started without --automation-scripting, which is a
      // deployment choice rather than a failure worth a toast.
      setAvailable(false)
    }
  }, [])

  useEffect(() => {
    if (open) load()
  }, [open, load])

  const openRun = async (id: string) => {
    try {
      setSelected(await api.getScriptRun(id))
    } catch (e) {
      addToast(String(e), 'error')
    }
  }

  return (
    <div className="bg-surface-card border border-border rounded">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs font-semibold text-content-muted uppercase tracking-wide"
      >
        {open ? <ChevronDown size={13} strokeWidth={2} /> : <ChevronRight size={13} strokeWidth={2} />}
        Script runs
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-2">
          {available === false ? (
            <p className="text-[11px] text-content-muted py-2">
              Script automation is off. Start Joro with <code className="font-mono">--automation-scripting</code> to
              expose <code className="font-mono">script_run</code>, which lets a granted token execute JavaScript
              against Joro&rsquo;s automation SDK in a sandboxed worker process.
            </p>
          ) : (
            <>
              <div className="flex items-center gap-2">
                <button onClick={load} className="text-[10px] text-accent-secondary hover:underline">
                  Refresh
                </button>
                <button
                  onClick={async () => {
                    try {
                      await api.clearScriptRuns()
                      setRuns([])
                    } catch (e) {
                      addToast(String(e), 'error')
                    }
                  }}
                  className="text-[10px] text-content-muted hover:underline ml-auto"
                >
                  Clear
                </button>
              </div>

              {runs.length === 0 ? (
                <p className="text-[11px] text-content-muted italic py-3 text-center">No script runs recorded.</p>
              ) : (
                <div className="max-h-72 overflow-y-auto font-mono text-[10px] leading-relaxed">
                  {runs.map((r) => (
                    <button
                      key={r.id}
                      onClick={() => openRun(r.id)}
                      className={`w-full text-left flex gap-2 py-0.5 border-b border-border-subtle last:border-0 hover:bg-surface-hover ${
                        r.result.reason === 'success' ? '' : 'text-semantic-warning'
                      }`}
                    >
                      <span className="text-content-muted shrink-0">
                        {new Date(r.startedAt).toLocaleTimeString()}
                      </span>
                      <span className="shrink-0 w-24 truncate">{r.tokenName}</span>
                      <span className="shrink-0 w-32 truncate">{r.result.reason}</span>
                      <span className="shrink-0 w-20">
                        {r.result.calls} call{r.result.calls === 1 ? '' : 's'}
                        {r.result.sendCalls > 0 ? ` (${r.result.sendCalls}s)` : ''}
                      </span>
                      <span className="shrink-0 w-14">{r.durationMs}ms</span>
                      <span className="text-content-muted truncate">{r.result.err || r.id}</span>
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {selected && <RunDetail run={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function RunDetail({ run, onClose }: { run: ScriptRun; onClose: () => void }) {
  const r = run.result
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-surface-card border border-border rounded-lg shadow-lg w-full max-w-3xl max-h-[85vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-content-primary font-mono truncate">{run.id}</h3>
            <p className="text-[11px] text-content-muted">
              {r.reason} &middot; {run.tokenName} &middot; {run.trigger} &middot; {run.bundle} &middot; {run.durationMs}ms
              &middot; {r.calls} SDK call{r.calls === 1 ? '' : 's'}
              {r.sendCalls > 0 ? ` (${r.sendCalls} sending)` : ''}
            </p>
          </div>
          <button onClick={onClose} className="ml-auto text-content-muted hover:text-content-primary" aria-label="Close">
            <X size={16} strokeWidth={2} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3 text-[11px]">
          {r.err && (
            <section>
              <h4 className="text-content-muted uppercase tracking-wide text-[10px] mb-1">Error</h4>
              <pre className="font-mono whitespace-pre-wrap text-semantic-error">{r.err}</pre>
            </section>
          )}

          <section>
            <h4 className="text-content-muted uppercase tracking-wide text-[10px] mb-1">
              Source &middot; sha256:{run.sourceHash.slice(0, 16)}
            </h4>
            <pre className="font-mono whitespace-pre-wrap bg-surface-input rounded p-2 overflow-x-auto">
              {run.source || '(not retained)'}
            </pre>
          </section>

          {r.logs && r.logs.length > 0 && (
            <section>
              <h4 className="text-content-muted uppercase tracking-wide text-[10px] mb-1">
                Console {r.logsTruncated ? '(truncated)' : ''}
              </h4>
              <div className="font-mono bg-surface-input rounded p-2 max-h-48 overflow-y-auto">
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
              </div>
            </section>
          )}

          {r.value !== undefined && r.value !== null && (
            <section>
              <h4 className="text-content-muted uppercase tracking-wide text-[10px] mb-1">Result</h4>
              <pre className="font-mono whitespace-pre-wrap bg-surface-input rounded p-2 overflow-x-auto">
                {JSON.stringify(r.value, null, 2)}
              </pre>
            </section>
          )}
        </div>
      </div>
    </div>
  )
}
