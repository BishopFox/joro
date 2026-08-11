import { useCallback, useEffect, useState } from 'react'
import { ChevronDown, ChevronRight, Eye, KeyRound } from 'lucide-react'
import { api, type AuditEntry } from '../lib/api'
import { useToastStore } from '../stores/toastStore'

/**
 * Recent automation activity.
 *
 * Called "Activity" rather than "Audit log" on purpose: this is an in-memory,
 * unsigned, process-lifetime record that proves nothing to a third party, and
 * labelling it an audit log would overclaim. It records an argument digest rather
 * than the arguments, since arguments to a send carry credentials and payloads.
 */
export default function AutomationActivity() {
  const [open, setOpen] = useState(false)
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [filter, setFilter] = useState('')
  const addToast = useToastStore((s) => s.addToast)

  const load = useCallback(async () => {
    try {
      const d = await api.listAutomationAudit({ result: filter || undefined, limit: 100 })
      setEntries(d.entries ?? [])
    } catch {
      /* automation disabled; the parent already explains that */
    }
  }, [filter])

  useEffect(() => {
    if (open) load()
  }, [open, load])

  const chip = (v: string, label: string) => (
    <button
      key={v}
      onClick={() => setFilter(filter === v ? '' : v)}
      className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${
        filter === v ? 'border-accent text-accent' : 'border-border text-content-muted hover:text-content-primary'
      }`}
    >
      {label}
    </button>
  )

  return (
    <div className="bg-surface-card border border-border rounded">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs font-semibold text-content-muted uppercase tracking-wide"
      >
        {open ? <ChevronDown size={13} strokeWidth={2} /> : <ChevronRight size={13} strokeWidth={2} />}
        Activity
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-2">
          <div className="flex items-center gap-1.5">
            {chip('denied', 'Denied')}
            {chip('error', 'Errors')}
            <button onClick={load} className="text-[10px] text-accent-secondary hover:underline ml-1">
              Refresh
            </button>
            <button
              onClick={async () => {
                try {
                  await api.clearAutomationAudit()
                  setEntries([])
                } catch (e) {
                  addToast(String(e), 'error')
                }
              }}
              className="text-[10px] text-content-muted hover:underline ml-auto"
            >
              Clear
            </button>
          </div>

          {entries.length === 0 ? (
            <p className="text-[11px] text-content-muted italic py-3 text-center">No activity recorded.</p>
          ) : (
            <div className="max-h-72 overflow-y-auto font-mono text-[10px] leading-relaxed">
              {entries.map((e) => (
                <div
                  key={e.seq}
                  className={`flex gap-2 py-0.5 border-b border-border-subtle last:border-0 ${
                    e.result === 'denied' ? 'text-semantic-warning' : e.result === 'error' ? 'text-semantic-error' : ''
                  }`}
                >
                  <span className="text-content-muted shrink-0">{new Date(e.at).toLocaleTimeString()}</span>
                  <span className="shrink-0 w-24 truncate">{e.tokenName}</span>
                  <span className="shrink-0 w-32 truncate">{e.capability}</span>
                  <span className="shrink-0 w-6 inline-flex gap-0.5">
                    {e.privileged && (
                      <span className="inline-flex" title="Command execution or C2">
                        <KeyRound size={10} strokeWidth={2} className="text-semantic-error" aria-hidden="true" />
                      </span>
                    )}
                    {e.credentials && (
                      <span className="inline-flex" title="Could return unmasked credential headers">
                        <Eye size={10} strokeWidth={2} className="text-semantic-warning" aria-hidden="true" />
                      </span>
                    )}
                  </span>
                  <span className="shrink-0 w-14">{e.code || e.result}</span>
                  <span className="text-content-muted truncate">
                    {/* A mutation has no target, so without `change` these rows would
                        read as a bare capability name — the operator could see that an
                        agent edited the proxy but not what it did. */}
                    {e.change ? (
                      <span className="text-semantic-special" title={e.change}>
                        {e.change}{' '}
                      </span>
                    ) : (
                      e.targetHost ? `${e.targetMethod ?? ''} ${e.targetHost}${e.targetPath ?? ''} ` : ''
                    )}
                    {e.outputBytes > 0 ? `${e.outputBytes}B ` : ''}
                    {e.durationMs}ms
                    {e.errMsg ? ` — ${e.errMsg}` : ''}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
