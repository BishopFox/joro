import { useMemo } from 'react'
import { AlertTriangle } from 'lucide-react'
import type { Capability } from '../lib/api'

type Props = {
  capabilities: Capability[]
  selected: string[]
  onChange: (next: string[]) => void
  /** Capability IDs that exist but this token has never been offered, marked so an
   *  operator reviewing an old token can see what is new. */
  highlight?: string[]
}

const CLASS_LABELS: Record<string, string> = {
  history: 'History',
  sitemap: 'Site map',
  scope: 'Scope',
  findings: 'Detection findings',
  notes: 'Notes',
  http: 'HTTP tools',
}

/**
 * The grant picker.
 *
 * Class checkboxes are a convenience that check boxes; they never store a
 * pattern. Grants are always a fully expanded list of capability IDs, so
 * upgrading Joro can never widen an existing token — a "http.*" grant written
 * today would silently pick up a send-capable capability shipped later, and this
 * tool's capability surface will grow precisely in that direction.
 *
 * Nothing is selected by default.
 */
export default function GrantPicker({ capabilities, selected, onChange, highlight = [] }: Props) {
  const byClass = useMemo(() => {
    const groups = new Map<string, Capability[]>()
    for (const c of capabilities) {
      const list = groups.get(c.class) ?? []
      list.push(c)
      groups.set(c.class, list)
    }
    return [...groups.entries()]
  }, [capabilities])

  const sel = new Set(selected)
  const isNew = new Set(highlight)

  const toggle = (id: string) => {
    const next = new Set(sel)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    onChange([...next].sort())
  }

  const toggleClass = (caps: Capability[], on: boolean) => {
    const next = new Set(sel)
    for (const c of caps) {
      if (on) next.add(c.id)
      else next.delete(c.id)
    }
    onChange([...next].sort())
  }

  const preset = (fn: (c: Capability) => boolean) =>
    onChange(capabilities.filter(fn).map((c) => c.id).sort())

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-[11px]">
        <span className="text-content-muted">Presets:</span>
        <button
          type="button"
          onClick={() => preset((c) => !c.mutating && !c.sendsTraffic)}
          className="text-accent-secondary hover:underline"
        >
          Read-only
        </button>
        <button
          type="button"
          onClick={() => preset(() => true)}
          className="text-accent-secondary hover:underline"
        >
          Read + send
        </button>
        <button type="button" onClick={() => onChange([])} className="text-content-muted hover:underline">
          Clear
        </button>
        <span className="ml-auto text-content-muted">{sel.size} selected</span>
      </div>

      <div className="max-h-72 overflow-y-auto border border-border rounded divide-y divide-border-subtle">
        {byClass.map(([cls, caps]) => {
          const all = caps.every((c) => sel.has(c.id))
          const some = !all && caps.some((c) => sel.has(c.id))
          const sends = caps.some((c) => c.sendsTraffic)
          return (
            <div key={cls} className="p-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={all}
                  ref={(el) => {
                    if (el) el.indeterminate = some
                  }}
                  onChange={() => toggleClass(caps, !all)}
                />
                <span className="text-xs font-semibold">{CLASS_LABELS[cls] ?? cls}</span>
                {sends && (
                  <span className="text-[10px] text-semantic-warning inline-flex items-center gap-1">
                    <AlertTriangle size={11} strokeWidth={2} aria-hidden="true" />
                    these emit traffic to targets
                  </span>
                )}
              </label>

              <div className="mt-1 ml-5 space-y-1">
                {caps.map((c) => (
                  <label key={c.id} className="flex items-start gap-2 cursor-pointer group">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={sel.has(c.id)}
                      onChange={() => toggle(c.id)}
                    />
                    <span className="min-w-0">
                      <span className="text-xs flex items-center gap-1.5">
                        <code className="font-mono text-[11px]">{c.toolName}</code>
                        {c.sendsTraffic && (
                          <AlertTriangle size={11} strokeWidth={2} className="text-semantic-warning shrink-0" aria-hidden="true" />
                        )}
                        {isNew.has(c.id) && <span className="w-1.5 h-1.5 rounded-full bg-accent shrink-0" title="New since this token was last reviewed" />}
                      </span>
                      <span className="block text-[10px] text-content-muted leading-snug">{c.title}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
