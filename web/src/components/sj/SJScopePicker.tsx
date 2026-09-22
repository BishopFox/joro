import { useMemo, useState } from 'react'
import { Check, Square } from 'lucide-react'
import type { SJOperation } from '../../lib/sjTypes'
import { type SJScope, scopeCount } from '../../stores/sjStore'
import { methodClass } from '../../lib/sjStatus'

/** The scope control for a run.
 *
 *  A plain select rather than a dropdown component: the choices are few and
 *  named, and the point is that the thing deciding what runs sits next to the
 *  button that runs it. "Custom…" opens a picker, which is the only way this UI
 *  offers to select in bulk — the checkbox-per-row it replaces had no select-all
 *  at all. */
export default function SJScopePicker({
  scope,
  ops,
  onChange,
  disabled,
}: {
  scope: SJScope
  ops: SJOperation[]
  onChange: (next: SJScope) => void
  disabled?: boolean
}) {
  const [picking, setPicking] = useState(false)

  const tags = useMemo(() => {
    const counts = new Map<string, number>()
    for (const op of ops) {
      for (const t of op.tags ?? []) counts.set(t, (counts.get(t) ?? 0) + 1)
    }
    return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [ops])

  const destructive = ops.filter((o) => o.destructive).length
  const value =
    scope.kind === 'tag' ? `tag:${scope.tag}` : scope.kind === 'custom' ? 'custom' : scope.kind

  return (
    <>
      <label className="flex items-center gap-1.5 text-xs text-content-muted">
        Scope
        <select
          value={value}
          disabled={disabled}
          onChange={(e) => {
            const v = e.target.value
            if (v === 'all') onChange({ kind: 'all' })
            else if (v === 'nonDestructive') onChange({ kind: 'nonDestructive' })
            else if (v.startsWith('tag:')) onChange({ kind: 'tag', tag: v.slice(4) })
            else setPicking(true)
          }}
          className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border disabled:opacity-50"
        >
          <option value="all">All operations ({ops.length})</option>
          {destructive > 0 && (
            <option value="nonDestructive">
              Non-destructive only ({ops.length - destructive})
            </option>
          )}
          {tags.map(([tag, n]) => (
            <option key={tag} value={`tag:${tag}`}>
              Tag: {tag} ({n})
            </option>
          ))}
          <option value="custom">
            {scope.kind === 'custom' ? `Custom (${scope.ids.length})…` : 'Custom…'}
          </option>
        </select>
      </label>

      {picking && (
        <OperationPicker
          ops={ops}
          initial={scope.kind === 'custom' ? scope.ids : []}
          onCancel={() => setPicking(false)}
          onConfirm={(ids) => {
            setPicking(false)
            onChange(ids.length > 0 ? { kind: 'custom', ids } : { kind: 'all' })
          }}
        />
      )}
    </>
  )
}

function OperationPicker({
  ops,
  initial,
  onCancel,
  onConfirm,
}: {
  ops: SJOperation[]
  initial: string[]
  onCancel: () => void
  onConfirm: (ids: string[]) => void
}) {
  const [picked, setPicked] = useState<Record<string, true>>(
    Object.fromEntries(initial.map((id) => [id, true as const]))
  )
  const [filter, setFilter] = useState('')

  const shown = useMemo(() => {
    const f = filter.toLowerCase()
    if (!f) return ops
    return ops.filter(
      (o) =>
        o.path.toLowerCase().includes(f) ||
        o.id.toLowerCase().includes(f) ||
        (o.summary ?? '').toLowerCase().includes(f)
    )
  }, [ops, filter])

  const shownIds = shown.map((o) => o.id)
  const allShownPicked = shownIds.length > 0 && shownIds.every((id) => picked[id])
  const count = Object.keys(picked).length

  function toggleAllShown() {
    const next = { ...picked }
    if (allShownPicked) for (const id of shownIds) delete next[id]
    else for (const id of shownIds) next[id] = true
    setPicked(next)
  }

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50"
      onMouseDown={onCancel}
    >
      <div
        className="flex flex-col w-full max-w-2xl h-[70vh] bg-surface-card border border-border rounded shadow-lg overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border">
          <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
            Choose operations
          </span>
          <span className="text-[10px] text-content-muted">{count} selected</span>
        </div>

        <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border">
          <input
            autoFocus
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter…"
            className="flex-1 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
          />
          <button
            onClick={toggleAllShown}
            className="flex items-center gap-1 px-2 py-1.5 rounded-sm text-xs bg-surface-input hover:bg-surface-hover text-content-secondary"
          >
            {allShownPicked ? <Square size={12} /> : <Check size={12} />}
            {allShownPicked ? 'None' : 'All'}
            {filter && ' shown'}
          </button>
        </div>

        <div className="flex-1 min-h-0 overflow-auto">
          {shown.map((o) => (
            <label
              key={o.id}
              className="flex items-center gap-2 px-3 py-1 text-xs cursor-pointer hover:bg-surface-hover"
            >
              <input
                type="checkbox"
                checked={!!picked[o.id]}
                onChange={(e) => {
                  const next = { ...picked }
                  if (e.target.checked) next[o.id] = true
                  else delete next[o.id]
                  setPicked(next)
                }}
              />
              <span className={`w-14 shrink-0 font-bold text-[10px] ${methodClass(o.method)}`}>
                {o.method}
              </span>
              <span className="font-mono truncate text-content-secondary">{o.path}</span>
              {o.destructive && (
                <span className="ml-auto text-[10px] text-semantic-warning shrink-0">destructive</span>
              )}
            </label>
          ))}
          {shown.length === 0 && (
            <div className="px-3 py-8 text-center text-xs text-content-muted">
              No operations match that filter.
            </div>
          )}
        </div>

        <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-t border-border">
          <button
            onClick={() => setPicked({})}
            className="text-xs text-content-secondary hover:text-content-primary"
          >
            Clear
          </button>
          <button
            onClick={onCancel}
            className="ml-auto px-3 py-1.5 rounded-sm text-xs bg-surface-input hover:bg-surface-hover text-content-secondary"
          >
            Cancel
          </button>
          <button
            onClick={() => onConfirm(Object.keys(picked))}
            className="px-3 py-1.5 rounded-sm text-xs bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold"
          >
            Use {count || 'all'}
          </button>
        </div>
      </div>
    </div>
  )
}

/** scopeLabel describes a scope in a sentence, for a run's status line. */
export function scopeLabel(scope: SJScope, ops: SJOperation[]): string {
  const n = scopeCount(scope, ops)
  switch (scope.kind) {
    case 'all':
      return `all ${n} operations`
    case 'nonDestructive':
      return `${n} non-destructive operations`
    case 'tag':
      return `${n} operations tagged ${scope.tag}`
    case 'custom':
      return `${n} selected operations`
  }
}
