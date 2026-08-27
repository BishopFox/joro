import { useCallback, useEffect, useMemo, useState } from 'react'
import { Plus } from 'lucide-react'
import { api, type Trigger, type TriggerFieldSpec } from '../../lib/api'
import { useToastStore } from '../../stores/toastStore'
import TriggerEditor from './TriggerEditor'

/**
 * Settings -> Automation -> Triggers: what an automation can be pointed at.
 *
 * Joro's own events are listed alongside the operator's custom triggers, one flat list with
 * an origin pill, which is how Detect lists its rules — the same problem, already solved.
 * A built-in opens read-only with Clone to custom; a custom one opens in the editor.
 *
 * The list is the source of truth for the editor, which is keyed by id rather than handed a
 * captured object, so a save is visible the moment the refetch lands.
 */

type Origin = 'all' | 'builtin' | 'custom'

const chip = (active: boolean) =>
  `px-2 py-0.5 rounded-sm text-[10px] font-semibold ${
    active ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
  }`

export default function TriggersPanel({ openEditor }: { openEditor?: (id: string) => void }) {
  const addToast = useToastStore((s) => s.addToast)

  const [triggers, setTriggers] = useState<Trigger[]>([])
  const [fields, setFields] = useState<Record<string, TriggerFieldSpec[]>>({})
  const [events, setEvents] = useState<string[]>([])
  const [valueLen, setValueLen] = useState(512)
  const [unavailable, setUnavailable] = useState<string | null>(null)

  const [editingId, setEditingId] = useState<string | null>(null)
  const [creating, setCreating] = useState<Trigger | null>(null)
  const [origin, setOrigin] = useState<Origin>('all')
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    try {
      const d = await api.listTriggers()
      setTriggers(d.triggers ?? [])
      setFields(d.fields ?? {})
      setEvents(d.events ?? [])
      setValueLen(d.limits?.valueLen ?? 512)
      setUnavailable(null)
    } catch (e) {
      setUnavailable(String(e instanceof Error ? e.message : e))
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const visible = useMemo(() => {
    const needle = search.toLowerCase()
    return triggers.filter((t) => {
      if (origin === 'builtin' && !t.builtin) return false
      if (origin === 'custom' && t.builtin) return false
      if (
        needle &&
        !t.name.toLowerCase().includes(needle) &&
        !t.id.toLowerCase().includes(needle) &&
        !(t.description ?? '').toLowerCase().includes(needle)
      ) {
        return false
      }
      return true
    })
  }, [triggers, search, origin])

  /** Resolved from the live list rather than captured on open, so a save shows immediately
   *  after the refetch. */
  const editing = creating ?? triggers.find((t) => t.id === editingId) ?? null

  const startNew = async () => {
    const on = events.find((e) => fields[e]) ?? 'request.captured'
    try {
      const seed = await api.seedTrigger(on)
      setEditingId(null)
      setCreating({ id: '', name: '', on, graph: seed.graph, usedBy: [] })
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    }
  }

  if (unavailable) {
    return (
      <div className="flex-1 overflow-auto p-5">
        <h3 className="text-sm font-semibold text-content-primary mb-2">Triggers</h3>
        <p className="text-[11px] text-content-secondary max-w-xl leading-relaxed">{unavailable}</p>
      </div>
    )
  }

  if (editing) {
    return (
      <TriggerEditor
        draft={editing}
        fields={fields}
        events={events}
        valueLen={valueLen}
        onClose={() => {
          setEditingId(null)
          setCreating(null)
        }}
        onSaved={load}
      />
    )
  }

  return (
    <div className="flex-1 overflow-auto p-5 space-y-3">
      <div className="flex items-start gap-2">
        <div>
          <h3 className="text-sm font-semibold text-content-primary">Triggers</h3>
          <p className="text-[11px] text-content-muted max-w-2xl leading-relaxed">
            What an automation can be pointed at. Joro&rsquo;s own events fire every time they
            happen; a custom trigger adds conditions, so it fires on some of them. Point an
            automation at one in its editor, under Automations.
          </p>
        </div>
        <button
          onClick={startNew}
          className="ml-auto shrink-0 inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold"
        >
          <Plus size={11} strokeWidth={2.4} aria-hidden="true" />
          New Trigger
        </button>
      </div>

      <div className="flex items-center gap-2">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search triggers"
          className="bg-surface-input text-xs px-2 py-1 rounded-sm border border-border text-content-primary flex-1 max-w-xs"
        />
        <div className="flex items-center gap-0.5">
          {(['all', 'builtin', 'custom'] as const).map((k) => (
            <button key={k} onClick={() => setOrigin(k)} className={chip(origin === k)}>
              {k === 'all' ? 'All' : k === 'builtin' ? 'Built-in' : 'Custom'}
            </button>
          ))}
        </div>
      </div>

      <table className="w-full text-[11px]">
        <thead>
          <tr className="text-content-muted uppercase tracking-wide text-[10px] text-left">
            <th className="pb-1 font-semibold">Trigger</th>
            <th className="pb-1 font-semibold w-44">Event</th>
            <th className="pb-1 font-semibold w-20">Origin</th>
            <th className="pb-1 font-semibold w-40">Used by</th>
          </tr>
        </thead>
        <tbody>
          {visible.length === 0 && (
            <tr>
              <td colSpan={4} className="py-8 text-center text-content-muted italic">
                No triggers match the current filters.
              </td>
            </tr>
          )}
          {visible.map((t) => (
            <tr
              key={t.id}
              onClick={() => {
                setCreating(null)
                setEditingId(t.id)
              }}
              className="border-t border-border-subtle cursor-pointer hover:bg-surface-hover align-top"
            >
              <td className="py-1.5 pr-2">
                <div className="text-content-primary font-semibold">{t.name}</div>
                {t.description && (
                  <div className="text-[10px] text-content-muted">{t.description}</div>
                )}
                {t.problem && (
                  <div className="text-[10px] text-semantic-error leading-snug max-w-lg">
                    {t.problem}
                  </div>
                )}
              </td>
              <td className="py-1.5 pr-2 font-mono text-[10px] text-content-secondary">{t.on}</td>
              <td className="py-1.5 pr-2">
                <span
                  className={`inline-block px-1 py-px rounded-sm bg-surface-input text-[10px] font-semibold uppercase tracking-wide ${
                    t.builtin ? 'text-accent-secondary' : 'text-accent-tertiary'
                  }`}
                >
                  {t.builtin ? 'Built-in' : 'Custom'}
                </span>
              </td>
              <td className="py-1.5 pr-2 text-content-secondary">
                {t.usedBy.length === 0 ? (
                  <span className="text-content-muted">&mdash;</span>
                ) : (
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      openEditor?.(t.usedBy[0])
                    }}
                    className="hover:text-accent-secondary text-left"
                    title={t.usedBy.join(', ')}
                  >
                    {t.usedBy.length === 1 ? t.usedBy[0] : `${t.usedBy.length} automations`}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
