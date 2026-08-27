import { useCallback, useEffect, useState } from 'react'
import { FlaskConical, Save, Trash2, X } from 'lucide-react'
import { api, type Trigger, type TriggerFieldSpec, type TriggerTest } from '../../lib/api'
import { useToastStore } from '../../stores/toastStore'
import TabButton from '../TabButton'
import TriggerBuilder from './TriggerBuilder'
import TriggerCanvas from './TriggerCanvas'

/**
 * The trigger editor: identity at the top, the graph in the middle, a dry run at the
 * bottom.
 *
 * The canvas is the default view because the graph is what a trigger is; the builder is
 * the shortcut for the common flat case. Both edit the same document.
 *
 * A built-in opens read-only — it is the raw event and there is nothing to configure —
 * with Clone to custom, which is the same trick DetectRuleModal uses: clear the id and
 * the save path becomes a create.
 */

type View = 'graph' | 'builder'

const inputCls =
  'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border text-content-primary w-full'

const BLANK: Trigger = { id: '', name: '', on: 'request.captured', graph: { nodes: [], edges: [] }, usedBy: [] }

export default function TriggerEditor({
  draft,
  fields,
  events,
  valueLen,
  onClose,
  onSaved,
  onDeleted,
  onDirtyChange,
}: {
  /** The trigger being edited or created. A built-in arrives with builtin set. Null while
   *  the catalog has not caught up with a selection, which a refetch resolves. */
  draft: Trigger | null
  fields: Record<string, TriggerFieldSpec[]>
  events: string[]
  valueLen: number
  onClose: () => void
  /** Called after a successful write, with the stored id — which a create only has once it
   *  lands, and which the rail adopts so a second Save updates rather than recreating. */
  onSaved: (id: string) => void | Promise<void>
  onDeleted?: () => void | Promise<void>
  /** Reported on every edit so the shell can ask before throwing the buffer away. */
  onDirtyChange?: (dirty: boolean) => void
}) {
  const addToast = useToastStore((s) => s.addToast)
  const [t, setT] = useState<Trigger>(draft ?? BLANK)
  const [view, setView] = useState<View>('graph')
  const [busy, setBusy] = useState(false)
  const [test, setTest] = useState<TriggerTest | null>(null)
  // What the buffer looked like when it was last in step with the server. Compared rather
  // than tracked with a flag so that typing a change and undoing it leaves the editor clean.
  const [pristine, setPristine] = useState(() => JSON.stringify(draft ?? BLANK))
  // Whether this trigger has ever been stored. Held rather than derived from t.id, which the
  // name field writes to on the first keystroke — deriving it would freeze the id after one
  // character. Clone sets it, which is what makes the clone save as a create.
  const [creating, setCreating] = useState(!draft?.id)
  const readOnly = !!t.builtin

  useEffect(() => {
    if (!draft) return
    setT(draft)
    setPristine(JSON.stringify(draft))
    setCreating(!draft.id)
    setTest(null)
  }, [draft])

  const dirty = !readOnly && JSON.stringify(t) !== pristine
  useEffect(() => {
    onDirtyChange?.(dirty)
  }, [dirty, onDirtyChange])
  // Leaving the editor cannot leave a stale dirty flag behind on the shell.
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const patch = (p: Partial<Trigger>) => setT((cur) => ({ ...cur, ...p }))

  /** Changing the event changes the vocabulary, so the graph is reseeded rather than left
   *  holding conditions on fields the new event does not carry — which would validate as
   *  an error the operator did not make. */
  const setEvent = async (on: string) => {
    try {
      const seed = await api.seedTrigger(on)
      patch({ on, graph: seed.graph })
      setTest(null)
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    }
  }

  const runTest = useCallback(async () => {
    setBusy(true)
    try {
      setTest(await api.testTrigger(t))
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    } finally {
      setBusy(false)
    }
  }, [t, addToast])

  const save = async () => {
    setBusy(true)
    try {
      const saved = creating ? await api.createTrigger(t) : await api.updateTrigger(t.id, t)
      // Take the stored trigger back rather than keeping what was sent: Normalize lowercases
      // the id and the ops, and usedBy/problem are computed on the way out. Without this the
      // editor stays dirty against a copy the server already rewrote.
      setT(saved)
      setPristine(JSON.stringify(saved))
      setCreating(false)
      await onSaved(saved.id)
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    setBusy(true)
    try {
      await api.deleteTrigger(t.id)
      setPristine(JSON.stringify(t))
      await (onDeleted ? onDeleted() : onClose())
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    } finally {
      setBusy(false)
    }
  }

  const eventFields = fields[t.on] ?? []

  // The rail selects by id and the catalog refetches behind it, so there is a tick where the
  // selection names a trigger the list has not produced yet.
  if (!draft) {
    return (
      <div className="flex-1 overflow-auto p-5 text-[11px] text-content-muted italic">
        Loading trigger&hellip;
      </div>
    )
  }

  return (
    <div className="flex flex-col flex-1 min-h-0 p-5 gap-3">
      <div className="flex items-start gap-2">
        <div className="flex-1 grid grid-cols-[auto_1fr_auto_1fr] gap-2 items-center max-w-3xl">
          <label className="text-[11px] text-content-muted">
            Name
            {dirty && (
              <span className="ml-1 text-accent-tertiary" title="Unsaved changes">
                &bull;
              </span>
            )}
          </label>
          <input
            className={inputCls}
            value={t.name}
            disabled={readOnly}
            placeholder="Example responses"
            onChange={(e) => {
              // The id is the reference automations hold, so it is derived from the name
              // once and then frozen — renaming a trigger later must not unhook them.
              const name = e.target.value
              patch(creating ? { name, id: slug(name) } : { name })
            }}
          />
          <label className="text-[11px] text-content-muted">Event</label>
          <select
            className={inputCls}
            value={t.on}
            disabled={readOnly || !creating}
            onChange={(e) => setEvent(e.target.value)}
            title={creating ? undefined : 'The event is fixed once a trigger is saved'}
          >
            {events
              .filter((e) => fields[e])
              .map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
          </select>

          <label className="text-[11px] text-content-muted">Description</label>
          <input
            className={`${inputCls} col-span-3`}
            value={t.description ?? ''}
            disabled={readOnly}
            placeholder="What this is for"
            onChange={(e) => patch({ description: e.target.value })}
          />
        </div>

        <div className="flex items-center gap-1.5">
          {readOnly ? (
            <button
              onClick={() => {
                setCreating(true)
                setT({
                  ...t,
                  id: '',
                  name: `${t.name} (copy)`,
                  builtin: false,
                  usedBy: [],
                  graph: t.graph.nodes.length ? t.graph : { nodes: [], edges: [] },
                })
              }}
              className="text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary font-semibold"
              title="Built-in triggers cannot be edited. Cloning makes an editable copy."
            >
              Clone to custom
            </button>
          ) : (
            <>
              <button
                onClick={runTest}
                disabled={busy}
                className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-50"
              >
                <FlaskConical size={11} strokeWidth={2} aria-hidden="true" />
                Test
              </button>
              <button
                onClick={save}
                disabled={busy || !t.name.trim()}
                className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-50"
              >
                <Save size={11} strokeWidth={2.4} aria-hidden="true" />
                {creating ? 'Create' : 'Save'}
              </button>
              {!creating && (
                <button
                  onClick={remove}
                  disabled={busy || t.usedBy.length > 0}
                  title={
                    t.usedBy.length > 0
                      ? `Used by ${t.usedBy.join(', ')}`
                      : 'Delete this trigger'
                  }
                  className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-semantic-error disabled:opacity-40"
                >
                  <Trash2 size={11} strokeWidth={2} aria-hidden="true" />
                </button>
              )}
            </>
          )}
          <button
            onClick={onClose}
            className="text-content-muted hover:text-content-primary"
            aria-label="Close"
          >
            <X size={15} strokeWidth={2} />
          </button>
        </div>
      </div>

      {t.usedBy.length > 0 && (
        <p className="text-[10px] text-semantic-warning">
          Used by {t.usedBy.join(', ')} &mdash; a change here changes all of them.
        </p>
      )}
      {t.problem && <p className="text-[10px] text-semantic-error">{t.problem}</p>}

      {readOnly ? (
        <p className="text-[11px] text-content-secondary max-w-2xl leading-relaxed">
          This is one of Joro&rsquo;s events, listed so an automation can name it directly. It has
          no conditions, so it fires every time the event happens. Clone it to build one that
          fires on some of them.
        </p>
      ) : (
        <>
          <div className="flex items-center gap-0.5 border-b border-border">
            <TabButton active={view === 'graph'} onClick={() => setView('graph')}>
              Graph
            </TabButton>
            <TabButton active={view === 'builder'} onClick={() => setView('builder')}>
              Builder
            </TabButton>
          </div>

          {view === 'graph' ? (
            <TriggerCanvas
              graph={t.graph}
              fields={eventFields}
              valueLen={valueLen}
              on={t.on}
              onChange={(graph) => patch({ graph })}
            />
          ) : (
            <div className="flex-1 min-h-0 overflow-auto">
              <TriggerBuilder
                graph={t.graph}
                fields={eventFields}
                valueLen={valueLen}
                onChange={(graph) => patch({ graph })}
                onOpenCanvas={() => setView('graph')}
              />
            </div>
          )}

          {test && <TestResult test={test} />}
        </>
      )}
    </div>
  )
}

/** A name turned into an id: lowercase, hyphenated, and stripped of everything the server
 *  refuses. */
function slug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
}

/** The dry run's outcome.
 *
 *  Scanned is shown beside the count because the pair is the answer: three of the last
 *  fifty says something a bare "3" does not. */
function TestResult({ test }: { test: TriggerTest }) {
  if (!test.valid) {
    return (
      <div className="rounded-sm border border-semantic-error bg-surface-card p-2 shrink-0">
        <div className="text-[11px] text-semantic-error font-semibold mb-0.5">
          This trigger will not compile
        </div>
        <div className="text-[10px] font-mono text-content-secondary break-all">{test.error}</div>
      </div>
    )
  }

  return (
    <div className="rounded-sm border border-border bg-surface-card p-2 space-y-1.5 shrink-0 max-h-56 overflow-auto">
      {test.orphans && test.orphans.length > 0 && (
        <div className="text-[10px] text-semantic-warning">
          Not connected to Run, so they do nothing: {test.orphans.join(', ')}
        </div>
      )}
      {!test.replayable ? (
        <div className="text-[11px] text-content-secondary">
          Valid. There is no captured history of this event to try it against, so nothing was
          replayed.
        </div>
      ) : (
        <>
          <div className="text-[11px] text-content-secondary">
            Matched <span className="text-content-primary font-semibold">{test.count}</span> of the
            last {test.scanned} captured request{test.scanned === 1 ? '' : 's'}.
            {test.count === 0 && test.scanned > 0 && (
              <span className="text-semantic-warning">
                {' '}
                Nothing matched &mdash; note that a body condition never matches a binary or
                brotli-encoded response.
              </span>
            )}
          </div>
          {test.matched.length > 0 && (
            <table className="w-full text-[10px] font-mono">
              <tbody>
                {test.matched.map((m) => (
                  <tr key={m.seq} className="border-t border-border-subtle">
                    <td className="py-0.5 pr-2 text-content-muted">{m.seq}</td>
                    <td className="py-0.5 pr-2 text-content-secondary">{m.method}</td>
                    <td className="py-0.5 pr-2 text-content-secondary">{m.status}</td>
                    <td className="py-0.5 text-content-secondary break-all">{m.url}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  )
}
