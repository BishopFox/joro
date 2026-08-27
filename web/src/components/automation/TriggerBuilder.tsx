import { Plus, Trash2 } from 'lucide-react'
import type { TriggerFieldSpec, TriggerGraph, TriggerNode } from '../../lib/api'
import { fromFlat, nextNodeId, patchNode, toFlat } from '../../lib/triggerGraph'
import TriggerConditionFields from './TriggerConditionFields'

/**
 * The structured view: the same graph as a list of conditions combined by one mode.
 *
 * It reads and writes the graph directly, so switching tabs converts nothing. What it
 * cannot show, it says so about rather than flattening: a graph with nesting, or with a
 * condition feeding two branches, has no honest flat reading, and pretending otherwise
 * would quietly discard the structure the operator built on the canvas.
 */
export default function TriggerBuilder({
  graph,
  fields,
  valueLen,
  onChange,
  onOpenCanvas,
}: {
  graph: TriggerGraph
  fields: TriggerFieldSpec[]
  valueLen: number
  onChange: (g: TriggerGraph) => void
  onOpenCanvas: () => void
}) {
  const flat = toFlat(graph)

  if (!flat) {
    return (
      <div className="rounded-sm border border-border bg-surface-card p-3 space-y-1.5">
        <p className="text-[11px] text-content-secondary">
          This trigger&rsquo;s logic is more than one level deep, so it cannot be shown as a
          flat list without changing what it means.
        </p>
        <button onClick={onOpenCanvas} className="text-[11px] text-accent-secondary hover:underline">
          Edit it on the canvas
        </button>
      </div>
    )
  }

  const set = (view: typeof flat) => onChange(fromFlat(graph, view))

  const addCondition = () => {
    if (fields.length === 0) return
    const id = nextNodeId(graph, 'condition')
    const node: TriggerNode = {
      id,
      type: 'condition',
      x: 0,
      y: flat.conditions.length * 120,
      field: fields[0].name,
      op: fields[0].ops[0],
      value: fields[0].values?.[0] ?? '',
    }
    set({ ...flat, conditions: [...flat.conditions, node] })
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1.5 text-[11px] text-content-secondary">
        Fire when
        <select
          value={flat.mode}
          onChange={(e) => set({ ...flat, mode: e.target.value as 'all' | 'any' })}
          disabled={flat.conditions.length < 2}
          className="bg-surface-input text-[11px] px-1.5 py-1 rounded-sm border border-border text-content-primary disabled:opacity-50"
        >
          <option value="all">all</option>
          <option value="any">any</option>
        </select>
        of these match.
      </div>

      {flat.conditions.length === 0 && (
        <p className="text-[10px] text-content-muted italic">
          No conditions, so this fires on every one of these events.
        </p>
      )}

      {flat.conditions.map((c) => (
        <div
          key={c.id}
          className="rounded-sm border border-border bg-surface-card p-2 flex items-center gap-1"
        >
          <div className="flex-1 min-w-0">
            <TriggerConditionFields
              fields={fields}
              node={c}
              valueLen={valueLen}
              onChange={(p) => onChange(patchNode(graph, c.id, p))}
            />
          </div>
          <button
            onClick={() =>
              set({ ...flat, conditions: flat.conditions.filter((x) => x.id !== c.id) })
            }
            className="text-content-muted hover:text-semantic-error shrink-0"
            title="Remove this condition"
          >
            <Trash2 size={11} strokeWidth={2} aria-hidden="true" />
          </button>
        </div>
      ))}

      <button
        onClick={addCondition}
        disabled={fields.length === 0}
        className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-40"
      >
        <Plus size={11} strokeWidth={2.4} aria-hidden="true" />
        Condition
      </button>
    </div>
  )
}
