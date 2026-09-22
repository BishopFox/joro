import { forwardRef } from 'react'
import { ArrowDown, Flag, GripVertical, KeyRound, RotateCcw, X } from 'lucide-react'
import { methodClass } from '../../lib/chainStatus'
import { requestTarget, stepTitle } from '../../lib/chainMap'
import type { ChainBinding, ChainStep } from '../../lib/chainTypes'

/** How many dependency chips a row shows before collapsing the rest. */
const MAX_CHIPS = 3

export interface StepRowProps {
  step: ChainStep
  index: number
  total: number
  selected: boolean
  goal: boolean
  /** True while this row is the one being dragged. */
  lifted: boolean
  /** Rows the pointer is near, and peers of the hovered row, light up. */
  highlighted: boolean
  compact: boolean
  /** Bindings this step consumes and produces, with the peer's row number. */
  consumes: { binding: ChainBinding; peer: number }[]
  produces: { binding: ChainBinding; peer: number }[]
  onSelect: () => void
  onToggleSetup: () => void
  onSetGoal: () => void
  onRemove: () => void
  onRemoveBinding: (id: string) => void
  onSelectBinding: (b: ChainBinding) => void
  onHoverBinding: (id: string | null) => void
  onGripDown: (e: React.PointerEvent) => void
  onGripKey: (e: React.KeyboardEvent) => void
}

/** One step in the map.
 *
 *  A row, not a node: position is the execution order and the gutter arcs are
 *  the data flow, so nothing here should look connectable. */
const ChainStepRow = forwardRef<HTMLLIElement, StepRowProps>(function ChainStepRow(
  {
    step, index, total, selected, goal, lifted, highlighted, compact,
    consumes, produces, onSelect, onToggleSetup, onSetGoal, onRemove,
    onRemoveBinding, onSelectBinding, onHoverBinding, onGripDown, onGripKey,
  },
  ref,
) {
  const border = selected
    ? 'border-accent'
    : goal
      ? 'border-accent-secondary'
      : highlighted
        ? 'border-accent-secondary'
        : 'border-border'

  return (
    <li
      ref={ref}
      onClick={onSelect}
      className={`relative bg-surface-card border ${border} rounded mb-2 flex items-start gap-2 px-2 ${
        compact ? 'py-1' : 'py-1.5'
      } ${lifted ? 'z-10 shadow-lg' : ''}`}
    >
      <button
        className="text-content-muted hover:text-content-primary cursor-grab shrink-0 mt-0.5"
        title="Drag to reorder, or Alt+Up / Alt+Down"
        aria-label={`Reorder ${step.label}, position ${index + 1} of ${total}`}
        onPointerDown={onGripDown}
        onKeyDown={onGripKey}
        onClick={(e) => e.stopPropagation()}
      >
        <GripVertical size={13} />
      </button>

      <span className="text-content-muted font-mono text-xs w-5 shrink-0 mt-0.5 text-right">
        {index + 1}
      </span>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className={`font-mono text-xs font-bold ${methodClass(step.method ?? '')}`}>
            {step.method}
          </span>
          <span className="text-content-primary text-xs truncate">{stepTitle(step)}</span>
        </div>

        {!compact && (
          <div className="text-[10px] text-content-muted break-all line-clamp-2 mt-0.5 font-mono">
            {requestTarget(step)}
          </div>
        )}

        {!compact && (consumes.length > 0 || produces.length > 0) && (
          <div className="flex flex-wrap items-center gap-1 mt-1">
            {consumes.slice(0, MAX_CHIPS).map(({ binding, peer }) => (
              <Chip
                key={binding.id}
                icon={<ArrowDown size={9} />}
                name={binding.var}
                peer={`${peer + 1}`}
                title={`${binding.var} comes from step ${peer + 1}, into ${binding.spans.length} place${
                  binding.spans.length === 1 ? '' : 's'
                } in this request`}
                onClick={() => onSelectBinding(binding)}
                onHover={(on) => onHoverBinding(on ? binding.id : null)}
                onRemove={() => onRemoveBinding(binding.id)}
              />
            ))}
            {produces.slice(0, MAX_CHIPS).map(({ binding, peer }) => (
              <Chip
                key={binding.id}
                icon={<KeyRound size={9} />}
                name={binding.var}
                peer={`→${peer + 1}`}
                title={`${binding.var} is read from this response and sent by step ${peer + 1}`}
                onClick={() => onSelectBinding(binding)}
                onHover={(on) => onHoverBinding(on ? binding.id : null)}
                onRemove={() => onRemoveBinding(binding.id)}
              />
            ))}
            <Overflow consumes={consumes} produces={produces} />
          </div>
        )}
      </div>

      <div className="flex items-center gap-1 shrink-0 mt-0.5">
        {step.setup && (
          <button
            className="text-semantic-info"
            title="Setup: never skipped, repeated or moved, so it re-runs before every variant"
            onClick={(e) => {
              e.stopPropagation()
              onToggleSetup()
            }}
          >
            <RotateCcw size={13} />
          </button>
        )}
        {goal && (
          <span className="text-accent-secondary" title="Goal: this step's outcome decides each verdict">
            <Flag size={13} />
          </span>
        )}
        {!goal && !compact && (
          <button
            className="text-content-muted hover:text-accent-secondary"
            title="Make this the goal step"
            onClick={(e) => {
              e.stopPropagation()
              onSetGoal()
            }}
          >
            <Flag size={13} />
          </button>
        )}
        <button
          className="text-content-muted hover:text-semantic-error"
          title="Remove this step"
          onClick={(e) => {
            e.stopPropagation()
            onRemove()
          }}
        >
          <X size={13} />
        </button>
      </div>
    </li>
  )
})

function Overflow({
  consumes, produces,
}: { consumes: StepRowProps['consumes']; produces: StepRowProps['produces'] }) {
  const hidden =
    Math.max(0, consumes.length - MAX_CHIPS) + Math.max(0, produces.length - MAX_CHIPS)
  if (hidden === 0) return null
  const names = [...consumes.slice(MAX_CHIPS), ...produces.slice(MAX_CHIPS)]
    .map((c) => c.binding.var)
    .join(', ')
  return (
    <span className="text-[10px] text-content-muted" title={names}>
      +{hidden}
    </span>
  )
}

/** One dependency, named. "How many" is not a question anyone has; "which value,
 *  and from where" is, and the arcs only answer it for ones the eye can trace. */
function Chip({
  icon, name, peer, title, onClick, onHover, onRemove,
}: {
  icon: React.ReactNode
  name: string
  peer: string
  title: string
  onClick: () => void
  onHover: (on: boolean) => void
  onRemove: () => void
}) {
  return (
    <span
      className="group inline-flex items-center gap-0.5 pl-1 pr-0.5 py-px rounded bg-surface-input border border-border-subtle text-[10px] text-content-secondary"
      title={title}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
    >
      <button
        className="inline-flex items-center gap-0.5 hover:text-accent-secondary"
        onClick={(e) => {
          e.stopPropagation()
          onClick()
        }}
      >
        {icon}
        <span className="font-mono">{name}</span>
        <span className="text-content-muted">{peer}</span>
      </button>
      <button
        className="opacity-0 group-hover:opacity-100 text-content-muted hover:text-semantic-error"
        title={`Remove the ${name} binding`}
        aria-label={`Remove the ${name} binding`}
        onClick={(e) => {
          e.stopPropagation()
          onRemove()
        }}
      >
        <X size={9} />
      </button>
    </span>
  )
}

export default ChainStepRow
