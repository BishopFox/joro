import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { AlertTriangle, Link2, Rows2, Rows3 } from 'lucide-react'
import { beginPointerDrag } from '../../lib/pointerDrag'
import {
  PORT_DY,
  arcPath,
  backwardsAfterMove,
  backwardsIn,
  laneX,
  layoutArcs,
  legalRange,
  moveStep,
} from '../../lib/chainMap'
import type { Chain, ChainBinding } from '../../lib/chainTypes'
import ChainStepRow from './ChainStepRow'

/** How close to an edge the pointer must get before the list scrolls itself. */
const EDGE = 40
const EDGE_SPEED = 8

interface Props {
  chain: Chain
  selectedStepId: string | null
  selectedBindingId: string | null
  onSelect: (stepId: string | null, bindingId?: string | null) => void
  onChange: (chain: Chain) => void
  onCorrelate: () => void
}

type Hover = { kind: 'step'; id: string } | { kind: 'arc'; id: string } | null

interface DragState {
  from: number
  to: number
  dy: number
  /** Row geometry as it was when the drag began; never re-measured mid-gesture,
   *  because the rows are being transformed and would measure their own shift. */
  tops: number[]
  heights: number[]
}

export default function ChainMap({
  chain, selectedStepId, selectedBindingId, onSelect, onChange, onCorrelate,
}: Props) {
  const uid = useId().replace(/:/g, '')
  const goalId = chain.goalStepId || chain.steps[chain.steps.length - 1]?.id

  const [compact, setCompact] = useState(false)
  const [hover, setHover] = useState<Hover>(null)
  const [drag, setDrag] = useState<DragState | null>(null)
  const [announce, setAnnounce] = useState('')
  const [tops, setTops] = useState<number[]>([])
  const [listH, setListH] = useState(0)

  const scrollRef = useRef<HTMLDivElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const rowRefs = useRef(new Map<string, HTMLLIElement>())
  const dragging = useRef(false)

  const { arcs, gutterW } = useMemo(() => layoutArcs(chain), [chain])

  const index = useMemo(() => {
    const m: Record<string, number> = {}
    chain.steps.forEach((s, i) => (m[s.id] = i))
    return m
  }, [chain.steps])

  // Measured, not assumed: a row is one or two lines tall depending on its URL.
  const measure = useCallback(() => {
    if (dragging.current) return
    const wrap = wrapRef.current
    if (!wrap) return
    const base = wrap.getBoundingClientRect().top
    const next = chain.steps.map((s) => {
      const el = rowRefs.current.get(s.id)
      return el ? el.getBoundingClientRect().top - base : 0
    })
    setTops(next)
    setListH(wrap.getBoundingClientRect().height)
  }, [chain.steps])

  useLayoutEffect(measure, [measure, compact])

  useEffect(() => {
    const wrap = wrapRef.current
    if (!wrap || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => measure())
    ro.observe(wrap)
    return () => ro.disconnect()
  }, [measure])

  const backwards = useMemo(() => backwardsIn(chain), [chain])
  const previewBad = useMemo(
    () => (drag ? new Set(backwardsAfterMove(chain, drag.from, drag.to).map((b) => b.id)) : null),
    [chain, drag],
  )

  const patch = useCallback((c: Chain) => onChange(c), [onChange])

  const removeStep = useCallback(
    (id: string) =>
      patch({
        ...chain,
        steps: chain.steps.filter((s) => s.id !== id),
        // Bindings at either end of a removed step have nowhere to go. Dropping
        // them here rather than letting the server refuse the save is what keeps
        // the delete a single click.
        bindings: chain.bindings.filter((b) => b.fromStep !== id && b.toStep !== id),
        goalStepId: chain.goalStepId === id ? '' : chain.goalStepId,
      }),
    [chain, patch],
  )

  const removeBinding = useCallback(
    (id: string) => patch({ ...chain, bindings: chain.bindings.filter((b) => b.id !== id) }),
    [chain, patch],
  )

  const commitMove = useCallback(
    (from: number, to: number) => {
      if (from === to) return
      const moved = chain.steps[from]
      const next = moveStep(chain, from, to)
      patch(next)
      const bad = backwardsIn(next).length
      setAnnounce(
        `Moved ${moved.label} to position ${to + 1} of ${chain.steps.length}.` +
          (bad ? ` ${bad} dependenc${bad === 1 ? 'y' : 'ies'} now point backwards.` : ''),
      )
    },
    [chain, patch],
  )

  // The drag is the edit. Rows slide out of the way as the pointer moves, so
  // the destination is visible before the drop.
  const onGripDown = useCallback(
    (e: React.PointerEvent, from: number) => {
      const wrap = wrapRef.current
      const scroll = scrollRef.current
      if (!wrap || !scroll) return
      const base = wrap.getBoundingClientRect().top
      const snapTops: number[] = []
      const snapH: number[] = []
      for (const s of chain.steps) {
        const el = rowRefs.current.get(s.id)
        const r = el?.getBoundingClientRect()
        snapTops.push(r ? r.top - base : 0)
        snapH.push(r ? r.height : 0)
      }
      const startY = e.clientY
      const startScroll = scroll.scrollTop
      let clientY = e.clientY
      let raf = 0

      const update = () => {
        const dy = clientY - startY + (scroll.scrollTop - startScroll)
        const centre = snapTops[from] + dy + snapH[from] / 2
        let to = from
        for (let i = 0; i < chain.steps.length; i++) {
          if (i === from) continue
          const c = snapTops[i] + snapH[i] / 2
          if (i < from && centre < c) to = Math.min(to, i)
          if (i > from && centre > c) to = Math.max(to, i)
        }
        setDrag({ from, to, dy, tops: snapTops, heights: snapH })
      }

      // beginPointerDrag's shield takes the pointer, so the container never
      // sees a drag near its edge and a long chain cannot be reached.
      const tick = () => {
        const r = scroll.getBoundingClientRect()
        if (clientY < r.top + EDGE) scroll.scrollTop -= EDGE_SPEED
        else if (clientY > r.bottom - EDGE) scroll.scrollTop += EDGE_SPEED
        else {
          raf = requestAnimationFrame(tick)
          return
        }
        update()
        raf = requestAnimationFrame(tick)
      }

      dragging.current = true
      update()
      raf = requestAnimationFrame(tick)

      const stop = beginPointerDrag(
        e,
        'grabbing',
        (ev) => {
          clientY = ev.clientY
          update()
        },
        () => {
          cancelAnimationFrame(raf)
          dragging.current = false
          setDrag((d) => {
            if (d) commitMove(d.from, d.to)
            return null
          })
        },
      )
      if (!stop) {
        cancelAnimationFrame(raf)
        dragging.current = false
        setDrag(null)
      }
    },
    [chain.steps, commitMove],
  )

  const onGripKey = useCallback(
    (e: React.KeyboardEvent, i: number) => {
      if (!e.altKey) return
      const to = e.key === 'ArrowUp' ? i - 1 : e.key === 'ArrowDown' ? i + 1 : -1
      if (to < 0 || to >= chain.steps.length) return
      e.preventDefault()
      const id = chain.steps[i].id
      commitMove(i, to)
      // Follow the row, or the next keystroke moves whatever took its slot.
      requestAnimationFrame(() => rowRefs.current.get(id)?.querySelector('button')?.focus())
    },
    [chain.steps, commitMove],
  )

  // Which arcs and rows are lit. Hovering a step lights everything it is joined
  // to; hovering an arc lights both of its ends.
  const hot = useMemo(() => {
    const arcIds = new Set<string>()
    const stepIds = new Set<string>()
    if (!hover && !selectedBindingId) return null
    if (selectedBindingId) {
      const b = chain.bindings.find((x) => x.id === selectedBindingId)
      if (b) {
        arcIds.add(b.id)
        stepIds.add(b.fromStep)
        stepIds.add(b.toStep)
      }
    }
    if (hover?.kind === 'step') {
      stepIds.add(hover.id)
      for (const b of chain.bindings) {
        if (b.fromStep === hover.id || b.toStep === hover.id) {
          arcIds.add(b.id)
          stepIds.add(b.fromStep)
          stepIds.add(b.toStep)
        }
      }
    }
    if (hover?.kind === 'arc') {
      const b = chain.bindings.find((x) => x.id === hover.id)
      if (b) {
        arcIds.add(b.id)
        stepIds.add(b.fromStep)
        stepIds.add(b.toStep)
      }
    }
    return { arcIds, stepIds }
  }, [hover, selectedBindingId, chain.bindings])

  const band = drag ? legalRange(chain, drag.from) : null
  const shift = (i: number) => {
    if (!drag) return 0
    if (i === drag.from) return drag.dy
    const h = drag.heights[drag.from]
    if (drag.to > drag.from && i > drag.from && i <= drag.to) return -h
    if (drag.to < drag.from && i >= drag.to && i < drag.from) return h
    return 0
  }

  const y = (i: number) => (tops[i] ?? 0) + PORT_DY

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {backwards.length > 0 && (
        <div className="flex items-start gap-2 px-3 py-1.5 bg-semantic-error-bg border-b border-border shrink-0">
          <AlertTriangle size={13} className="text-semantic-error shrink-0 mt-0.5" />
          <div className="text-[11px] text-content-primary">
            {backwards.length} dependenc{backwards.length === 1 ? 'y' : 'ies'} point backwards -
            the value is produced after the step that needs it, so the save will be refused.
            <div className="flex flex-wrap gap-1 mt-1">
              {backwards.map((b) => (
                <button
                  key={b.id}
                  className="font-mono text-[10px] px-1 py-px rounded bg-surface-input border border-border hover:text-accent-secondary"
                  onClick={() => onSelect(b.toStep, b.id)}
                  onMouseEnter={() => setHover({ kind: 'arc', id: b.id })}
                  onMouseLeave={() => setHover(null)}
                >
                  {b.var} · {chain.steps[index[b.fromStep]]?.label ?? '?'} →{' '}
                  {chain.steps[index[b.toStep]]?.label ?? '?'}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between px-2 py-1 border-b border-border shrink-0">
        <span className="text-[10px] text-content-muted">
          Order runs top to bottom. Arcs are the values one response hands a later request.
        </span>
        <button
          className="text-content-muted hover:text-content-primary"
          title={compact ? 'Show full detail' : 'Compact rows'}
          aria-label={compact ? 'Show full detail' : 'Compact rows'}
          onClick={() => setCompact((c) => !c)}
        >
          {compact ? <Rows3 size={13} /> : <Rows2 size={13} />}
        </button>
      </div>

      {/* Background clicks only: a row's own click bubbles here, and an
          unguarded handler would deselect the step it just selected. */}
      <div
        ref={scrollRef}
        className="flex-1 min-h-0 overflow-y-auto"
        onClick={(e) => {
          if (!(e.target as HTMLElement).closest('li')) onSelect(null)
        }}
      >
        <div ref={wrapRef} className="relative px-2 py-2">
          <svg
            // top-0, not top-2: row tops are measured from the wrapper's border
            // box, so the arc layer has to share that origin or every arc sits
            // one padding step above the row it points at.
            className="absolute left-2 top-0 pointer-events-none overflow-visible"
            width={gutterW}
            height={listH}
            aria-hidden="true"
          >
            <defs>
              <marker id={`${uid}-tip`} viewBox="0 0 6 6" refX="5" refY="3" markerWidth="5" markerHeight="5" orient="auto">
                <path d="M0 0 L6 3 L0 6 z" fill="var(--color-accent-secondary)" />
              </marker>
              <marker id={`${uid}-tip-dim`} viewBox="0 0 6 6" refX="5" refY="3" markerWidth="5" markerHeight="5" orient="auto">
                <path d="M0 0 L6 3 L0 6 z" fill="var(--color-border)" />
              </marker>
              <marker id={`${uid}-tip-bad`} viewBox="0 0 6 6" refX="5" refY="3" markerWidth="5" markerHeight="5" orient="auto">
                <path d="M0 0 L6 3 L0 6 z" fill="var(--color-semantic-error)" />
              </marker>
            </defs>

            {band && drag && tops.length > 0 && (
              <rect
                x={0}
                y={(tops[band[0]] ?? 0) - 2}
                width={gutterW}
                height={
                  (tops[band[1]] ?? tops[tops.length - 1] ?? 0) +
                  (drag.heights[band[1]] ?? 0) -
                  (tops[band[0]] ?? 0) +
                  4
                }
                fill="var(--color-semantic-info)"
                opacity="0.12"
              />
            )}

            {tops.length === chain.steps.length &&
              arcs.map((a) => {
                const bad = previewBad ? previewBad.has(a.id) : a.backwards
                const lit = !hot || hot.arcIds.has(a.id)
                const x = laneX(a.depth, gutterW)
                const d = arcPath(x, y(a.from), y(a.to), gutterW)
                const stroke = bad
                  ? 'var(--color-semantic-error)'
                  : hot?.arcIds.has(a.id)
                    ? 'var(--color-accent-secondary)'
                    : 'var(--color-border)'
                const tip = bad ? 'tip-bad' : hot?.arcIds.has(a.id) ? 'tip' : 'tip-dim'
                return (
                  <g key={a.id} className="joro-chain-arc" opacity={lit ? 1 : 0.3}>
                    <path
                      d={d}
                      fill="none"
                      stroke="transparent"
                      strokeWidth={12}
                      style={{ pointerEvents: 'stroke' }}
                      onMouseEnter={() => setHover({ kind: 'arc', id: a.id })}
                      onMouseLeave={() => setHover(null)}
                      onClick={(e) => {
                        e.stopPropagation()
                        onSelect(a.binding.toStep, a.id)
                      }}
                    >
                      <title>
                        {bad
                          ? `${a.binding.var} is produced after the step that needs it, so it can never resolve`
                          : `${a.binding.var} flows from step ${a.from + 1} into step ${a.to + 1}`}
                      </title>
                    </path>
                    <path
                      d={d}
                      fill="none"
                      stroke={stroke}
                      strokeWidth={hot?.arcIds.has(a.id) ? 2 : 1.25}
                      strokeDasharray={bad ? '4 3' : undefined}
                      markerEnd={`url(#${uid}-${tip})`}
                      style={{ pointerEvents: 'none' }}
                    />
                    <circle cx={gutterW - 1} cy={y(a.from)} r={2.5} fill={stroke} style={{ pointerEvents: 'none' }} />
                  </g>
                )
              })}
          </svg>

          <ol style={{ paddingLeft: gutterW }}>
            {chain.steps.map((step, i) => {
              const consumes = chain.bindings
                .filter((b) => b.toStep === step.id)
                .map((b) => ({ binding: b, peer: index[b.fromStep] ?? 0 }))
              const produces = chain.bindings
                .filter((b) => b.fromStep === step.id)
                .map((b) => ({ binding: b, peer: index[b.toStep] ?? 0 }))
              const dy = shift(i)
              return (
                <div
                  key={step.id}
                  style={{
                    transform: dy ? `translateY(${dy}px)` : undefined,
                    transition: drag && i !== drag.from ? 'transform 100ms' : undefined,
                  }}
                  onMouseEnter={() => setHover({ kind: 'step', id: step.id })}
                  onMouseLeave={() => setHover(null)}
                >
                  <ChainStepRow
                    ref={(el) => {
                      if (el) rowRefs.current.set(step.id, el)
                      else rowRefs.current.delete(step.id)
                    }}
                    step={step}
                    index={i}
                    total={chain.steps.length}
                    selected={selectedStepId === step.id}
                    goal={step.id === goalId}
                    lifted={drag?.from === i}
                    highlighted={!!hot?.stepIds.has(step.id)}
                    compact={compact}
                    consumes={consumes}
                    produces={produces}
                    onSelect={() => onSelect(step.id)}
                    onToggleSetup={() =>
                      patch({
                        ...chain,
                        steps: chain.steps.map((s) =>
                          s.id === step.id ? { ...s, setup: !s.setup } : s,
                        ),
                      })
                    }
                    onSetGoal={() => patch({ ...chain, goalStepId: step.id })}
                    onRemove={() => removeStep(step.id)}
                    onRemoveBinding={removeBinding}
                    onSelectBinding={(b: ChainBinding) => onSelect(b.toStep, b.id)}
                    onHoverBinding={(id) => setHover(id ? { kind: 'arc', id } : null)}
                    onGripDown={(e) => onGripDown(e, i)}
                    onGripKey={(e) => onGripKey(e, i)}
                  />
                </div>
              )
            })}
          </ol>

          {drag && previewBad && previewBad.size > 0 && (
            <div
              className="absolute right-2 text-[10px] text-semantic-warning bg-surface-card border border-border rounded px-1.5 py-0.5"
              style={{ top: (drag.tops[drag.from] ?? 0) + drag.dy }}
            >
              {previewBad.size} dependenc{previewBad.size === 1 ? 'y' : 'ies'} would point backwards
            </div>
          )}
        </div>
      </div>

      {chain.steps.length === 1 && (
        <div className="px-3 py-2 border-t border-border text-[11px] text-content-muted shrink-0">
          A chain needs a second step before there is an order to test.
        </div>
      )}

      {chain.steps.length > 1 && chain.bindings.length === 0 && (
        <div className="px-3 py-2 border-t border-border shrink-0">
          <div className="text-xs text-content-primary">Nothing flows between these steps yet.</div>
          <div className="text-[11px] text-content-muted mt-0.5 leading-relaxed">
            Every step replays the tokens it was recorded with, so a variant that fails may only
            mean the session went stale rather than that the application enforced its order.
          </div>
          <button
            onClick={onCorrelate}
            className="mt-1.5 flex items-center gap-1 px-2 py-1 rounded text-xs bg-surface-input text-content-primary hover:text-accent-secondary"
          >
            <Link2 size={12} /> Correlate - find the values one response hands the next
          </button>
        </div>
      )}

      <p className="sr-only" aria-live="polite">
        {announce}
      </p>
    </div>
  )
}
