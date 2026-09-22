// Geometry for the Chain map: an ordered list of steps, plus the data
// dependencies between them drawn as arcs in a gutter beside it.
//
// A list, not a canvas. Skip, repeat and reorder are list operations and a
// Variant is a flat array of step ids, so free positioning would let the picture
// lie about the execution order it exists to show. What is genuinely a graph is
// the data, and the arcs get their own language so the two are not confused.
//
// validate.go refuses a binding whose producer does not run first, so every arc
// points downward within one column — which makes routing interval packing over
// a line rather than a layout engine.

import type { Chain, ChainBinding, ChainStep } from './chainTypes'

/** Where in a row an arc attaches, measured from the row's top. Line one's
 *  centre, so an arc points at the method and label rather than at the URL. */
export const PORT_DY = 15

/** Gutter lane pitch, and the gap between the innermost lane and the rows.
 *
 *  LANE_PAD must stay larger than CORNER: the difference is the straight run the
 *  arrowhead is drawn along, and closing it up renders the marker on its own
 *  corner curve. */
export const LANE_W = 11
export const LANE_PAD = 13

/** Lanes past this share the outermost one. Overlapping arcs beyond five deep
 *  are unreadable either way, and an unbounded gutter would eat the rows. */
export const MAX_DEPTH = 5

/** Arc corner radius, clamped per arc so a short arc still rounds. */
export const CORNER = 5

/** Arc is one binding placed in the gutter. */
export interface Arc {
  id: string
  binding: ChainBinding
  /** Row indices, not ids: everything downstream is arithmetic on these. */
  from: number
  to: number
  /** 0 is the lane nearest the rows, so nested arcs hug what contains them. */
  depth: number
  /** The producer does not run before the consumer, so this is the state the
   *  server will refuse to save. Drawn running upward, not merely recoloured. */
  backwards: boolean
}

export interface ArcLayout {
  arcs: Arc[]
  /** Width the rows must be inset by to clear every lane. */
  gutterW: number
}

/** stepIndex maps every step id to its position, once per layout. */
function stepIndex(chain: Chain): Record<string, number> {
  const m: Record<string, number> = {}
  chain.steps.forEach((s, i) => (m[s.id] = i))
  return m
}

/** layoutArcs assigns every binding a lane, so that no two arcs sharing a span
 *  of rows share a lane.
 *
 *  Greedy interval packing: sorted so an enclosing arc is placed before what it
 *  contains, each takes the innermost free lane. That hands low lanes to the
 *  enclosing arcs, which is visually backwards, so the number is inverted into
 *  `depth` at the end — reversing the sort instead would break the packing. */
export function layoutArcs(chain: Chain): ArcLayout {
  const idx = stepIndex(chain)
  const raw: Arc[] = []
  for (const b of chain.bindings) {
    const from = idx[b.fromStep]
    const to = idx[b.toStep]
    // A binding naming a step that is not in the chain has nothing to draw
    // between. Dropping it here keeps the picture honest; the save refuses it.
    if (from === undefined || to === undefined) continue
    raw.push({ id: b.id, binding: b, from, to, depth: 0, backwards: from >= to })
  }

  const order = raw
    .map((a, i) => ({ a, i, lo: Math.min(a.from, a.to), hi: Math.max(a.from, a.to) }))
    .sort((x, y) => x.lo - y.lo || y.hi - x.hi || x.i - y.i)

  const laneEnd: number[] = []
  const lane = new Map<string, number>()
  for (const { a, lo, hi } of order) {
    let L = laneEnd.findIndex((end) => end < lo)
    if (L < 0) L = laneEnd.length
    laneEnd[L] = hi
    lane.set(a.id, L)
  }

  const maxLane = laneEnd.length ? laneEnd.length - 1 : 0
  for (const a of raw) {
    a.depth = Math.min(MAX_DEPTH, maxLane - (lane.get(a.id) ?? 0))
  }

  const usedDepth = raw.length ? Math.max(...raw.map((a) => a.depth)) : -1
  const gutterW = usedDepth < 0 ? LANE_PAD : LANE_PAD + (usedDepth + 1) * LANE_W
  return { arcs: raw, gutterW }
}

/** laneX is the horizontal centre of an arc's vertical run. */
export function laneX(depth: number, gutterW: number): number {
  return Math.max(2, gutterW - LANE_PAD - depth * LANE_W)
}

/** arcPath draws one arc as a rounded bracket: out of the producer row, down the
 *  gutter, back into the consumer row.
 *
 *  The final segment always runs in +x, so one marker with orient="auto" aims
 *  every arrowhead with no per-arc rotation. A backwards arc genuinely runs
 *  upward, so its direction survives without colour. */
export function arcPath(x: number, y1: number, y2: number, gutterW: number): string {
  const dir = Math.sign(y2 - y1) || 1
  const r = Math.min(CORNER, Math.abs(y2 - y1) / 2)
  return (
    `M ${gutterW} ${y1} H ${x + r} Q ${x} ${y1} ${x} ${y1 + dir * r} ` +
    `V ${y2 - dir * r} Q ${x} ${y2} ${x + r} ${y2} H ${gutterW - 1}`
  )
}

/** moveStep returns the chain with one step spliced to a new index. Shared by
 *  the drag commit and the keyboard path so there is one definition of a move. */
export function moveStep(chain: Chain, from: number, to: number): Chain {
  if (from === to || from < 0 || from >= chain.steps.length) return chain
  const steps = chain.steps.slice()
  const [moved] = steps.splice(from, 1)
  steps.splice(Math.max(0, Math.min(steps.length, to)), 0, moved)
  return { ...chain, steps }
}

/** backwardsAfterMove names the bindings a candidate move would invert.
 *
 *  Mirrors validate.go's producer-before-consumer rule and nothing else: a
 *  client copy that grew to guess at the rest would refuse states the server
 *  accepts. The server stays the authority. */
export function backwardsAfterMove(chain: Chain, from: number, to: number): ChainBinding[] {
  return backwardsIn(moveStep(chain, from, to))
}

/** backwardsIn names the bindings a chain currently holds that cannot resolve. */
export function backwardsIn(chain: Chain): ChainBinding[] {
  const idx = stepIndex(chain)
  return chain.bindings.filter((b) => {
    const f = idx[b.fromStep]
    const t = idx[b.toStep]
    return f !== undefined && t !== undefined && f >= t
  })
}

/** legalRange is the band of indices step `i` can move to with every one of its
 *  bindings still resolvable: after the last step that produces a value it
 *  consumes, and before the first step that consumes a value it produces.
 *
 *  Shown as a shaded band during a drag, not enforced as a snap: a snap resists
 *  silently, and blocks the intermediate states a multi-step rearrange passes
 *  through. */
export function legalRange(chain: Chain, i: number): [number, number] {
  const idx = stepIndex(chain)
  const step = chain.steps[i]
  if (!step) return [0, Math.max(0, chain.steps.length - 1)]
  let lo = 0
  let hi = chain.steps.length - 1
  for (const b of chain.bindings) {
    if (b.toStep === step.id) {
      const f = idx[b.fromStep]
      if (f !== undefined && f !== i) lo = Math.max(lo, f + 1)
    }
    if (b.fromStep === step.id) {
      const t = idx[b.toStep]
      if (t !== undefined && t !== i) hi = Math.min(hi, t - 1)
    }
  }
  return [lo, hi]
}

/** requestTarget is the full URL a step sends to.
 *
 *  Not step.label: chain.Label strips the query and truncates to 48 chars, and
 *  a checkout and its confirm step can differ only in the query string.
 *
 *  Only the head is decoded — 64 steps of up to a megabyte each is too much for
 *  one line of text. atob yields latin-1, exact for a percent-encoded target. */
export function requestTarget(step: ChainStep): string {
  let line = ''
  try {
    // A multiple of 4 so the slice is a whole number of base64 quanta.
    const head = atob(step.reqRaw.slice(0, 2048))
    const nl = head.indexOf('\n')
    line = nl < 0 ? head : head.slice(0, nl)
  } catch {
    return `${step.scheme}://${step.host}`
  }
  const parts = line.trim().split(' ')
  const target = parts.length > 1 ? parts[1] : ''
  if (!target || target.startsWith('http://') || target.startsWith('https://')) {
    return target || `${step.scheme}://${step.host}`
  }
  return `${step.scheme}://${step.host}${target}`
}

/** stepTitle is a step's label without the method it already carries.
 *
 *  chain.Label renders "METHOD /path" and the row badges the method itself, so
 *  without this every row reads "POST POST /checkout". */
export function stepTitle(step: ChainStep): string {
  const m = step.method ?? ''
  return m && step.label.startsWith(m + ' ') ? step.label.slice(m.length + 1) : step.label
}
