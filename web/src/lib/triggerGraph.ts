import type { TriggerEdge, TriggerGraph, TriggerNode, TriggerNodeType } from './api'

/**
 * Graph helpers shared by the canvas and the builder.
 *
 * The graph is the document. Neither view holds a second representation — the builder
 * reads a graph and writes a graph, so switching tabs is a re-render rather than a
 * conversion, and there is nothing that can drift.
 */

/** Node sizes, fixed per type so an edge's endpoints are arithmetic rather than a
 *  measurement. The canvas renders at these exact sizes. */
export const NODE_SIZE: Record<TriggerNodeType, { width: number; height: number }> = {
  event: { width: 200, height: 64 },
  condition: { width: 240, height: 84 },
  all: { width: 120, height: 52 },
  any: { width: 120, height: 52 },
  not: { width: 120, height: 52 },
  fire: { width: 180, height: 64 },
}

export const COL = 300
export const ROW = 120

/** Which node types the operator can add. event and fire are excluded: a graph has
 *  exactly one of each, and the server refuses a second. */
export const ADDABLE: TriggerNodeType[] = ['condition', 'all', 'any', 'not']

export const NODE_LABEL: Record<TriggerNodeType, string> = {
  event: 'Event',
  condition: 'Condition',
  all: 'AND',
  any: 'OR',
  not: 'NOT',
  fire: 'Run',
}

/** How each operator reads in a row, rather than as its wire name. */
export const OP_LABEL: Record<string, string> = {
  eq: 'is',
  ne: 'is not',
  contains: 'contains',
  prefix: 'starts with',
  suffix: 'ends with',
  matches: 'matches regex',
  glob: 'matches glob',
  in: 'is one of',
  exists: 'is present',
  status: 'matches status',
  gt: '>',
  lt: '<',
  gte: '>=',
  lte: '<=',
}

/** The placeholder for a value box, which is where the shape of an operator's argument is
 *  explained — an expression, a comma-separated set and a regex all look like free text. */
export const OP_HINT: Record<string, string> = {
  status: '4xx, 403, 500-599, none',
  in: 'GET, POST',
  matches: 'RE2 — no lookahead or backreferences',
  glob: '*.target.com',
}

/** One condition as a line of text, for a node body or a summary. */
export function describeNode(n: TriggerNode): string {
  if (n.type !== 'condition') return NODE_LABEL[n.type]
  const not = n.negate ? 'not ' : ''
  const cs = n.caseSensitive ? ' (case)' : ''
  if (n.op === 'exists') return `${not}${n.field} is present`
  return `${not}${n.field} ${OP_LABEL[n.op ?? ''] ?? n.op} ${JSON.stringify(n.value ?? '')}${cs}`
}

export function findNode(g: TriggerGraph, id: string): TriggerNode | undefined {
  return g.nodes.find((n) => n.id === id)
}

export function nodeOfType(g: TriggerGraph, type: TriggerNodeType): TriggerNode | undefined {
  return g.nodes.find((n) => n.type === type)
}

/** A node id nothing else is using. Sequential rather than random so a saved graph diffs
 *  cleanly and an operator reading the file can follow it. */
export function nextNodeId(g: TriggerGraph, type: TriggerNodeType): string {
  const prefix = type === 'condition' ? 'c' : type
  for (let i = 1; ; i++) {
    const id = `${prefix}${i}`
    if (!g.nodes.some((n) => n.id === id)) return id
  }
}

/** The boolean inputs of a node — every edge into it that does not come from the event. */
export function boolInputs(g: TriggerGraph, id: string): string[] {
  const event = nodeOfType(g, 'event')
  return g.edges.filter((e) => e.to === id && e.from !== event?.id).map((e) => e.from)
}

/** Whether an edge would be accepted, mirroring the server's port rules so the canvas
 *  refuses a bad connection while it is being dragged rather than on save.
 *
 *  The server still checks: this is the interaction, not the enforcement. */
export function canConnect(g: TriggerGraph, from: string, to: string): boolean {
  if (from === to) return false
  const a = findNode(g, from)
  const b = findNode(g, to)
  if (!a || !b) return false
  if (g.edges.some((e) => e.from === from && e.to === to)) return false

  // The event feeds conditions and nothing else.
  if (a.type === 'event') return b.type === 'condition'
  // Nothing leads out of the run node, and nothing boolean leads into a condition or the
  // event — a condition's only input is the event itself.
  if (a.type === 'fire' || b.type === 'condition' || b.type === 'event') return false

  // Arity, checked here so the canvas does not let you build something it would then have
  // to explain. NOT inverts one input; the run node takes one.
  const existing = boolInputs(g, to).length
  if ((b.type === 'not' || b.type === 'fire') && existing >= 1) return false

  return !wouldCycle(g, from, to)
}

/** Whether adding from -> to would close a loop: true when `from` is already reachable
 *  downstream of `to`. */
function wouldCycle(g: TriggerGraph, from: string, to: string): boolean {
  const event = nodeOfType(g, 'event')
  const seen = new Set<string>()
  const queue = [to]
  while (queue.length) {
    const id = queue.shift()!
    if (id === from) return true
    if (seen.has(id)) continue
    seen.add(id)
    for (const e of g.edges) {
      if (e.from === id && e.from !== event?.id) queue.push(e.to)
    }
  }
  return false
}

/** Add a node, wiring a condition to the event so the operator never has to make that
 *  connection by hand — it is required, and always the same. */
export function addNode(
  g: TriggerGraph,
  type: TriggerNodeType,
  at: { x: number; y: number },
  seed?: Partial<TriggerNode>
): TriggerGraph {
  const id = nextNodeId(g, type)
  const node: TriggerNode = { id, type, x: at.x, y: at.y, ...seed }
  const edges = [...g.edges]
  if (type === 'condition') {
    const event = nodeOfType(g, 'event')
    if (event) edges.push({ from: event.id, to: id })
  }
  return { nodes: [...g.nodes, node], edges }
}

/** Remove a node and everything wired to it. The event and run nodes are never removable:
 *  a graph needs exactly one of each. */
export function removeNode(g: TriggerGraph, id: string): TriggerGraph {
  const n = findNode(g, id)
  if (!n || n.type === 'event' || n.type === 'fire') return g
  return {
    nodes: g.nodes.filter((x) => x.id !== id),
    edges: g.edges.filter((e) => e.from !== id && e.to !== id),
  }
}

export function patchNode(g: TriggerGraph, id: string, p: Partial<TriggerNode>): TriggerGraph {
  return { ...g, nodes: g.nodes.map((n) => (n.id === id ? { ...n, ...p } : n)) }
}

export function removeEdge(g: TriggerGraph, e: TriggerEdge): TriggerGraph {
  return { ...g, edges: g.edges.filter((x) => !(x.from === e.from && x.to === e.to)) }
}

/** Nodes nothing reaches from the run node. Mirrors Graph.Orphans on the server so the
 *  canvas can mark them without a round trip; the server's answer is the one that counts. */
export function orphans(g: TriggerGraph): string[] {
  const fire = nodeOfType(g, 'fire')
  if (!fire) return []
  const event = nodeOfType(g, 'event')
  const reached = new Set([fire.id])
  const queue = [fire.id]
  while (queue.length) {
    const id = queue.shift()!
    for (const e of g.edges) {
      if (e.to === id && e.from !== event?.id && !reached.has(e.from)) {
        reached.add(e.from)
        queue.push(e.from)
      }
    }
  }
  return g.nodes
    .filter((n) => n.type !== 'event' && n.type !== 'fire' && !reached.has(n.id))
    .map((n) => n.id)
}

// ---- the flat projection the builder edits ----

/** A graph the builder can represent: one level of conditions, combined by one mode.
 *
 *  Deliberately narrow. The builder exists for the common trigger — a handful of tests
 *  ANDed or ORed together — and pretending it can show an arbitrary graph would mean
 *  either lying about one or silently flattening it. Anything nested is sent to the
 *  canvas, which can show it exactly. */
export interface FlatView {
  mode: 'all' | 'any'
  conditions: TriggerNode[]
}

/** The flat reading of a graph, or null when it has none. */
export function toFlat(g: TriggerGraph): FlatView | null {
  const fire = nodeOfType(g, 'fire')
  if (!fire) return null
  const into = boolInputs(g, fire.id)
  if (into.length === 0) return { mode: 'all', conditions: [] }
  if (into.length > 1) return null

  const root = findNode(g, into[0])
  if (!root) return null
  if (root.type === 'condition') return { mode: 'all', conditions: [root] }
  if (root.type !== 'all' && root.type !== 'any') return null

  const kids = boolInputs(g, root.id).map((id) => findNode(g, id))
  if (kids.some((k) => !k || k.type !== 'condition')) return null
  // A condition feeding something else as well is shared, and removing it here would
  // change that other branch. Shared structure is exactly what the canvas is for.
  const usedTwice = kids.some(
    (k) => g.edges.filter((e) => e.from === k!.id && e.to !== root.id).length > 0
  )
  if (usedTwice) return null

  return { mode: root.type, conditions: kids as TriggerNode[] }
}

/** Rebuild a graph from the flat view, keeping node positions where they already exist so
 *  editing in the builder does not scramble a layout arranged on the canvas. */
export function fromFlat(g: TriggerGraph, view: FlatView): TriggerGraph {
  const event = nodeOfType(g, 'event') ?? { id: 'event', type: 'event' as const, x: 0, y: ROW }
  const fire = nodeOfType(g, 'fire') ?? { id: 'fire', type: 'fire' as const, x: COL * 3, y: ROW }

  const nodes: TriggerNode[] = [event, fire]
  const edges: TriggerEdge[] = []

  view.conditions.forEach((c, i) => {
    nodes.push({ ...c, x: c.x ?? COL, y: c.y ?? i * ROW })
    edges.push({ from: event.id, to: c.id })
  })

  if (view.conditions.length === 0) {
    return { nodes, edges }
  }
  if (view.conditions.length === 1) {
    edges.push({ from: view.conditions[0].id, to: fire.id })
    return { nodes, edges }
  }

  // Reuse the existing combiner when it is already the right kind, so its position and id
  // survive a mode change made in the builder.
  const existing = g.nodes.find((n) => n.type === 'all' || n.type === 'any')
  const combiner: TriggerNode = {
    id: existing?.id ?? 'logic1',
    type: view.mode,
    x: existing?.x ?? COL * 2,
    y: existing?.y ?? ROW,
  }
  nodes.push(combiner)
  for (const c of view.conditions) edges.push({ from: c.id, to: combiner.id })
  edges.push({ from: combiner.id, to: fire.id })
  return { nodes, edges }
}

/** Lay a graph out left to right in columns by depth from the run node. For the Tidy
 *  button, and for a graph that arrived without positions. */
export function tidy(g: TriggerGraph): TriggerGraph {
  const event = nodeOfType(g, 'event')
  const fire = nodeOfType(g, 'fire')
  if (!fire) return g

  // Depth is the longest path back to the run node, so a node always sits left of
  // everything it feeds.
  const depth = new Map<string, number>([[fire.id, 0]])
  let changed = true
  let guard = 0
  while (changed && guard++ < g.nodes.length + 2) {
    changed = false
    for (const e of g.edges) {
      if (e.from === event?.id) continue
      const d = (depth.get(e.to) ?? 0) + 1
      if (d > (depth.get(e.from) ?? -1)) {
        depth.set(e.from, d)
        changed = true
      }
    }
  }
  const maxDepth = Math.max(0, ...depth.values())

  const byColumn = new Map<number, string[]>()
  for (const n of g.nodes) {
    if (n.type === 'event') continue
    const col = maxDepth - (depth.get(n.id) ?? maxDepth)
    byColumn.set(col, [...(byColumn.get(col) ?? []), n.id])
  }

  const placed = new Map<string, { x: number; y: number }>()
  for (const [col, ids] of byColumn) {
    ids.forEach((id, i) => placed.set(id, { x: (col + 1) * COL, y: i * ROW }))
  }
  if (event) placed.set(event.id, { x: 0, y: ((byColumn.get(0)?.length ?? 1) - 1) * ROW * 0.5 })

  return { ...g, nodes: g.nodes.map((n) => ({ ...n, ...(placed.get(n.id) ?? {}) })) }
}
