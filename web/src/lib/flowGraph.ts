import type { FlowEdge, FlowGraph, FlowNode, FlowNodeData, FlowNodeType, SdkMethod } from './api'

// Re-exported so a consumer imports the graph vocabulary from one place: the wire shape
// lives beside TriggerGraph in api.ts, and everything that gives it meaning lives here.
export type { FlowEdge, FlowGraph, FlowNode, FlowNodeData, FlowNodeType }

/**
 * The automation flow graph: what an automation does, as boxes and wires.
 *
 * The same shape as a trigger graph one level up. A trigger graph is a boolean expression
 * over one event — sources, logic, one terminal. This is the same three regions over a whole
 * run: trigger nodes and the run context are the sources, SDK calls and expressions are the
 * middle, and exactly one return node is the terminal. An operator who has built a trigger
 * already knows how to read one of these.
 *
 * The graph is the editing document, not the executable. It compiles to JavaScript
 * (flowCompile.ts) and the generated source is what gets stored and run, bounded by the same
 * SDK bundle as anything hand-written. A graph that will not compile therefore cannot break
 * an automation that is already installed — the last source that did compile is still on
 * disk. That polarity is deliberate and matches internal/trigger, where an unreadable trigger
 * is reported rather than silently treated as "no filter".
 *
 * Ports are named here, unlike a trigger graph where they are implied by node type. A call
 * node has one input per argument of the method it calls, so there is nothing to imply.
 */

/** What travels down a wire. Two kinds rather than a type system: a boolean is the one
 *  distinction the language actually enforces, because logic, choose and stop-unless take
 *  nothing else and a port that quietly accepts a string is a bug that only surfaces at run
 *  time. Ports are not part of the wire shape — they are derived from the node's kind, or
 *  for a call node from the capability's own JSON Schema — so they live here. */
export type PortKind = 'value' | 'bool'

export interface FlowPort {
  id: string
  label: string
  kind: PortKind
  /** Accepts more than one wire. AND/OR combine what they are given; log prints it. */
  many?: boolean
  /** Compilation fails without it, rather than emitting undefined and hoping. */
  required?: boolean
}

/** Bounds, mirrored in internal/jsautomation/flow.go. Twice the trigger package's, because a
 *  program is a bigger thing than a predicate. Edited together. */
export const MAX_NODES = 128
export const MAX_EDGES = 256
export const MAX_VALUE_LEN = 4096

// ---- the node registry ----

export interface NodeSpec {
  label: string
  /** The one-line description shown in the palette and the inspector. */
  hint: string
  inputs: FlowPort[]
  outputs: FlowPort[]
  /** A graph holds at most one. */
  singleton?: boolean
  /** Not offered in the palette: added another way, or not addable at all. */
  hidden?: boolean
  /** Which group it sits under in the palette. */
  group?: 'Source' | 'Value' | 'Logic' | 'Action' | 'Control'
}

const V = (id: string, label: string, extra: Partial<FlowPort> = {}): FlowPort => ({
  id,
  label,
  kind: 'value',
  ...extra,
})
const B = (id: string, label: string, extra: Partial<FlowPort> = {}): FlowPort => ({
  id,
  label,
  kind: 'bool',
  ...extra,
})

const OUT = [V('out', 'out')]

export const NODE_SPECS: Record<FlowNodeType, NodeSpec> = {
  trigger: {
    label: 'Trigger',
    hint: 'Why this ran. Wire it to read the event that woke the automation.',
    inputs: [],
    outputs: OUT,
    group: 'Source',
    // Added through the trigger picker, which offers the catalog, rather than as a blank box
    // that then has to be told which trigger it is.
    hidden: true,
  },
  context: {
    label: 'Context',
    hint: 'ctx.input, ctx.trigger or ctx.run.',
    inputs: [],
    outputs: OUT,
    group: 'Source',
  },
  literal: {
    label: 'Value',
    hint: 'A fixed value, written as JSON.',
    inputs: [],
    outputs: OUT,
    group: 'Source',
  },
  get: {
    label: 'Read field',
    hint: 'Reach into an object or array by path. Missing steps read as undefined.',
    inputs: [V('in', 'from', { required: true })],
    outputs: OUT,
    group: 'Value',
  },
  template: {
    label: 'Text',
    hint: 'Build a string. Write {{a}}, {{b}} and {{c}} where the inputs go.',
    inputs: [V('a', 'a'), V('b', 'b'), V('c', 'c')],
    outputs: OUT,
    group: 'Value',
  },
  arith: {
    label: 'Arithmetic',
    hint: 'Add, subtract, multiply, divide or take a remainder.',
    inputs: [V('a', 'a', { required: true }), V('b', 'b', { required: true })],
    outputs: OUT,
    group: 'Value',
  },
  compare: {
    label: 'Compare',
    hint: 'Test two values. Produces a true or false.',
    inputs: [V('a', 'a', { required: true }), V('b', 'b')],
    outputs: [B('out', 'out')],
    group: 'Logic',
  },
  all: {
    label: 'AND',
    hint: 'True when every input is.',
    inputs: [B('in', 'in', { many: true, required: true })],
    outputs: [B('out', 'out')],
    group: 'Logic',
  },
  any: {
    label: 'OR',
    hint: 'True when any input is.',
    inputs: [B('in', 'in', { many: true, required: true })],
    outputs: [B('out', 'out')],
    group: 'Logic',
  },
  not: {
    label: 'NOT',
    hint: 'Inverts the one input wired into it.',
    inputs: [B('in', 'in', { required: true })],
    outputs: [B('out', 'out')],
    group: 'Logic',
  },
  select: {
    label: 'Choose',
    hint: 'One value when a test passes, another when it does not.',
    inputs: [B('cond', 'if', { required: true }), V('then', 'then'), V('else', 'else')],
    outputs: OUT,
    group: 'Logic',
  },
  call: {
    label: 'SDK call',
    hint: 'Call one joro.* method. Its inputs are the arguments the method takes.',
    inputs: [],
    outputs: OUT,
    group: 'Action',
  },
  storage: {
    label: 'Storage',
    hint: "This automation's own key/value store. Scoped to it and nothing else.",
    inputs: [V('key', 'key'), V('value', 'value')],
    outputs: OUT,
    group: 'Action',
  },
  log: {
    label: 'Log',
    hint: 'Write to the run log. Produces nothing.',
    inputs: [V('in', 'in', { many: true })],
    outputs: [],
    group: 'Action',
  },
  guard: {
    label: 'Stop unless',
    hint: 'Return early when a test fails, so nothing after it runs.',
    inputs: [B('cond', 'unless', { required: true }), V('value', 'return')],
    outputs: [],
    group: 'Control',
  },
  each: {
    label: 'For each',
    hint: 'Run the boxes between item and collect once per element.',
    inputs: [V('in', 'list', { required: true }), V('collect', 'collect')],
    outputs: [V('item', 'item'), V('index', 'index'), V('out', 'result')],
    group: 'Control',
  },
  return: {
    label: 'Return',
    hint: 'What the run produces. Exactly one, and it is where the graph ends.',
    inputs: [V('in', 'value')],
    outputs: [],
    singleton: true,
    hidden: true,
    group: 'Control',
  },
  body: {
    label: 'Code',
    hint: 'The automation body the graph does not author.',
    inputs: [V('in', 'started by', { many: true })],
    outputs: OUT,
    hidden: true,
    singleton: true,
  },
}

/** The operators a compare node offers, read the way the trigger canvas reads its own. */
export const COMPARE_OPS: Record<string, string> = {
  eq: 'is',
  ne: 'is not',
  gt: '>',
  lt: '<',
  gte: '>=',
  lte: '<=',
  contains: 'contains',
  prefix: 'starts with',
  suffix: 'ends with',
  matches: 'matches regex',
}

export const ARITH_OPS: Record<string, string> = {
  add: '+',
  sub: '-',
  mul: '×',
  div: '÷',
  mod: 'remainder',
}

export const STORAGE_ACTIONS: Record<string, string> = {
  get: 'read',
  set: 'write',
  delete: 'remove',
  keys: 'list keys',
}

/** Node sizes, fixed per type so an edge's endpoints are arithmetic rather than a
 *  measurement, and so Tidy's columns line up. A call node grows with its argument list. */
export function nodeSize(n: FlowNode, method?: SdkMethod): { width: number; height: number } {
  if (n.type === 'call') {
    const ports = callPorts(method)
    return { width: 240, height: Math.max(72, 44 + ports.length * 16) }
  }
  const spec = NODE_SPECS[n.type]
  const rows = Math.max(spec.inputs.length, spec.outputs.length)
  switch (n.type) {
    case 'all':
    case 'any':
    case 'not':
      return { width: 120, height: 52 }
    case 'trigger':
      return { width: 200, height: 68 }
    case 'return':
    case 'body':
      return { width: 200, height: 68 }
    default:
      return { width: 200, height: Math.max(60, 40 + rows * 16) }
  }
}

export const COL = 300
export const ROW = 130

// ---- SDK-driven ports ----

/** The argument ports of a call node, taken from the capability's own JSON Schema.
 *
 *  Generated rather than listed, so a capability that gains an argument gains a port with no
 *  frontend change — the same reason the trigger canvas builds its field selects from
 *  trigger.Fields() instead of naming the fields here. */
export function callPorts(method?: SdkMethod): FlowPort[] {
  const schema = method?.inputSchema as
    | { properties?: Record<string, { description?: string }>; required?: string[] }
    | undefined
  if (!schema?.properties) return []
  const required = new Set(schema.required ?? [])
  return Object.keys(schema.properties).map((name) =>
    V(name, name, { required: required.has(name) })
  )
}

/** Every input port of a node, whether fixed or derived. */
export function inputsOf(n: FlowNode, methods: SdkMethod[]): FlowPort[] {
  if (n.type === 'call') return callPorts(methods.find((m) => m.js === n.data?.method))
  return NODE_SPECS[n.type].inputs
}

export function outputsOf(n: FlowNode): FlowPort[] {
  return NODE_SPECS[n.type].outputs
}

// ---- graph helpers ----

export function findNode(g: FlowGraph, id: string): FlowNode | undefined {
  return g.nodes.find((n) => n.id === id)
}

export function nodeOfType(g: FlowGraph, type: FlowNodeType): FlowNode | undefined {
  return g.nodes.find((n) => n.type === type)
}

/** A node id nothing else is using. Sequential rather than random so a saved graph diffs
 *  cleanly and an operator reading the file can follow it. */
export function nextNodeId(g: FlowGraph, type: FlowNodeType): string {
  const prefix = type === 'call' ? 'call' : type
  for (let i = 1; ; i++) {
    const id = `${prefix}${i}`
    if (!g.nodes.some((n) => n.id === id)) return id
  }
}

/** The edges arriving at one port. */
export function edgesInto(g: FlowGraph, id: string, port?: string): FlowEdge[] {
  return g.edges.filter((e) => e.to === id && (port === undefined || e.toPort === port))
}

function portOf(ports: FlowPort[], id?: string): FlowPort | undefined {
  if (!id) return ports[0]
  return ports.find((p) => p.id === id)
}

/**
 * Whether an edge would be accepted. The port rules the canvas enforces while a wire is
 * being dragged, so a refusal is visible at the moment it happens rather than on save.
 */
export function canConnect(g: FlowGraph, e: FlowEdge, methods: SdkMethod[]): boolean {
  if (e.from === e.to) return false
  const a = findNode(g, e.from)
  const b = findNode(g, e.to)
  if (!a || !b) return false
  if (g.edges.some((x) => x.from === e.from && x.fromPort === e.fromPort && x.to === e.to && x.toPort === e.toPort)) {
    return false
  }

  const src = portOf(outputsOf(a), e.fromPort)
  const dst = portOf(inputsOf(b, methods), e.toPort)
  if (!src || !dst) return false
  // A boolean is a value, but a value is not a boolean: logic, choose and stop-unless take
  // nothing else, and accepting a string there is a bug that would only surface at run time.
  if (dst.kind === 'bool' && src.kind !== 'bool') return false

  // Arity. A port that takes one wire already has its answer.
  if (!dst.many && edgesInto(g, e.to, e.toPort).length >= 1) return false

  return !wouldCycle(g, e)
}

/**
 * Which loop each node belongs to, innermost first.
 *
 * A node inside two loops belongs to the inner one, which is what nesting means: the outer
 * loop emits the inner loop node, and the inner emits its own body. Resolved by taking the
 * smallest body that contains it, so nesting needs no separate notion of depth.
 */
export function loopOwners(g: FlowGraph): Map<string, string> {
  const bodies = g.nodes
    .filter((n) => n.type === 'each')
    .map((n) => ({ id: n.id, body: rawLoopBody(g, n.id) }))
    .sort((a, b) => a.body.size - b.body.size)

  const out = new Map<string, string>()
  for (const { id, body } of bodies) {
    for (const member of body) if (!out.has(member)) out.set(member, id)
  }
  // A loop node itself is emitted by whichever loop encloses it, never by its own body.
  for (const { id } of bodies) if (out.get(id) === id) out.delete(id)
  return out
}

/** The suffix marking the second half of a split loop node. */
export const LOOP_END = '#end'

/**
 * The graph with every `each` split into the two halves it actually is.
 *
 * A loop looks cyclic and is not. Its item and index outputs feed the body, and the body
 * feeds its collect input, so following the wires literally walks in a circle — but nothing
 * about that is a loop of *dependencies*: the entry half consumes the list and produces the
 * element, the body runs, and the exit half consumes what the body collected.
 *
 * Splitting it into `id` (consumes list, produces item and index) and `id#end` (consumes
 * collect, produces the result), joined by one edge, makes the whole thing an ordinary DAG.
 * Both the cycle check and the compiler's topological sort work on this, so neither has to
 * special-case a loop and they cannot disagree about what is inside one.
 */
export function splitLoops(g: FlowGraph, extra?: FlowEdge): { nodes: string[]; adj: Map<string, string[]> } {
  const edges = extra ? [...g.edges, extra] : g.edges
  const loops = g.nodes.filter((n) => n.type === 'each').map((n) => n.id)
  const isLoop = new Set(loops)
  const nodes: string[] = []
  for (const n of g.nodes) {
    nodes.push(n.id)
    if (isLoop.has(n.id)) nodes.push(n.id + LOOP_END)
  }

  const adj = new Map<string, string[]>(nodes.map((id) => [id, []]))
  const link = (from: string, to: string) => {
    if (!adj.has(from) || !adj.has(to) || from === to) return
    adj.get(from)!.push(to)
  }
  for (const id of loops) link(id, id + LOOP_END)

  for (const e of edges) {
    const from = isLoop.has(e.from) && e.fromPort !== 'item' && e.fromPort !== 'index' ? e.from + LOOP_END : e.from
    const to = isLoop.has(e.to) && e.toPort === 'collect' ? e.to + LOOP_END : e.to
    link(from, to)
  }

  // A box outside a loop that feeds one inside it has to be bound before the loop opens,
  // and no wire says so: the wire runs to the box in the body, which the loop emits, not to
  // the loop. Without this the two are unordered and a stable sort is free to declare the
  // outside box after the `for`, leaving the body reading a binding that does not exist yet.
  for (const id of loops) {
    const body = rawLoopBody(g, id, edges)
    for (const e of edges) {
      if (!body.has(e.to) || body.has(e.from) || e.from === id) continue
      link(isLoop.has(e.from) && e.fromPort !== 'item' && e.fromPort !== 'index' ? e.from + LOOP_END : e.from, id)
    }
  }
  return { nodes, adj }
}

/** Everything that depends on one loop's element, and therefore runs once per element.
 *
 *  Forward from item and index over the raw wires, stopping at the loop itself — reaching it
 *  again means arriving at collect, which is where the body ends. Depending on the element
 *  is the whole test: a box that reads it cannot be hoisted out, whether or not anything
 *  collects what it produces. */
function rawLoopBody(g: FlowGraph, loopId: string, edges: FlowEdge[] = g.edges): Set<string> {
  const out = new Set<string>()
  const queue = edges
    .filter((e) => e.from === loopId && (e.fromPort === 'item' || e.fromPort === 'index'))
    .map((e) => e.to)
  while (queue.length) {
    const id = queue.shift()!
    if (id === loopId || out.has(id)) continue
    out.add(id)
    for (const e of edges) if (e.from === id) queue.push(e.to)
  }
  return out
}

/** Whether adding an edge would close a loop of dependencies, judged on the split graph so a
 *  body wired back into its own loop's collect is allowed — that is what a loop is. */
function wouldCycle(g: FlowGraph, candidate: FlowEdge): boolean {
  const { adj } = splitLoops(g, candidate)
  const loops = new Set(g.nodes.filter((n) => n.type === 'each').map((n) => n.id))
  const start =
    loops.has(candidate.to) && candidate.toPort === 'collect' ? candidate.to + LOOP_END : candidate.to
  const target =
    loops.has(candidate.from) && candidate.fromPort !== 'item' && candidate.fromPort !== 'index'
      ? candidate.from + LOOP_END
      : candidate.from

  const seen = new Set<string>()
  const queue = [start]
  while (queue.length) {
    const id = queue.shift()!
    if (id === target) return true
    if (seen.has(id)) continue
    seen.add(id)
    for (const next of adj.get(id) ?? []) queue.push(next)
  }
  return false
}

export function addNode(
  g: FlowGraph,
  type: FlowNodeType,
  at: { x: number; y: number },
  data?: FlowNodeData
): FlowGraph {
  const id = nextNodeId(g, type)
  return { ...g, nodes: [...g.nodes, { id, type, x: at.x, y: at.y, ...(data ? { data } : {}) }] }
}

/** Remove a node and everything wired to it. The return node is never removable: a graph
 *  needs exactly one, and it is where the run ends. */
export function removeNode(g: FlowGraph, id: string): FlowGraph {
  const n = findNode(g, id)
  if (!n || n.type === 'return' || n.type === 'body') return g
  return {
    ...g,
    nodes: g.nodes.filter((x) => x.id !== id),
    edges: g.edges.filter((e) => e.from !== id && e.to !== id),
  }
}

export function patchNode(g: FlowGraph, id: string, p: Partial<FlowNode>): FlowGraph {
  return { ...g, nodes: g.nodes.map((n) => (n.id === id ? { ...n, ...p } : n)) }
}

/** Merge into a node's data rather than replacing it, so setting one field does not drop
 *  the rest of the configuration. */
export function patchData(g: FlowGraph, id: string, p: FlowNodeData): FlowGraph {
  return {
    ...g,
    nodes: g.nodes.map((n) => (n.id === id ? { ...n, data: { ...n.data, ...p } } : n)),
  }
}

export function removeEdge(g: FlowGraph, e: FlowEdge): FlowGraph {
  return {
    ...g,
    edges: g.edges.filter(
      (x) => !(x.from === e.from && x.fromPort === e.fromPort && x.to === e.to && x.toPort === e.toPort)
    ),
  }
}

/** Nodes nothing reaches from the return node, and that have no effect of their own.
 *
 *  A log or a call with nothing consuming it is not an orphan — its point is what it does,
 *  not what it produces. Everything else unreached is dead weight the operator built and
 *  then disconnected, which is worth saying because a disconnected condition reads as a
 *  narrowing that is not being applied. */
export function orphans(g: FlowGraph): string[] {
  const end = nodeOfType(g, 'return')
  const reached = new Set<string>()
  const queue: string[] = []
  const seed = (id: string) => {
    if (reached.has(id)) return
    reached.add(id)
    queue.push(id)
  }
  if (end) seed(end.id)
  for (const n of g.nodes) if (n.type === 'log' || n.type === 'call' || n.type === 'guard') seed(n.id)
  while (queue.length) {
    const id = queue.shift()!
    for (const e of g.edges) if (e.to === id) seed(e.from)
  }
  // A trigger box is a declaration, not a step: it says what wakes this automation, and it
  // does that whether or not anything reads the event. Flagging one as unreached would put a
  // warning on every automation that does not happen to inspect why it ran.
  return g.nodes
    .filter((n) => n.type !== 'return' && n.type !== 'trigger' && n.type !== 'body' && !reached.has(n.id))
    .map((n) => n.id)
}

/** Lay a graph out left to right in columns by depth from the return node. For the Tidy
 *  button, and for a graph that arrived without positions. */
export function tidy(g: FlowGraph, methods: SdkMethod[]): FlowGraph {
  // Depth is the longest path forward to a sink, so a node always sits left of everything it
  // feeds. Sinks — return, log, guard — are depth 0.
  const depth = new Map<string, number>()
  for (const n of g.nodes) if (outputsOf(n).length === 0) depth.set(n.id, 0)
  let changed = true
  let guard = 0
  while (changed && guard++ < g.nodes.length + 2) {
    changed = false
    for (const e of g.edges) {
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
    const col = maxDepth - (depth.get(n.id) ?? maxDepth)
    byColumn.set(col, [...(byColumn.get(col) ?? []), n.id])
  }

  const heights = new Map(g.nodes.map((n) => [n.id, nodeSize(n, methods.find((m) => m.js === n.data?.method)).height]))
  const placed = new Map<string, { x: number; y: number }>()
  for (const [col, ids] of byColumn) {
    let y = 0
    for (const id of ids) {
      placed.set(id, { x: col * COL, y })
      y += Math.max(ROW, (heights.get(id) ?? 60) + 40)
    }
  }
  return { ...g, nodes: g.nodes.map((n) => ({ ...n, ...(placed.get(n.id) ?? {}) })) }
}

// ---- seeds ----

/** The graph a new automation starts from: what woke it, and what it gives back.
 *
 *  Seeded here rather than served, unlike a trigger's seed, because nothing on the server
 *  reads this graph — it compiles in the browser and only the generated source crosses the
 *  wire. */
export function seedGraph(refs: string[]): FlowGraph {
  const nodes: FlowNode[] = refs.map((ref, i) => ({
    id: `trigger${i + 1}`,
    type: 'trigger',
    x: 0,
    y: i * ROW,
    data: { ref },
  }))
  nodes.push({ id: 'return', type: 'return', x: COL * 2, y: 0 })
  return { nodes, edges: [] }
}

/**
 * The graph with one trigger node per declared trigger, and none for a trigger the manifest
 * no longer names.
 *
 * The manifest is the authority on what wakes an automation — it is what the dispatcher
 * reads — so the canvas follows it rather than holding a second list that could disagree.
 * Positions of nodes that survive are kept, so ticking a trigger off and back on does not
 * scramble a layout.
 */
export function syncTriggerNodes(g: FlowGraph, refs: string[]): FlowGraph {
  const want = new Set(refs)
  const have = new Map(g.nodes.filter((n) => n.type === 'trigger').map((n) => [n.data?.ref ?? '', n]))
  if (refs.every((r) => have.has(r)) && have.size === want.size) return g

  const kept = g.nodes.filter((n) => n.type !== 'trigger' || want.has(n.data?.ref ?? ''))
  const dropped = [...have.entries()].filter(([ref]) => !want.has(ref)).map(([, n]) => n.id)
  const nodes = [...kept]
  let row = 0
  for (const ref of refs) {
    if (have.has(ref)) continue
    // Placed down the left edge, below whatever is already there, so a new trigger appears
    // in the region trigger nodes live in rather than under the cursor.
    while (nodes.some((n) => n.x === 0 && n.y === row * ROW)) row++
    nodes.push({ id: nextNodeId({ ...g, nodes }, 'trigger'), type: 'trigger', x: 0, y: row * ROW, data: { ref } })
    row++
  }
  return {
    ...g,
    nodes,
    edges: g.edges.filter((e) => !dropped.includes(e.from) && !dropped.includes(e.to)),
  }
}

/**
 * The wiring of an automation the graph does not author — hand-written code, or a command.
 *
 * Derived from the manifest every render and never stored: it holds nothing the manifest
 * does not already say, so persisting it would be a second copy of the trigger list that
 * could disagree with the first.
 */
export function wiringGraph(refs: string[], kind: string, lens?: { label: string }): FlowGraph {
  const nodes: FlowNode[] = refs.map((ref, i) => ({
    id: `trigger:${ref}`,
    type: 'trigger',
    x: 0,
    y: i * ROW,
    data: { ref },
  }))
  const mid = Math.max(0, ((refs.length - 1) * ROW) / 2)
  nodes.push({ id: 'body', type: 'body', x: COL, y: mid, data: { value: kind } })
  nodes.push({ id: 'return', type: 'return', x: COL * 2, y: mid, data: { value: lens?.label } })
  const edges: FlowEdge[] = refs.map((ref) => ({ from: `trigger:${ref}`, to: 'body', toPort: 'in' }))
  edges.push({ from: 'body', to: 'return', toPort: 'in' })
  return { nodes, edges }
}
