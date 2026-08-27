import type { SdkMethod } from './api'
import {
  LOOP_END,
  MAX_EDGES,
  MAX_NODES,
  NODE_SPECS,
  edgesInto,
  findNode,
  inputsOf,
  loopOwners,
  nodeOfType,
  splitLoops,
  type FlowGraph,
  type FlowNode,
} from './flowGraph'

/**
 * The flow graph, compiled to the `async function run(ctx)` the runtime already expects.
 *
 * This lives in the browser rather than in Go, unlike internal/trigger's compiler, and the
 * difference is what each one produces. A trigger compiles to an evaluator the dispatcher
 * runs on every event, so it has to exist where the events are. This produces source text
 * consumed by a save — the editor needs it live for the Code view anyway, and
 * POST /automation/scripts already takes {manifest, source}. It is the same shape as
 * lib/cmdline.ts: an author-time transformation whose *output* is the thing that gets stored
 * and enforced.
 *
 * Nothing about authority changes by generating code. A run's grants come from the SDK
 * bundle, never from what the source asks for, so generated JavaScript reaches exactly what
 * hand-written JavaScript reaches. The graph is not a permission surface and no token can
 * submit one — script.install has no graph argument, for the reason it has no lens argument.
 *
 * Every node becomes one `const`, in topological order, so a generated line maps to exactly
 * one box. jsruntime.Prepare documents that it preserves line numbers, which is what lets a
 * stack trace point back at the node an operator actually built.
 */

export interface CompileError {
  nodeId?: string
  message: string
}

export interface CompileResult {
  source: string
  /** 1-indexed generated line to the node that produced it, for mapping a runtime error
   *  back to a box. */
  lineMap: Record<number, string>
  errors: CompileError[]
}

/** A JS identifier for a node's result. Prefixed so a node id can never collide with a
 *  keyword or with the two names the wrapper introduces. */
function slot(id: string): string {
  return `_${id.replace(/[^A-Za-z0-9_]/g, '_')}`
}

function jsString(s: string): string {
  return JSON.stringify(s)
}

/** A dotted path as a chain of optional accesses, so a missing step reads as undefined
 *  rather than throwing halfway down. `a.b[0].c` and `a.0.c` both work. */
function accessPath(base: string, path: string): string {
  const parts = path
    .split(/[.[\]]+/)
    .map((p) => p.trim())
    .filter(Boolean)
  let out = base
  for (const p of parts) {
    out += /^\d+$/.test(p) ? `?.[${p}]` : /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(p) ? `?.${p}` : `?.[${jsString(p)}]`
  }
  return out
}

const BINARY: Record<string, string> = {
  eq: '===',
  ne: '!==',
  gt: '>',
  lt: '<',
  gte: '>=',
  lte: '<=',
  add: '+',
  sub: '-',
  mul: '*',
  div: '/',
  mod: '%',
}

export function compile(graph: FlowGraph, methods: SdkMethod[]): CompileResult {
  const errors: CompileError[] = []
  const push = (message: string, nodeId?: string) => errors.push({ nodeId, message })

  if (graph.nodes.length > MAX_NODES) push(`A graph holds at most ${MAX_NODES} boxes.`)
  if (graph.edges.length > MAX_EDGES) push(`A graph holds at most ${MAX_EDGES} wires.`)

  const end = nodeOfType(graph, 'return')
  if (!end) push('This graph has no Return box, so nothing says where the run ends.')

  // ---- the loop bodies ----
  //
  // An `each` owns everything downstream of its item and index outputs. Those nodes emit
  // inside the for-of rather than beside it, which is the one place the flat topological
  // order is not enough.
  const owner = loopOwners(graph)
  // The terminal is not per-element. Reaching it from a loop's item means the run's value
  // depends on a variable that only exists inside the loop, which has no reading.
  if (end && owner.has(end.id)) {
    push('Return reads a value that only exists inside a loop. Collect it and return that instead.', end.id)
    owner.delete(end.id)
  }

  // ---- order ----
  const order = topoSort(graph, push)

  // ---- required inputs ----
  for (const n of graph.nodes) {
    if (n.type === 'body') continue
    for (const p of inputsOf(n, methods)) {
      if (!p.required) continue
      const wired = edgesInto(graph, n.id, p.id).length > 0
      const literal = n.type === 'call' && (n.data?.args?.[p.id] ?? '').trim() !== ''
      if (!wired && !literal) {
        push(`${NODE_SPECS[n.type].label} needs something wired into "${p.label}".`, n.id)
      }
    }
  }

  // ---- emit ----
  const lines: string[] = []
  const lineMap: Record<number, string> = {}
  const emit = (text: string, nodeId?: string, indent = 1) => {
    lines.push('  '.repeat(indent) + text)
    if (nodeId) lineMap[lines.length + 1] = nodeId // +1 for the function signature line
  }

  /** The expression for whatever is wired into one port, or undefined when nothing is. */
  const inputExpr = (n: FlowNode, port: string): string | undefined => {
    const e = edgesInto(graph, n.id, port)[0]
    if (!e) return undefined
    const src = findNode(graph, e.from)
    if (!src) return undefined
    if (src.type === 'each') {
      if (e.fromPort === 'item') return `${slot(src.id)}_item`
      if (e.fromPort === 'index') return `${slot(src.id)}_i`
    }
    return slot(src.id)
  }

  const inputExprs = (n: FlowNode, port: string): string[] =>
    edgesInto(graph, n.id, port)
      .map((e) => {
        const src = findNode(graph, e.from)
        if (!src) return undefined
        if (src.type === 'each' && e.fromPort === 'item') return `${slot(src.id)}_item`
        if (src.type === 'each' && e.fromPort === 'index') return `${slot(src.id)}_i`
        return slot(src.id)
      })
      .filter((x): x is string => !!x)

  const expressionFor = (n: FlowNode): string | null => {
    const d = n.data ?? {}
    switch (n.type) {
      case 'trigger':
        return 'ctx.trigger'
      case 'context':
        return `ctx.${d.path ?? 'input'}`
      case 'literal': {
        const raw = (d.value ?? '').trim()
        if (raw === '') return 'null'
        try {
          return JSON.stringify(JSON.parse(raw))
        } catch {
          // Bare text is the common case and quoting it is what the operator meant; only a
          // value that looks like JSON and is not gets reported.
          if (/^[[{"]|^-?\d|^(true|false|null)$/.test(raw)) {
            push('This value is not valid JSON.', n.id)
            return 'null'
          }
          return jsString(raw)
        }
      }
      case 'get': {
        const from = inputExpr(n, 'in')
        if (!from) return 'undefined'
        return accessPath(from, d.get ?? '')
      }
      case 'template': {
        const text = d.template ?? ''
        // Built with a JSON string and concatenation rather than a template literal, so a
        // backtick or ${ in the operator's text cannot escape into the generated code.
        const parts: string[] = []
        let last = 0
        for (const m of text.matchAll(/\{\{([abc])\}\}/g)) {
          parts.push(jsString(text.slice(last, m.index)))
          parts.push(`String(${inputExpr(n, m[1]) ?? '""'})`)
          last = m.index + m[0].length
        }
        parts.push(jsString(text.slice(last)))
        return parts.filter((p) => p !== '""').join(' + ') || '""'
      }
      case 'arith': {
        const op = BINARY[d.op ?? 'add']
        if (!op) {
          push('Pick an operation.', n.id)
          return 'undefined'
        }
        return `(${inputExpr(n, 'a') ?? 'undefined'} ${op} ${inputExpr(n, 'b') ?? 'undefined'})`
      }
      case 'compare': {
        const a = inputExpr(n, 'a') ?? 'undefined'
        const b = inputExpr(n, 'b') ?? 'undefined'
        switch (d.op) {
          case 'contains':
            return `String(${a}).includes(String(${b}))`
          case 'prefix':
            return `String(${a}).startsWith(String(${b}))`
          case 'suffix':
            return `String(${a}).endsWith(String(${b}))`
          case 'matches':
            return `new RegExp(String(${b})).test(String(${a}))`
          default: {
            const op = BINARY[d.op ?? 'eq']
            if (!op) {
              push('Pick a comparison.', n.id)
              return 'false'
            }
            return `(${a} ${op} ${b})`
          }
        }
      }
      case 'all':
      case 'any': {
        const parts = inputExprs(n, 'in')
        if (parts.length === 0) return n.type === 'all' ? 'true' : 'false'
        return `(${parts.join(n.type === 'all' ? ' && ' : ' || ')})`
      }
      case 'not':
        return `!(${inputExpr(n, 'in') ?? 'undefined'})`
      case 'select':
        return `(${inputExpr(n, 'cond') ?? 'false'} ? ${inputExpr(n, 'then') ?? 'undefined'} : ${
          inputExpr(n, 'else') ?? 'undefined'
        })`
      case 'call': {
        const method = methods.find((m) => m.js === d.method)
        if (!method) {
          push(d.method ? `No SDK method called ${d.method}.` : 'Pick an SDK method.', n.id)
          return 'undefined'
        }
        const parts: string[] = []
        for (const p of inputsOf(n, methods)) {
          const wired = inputExpr(n, p.id)
          if (wired) {
            parts.push(`${JSON.stringify(p.id)}: ${wired}`)
            continue
          }
          const raw = (d.args?.[p.id] ?? '').trim()
          if (raw === '') continue
          try {
            parts.push(`${JSON.stringify(p.id)}: ${JSON.stringify(JSON.parse(raw))}`)
          } catch {
            parts.push(`${JSON.stringify(p.id)}: ${jsString(raw)}`)
          }
        }
        return `await ${method.js}({ ${parts.join(', ')} })`
      }
      case 'storage': {
        const key = inputExpr(n, 'key') ?? jsString(d.key ?? '')
        switch (d.action ?? 'get') {
          case 'set':
            return `joro.storage.set(${key}, ${inputExpr(n, 'value') ?? 'null'})`
          case 'delete':
            return `joro.storage.delete(${key})`
          case 'keys':
            return 'joro.storage.keys()'
          default:
            return `joro.storage.get(${key})`
        }
      }
      default:
        return null
    }
  }

  /** Whether anything reads what a node produces. */
  const consumed = (id: string) => graph.edges.some((e) => e.from === id)

  /** Boxes worth emitting only for what they produce. One of these with nothing wired out
   *  of it is a binding no line reads — the canvas already flags it as unreached, and
   *  emitting it anyway would put dead code in a file an operator is expected to read. */
  const PURE = new Set([
    'trigger',
    'context',
    'literal',
    'get',
    'template',
    'arith',
    'compare',
    'all',
    'any',
    'not',
    'select',
  ])

  /** Emit one node. Statement nodes write their own line; everything else binds a const. */
  const emitNode = (n: FlowNode, indent: number) => {
    if (PURE.has(n.type) && !consumed(n.id)) return
    switch (n.type) {
      case 'body':
        return
      case 'log': {
        const parts = inputExprs(n, 'in')
        emit(`console.log(${parts.join(', ') || '""'});`, n.id, indent)
        return
      }
      case 'guard': {
        const cond = inputExpr(n, 'cond') ?? 'true'
        const value = inputExpr(n, 'value') ?? 'undefined'
        emit(`if (!(${cond})) return ${value};`, n.id, indent)
        return
      }
      case 'each': {
        const list = inputExpr(n, 'in') ?? '[]'
        const collects = edgesInto(graph, n.id, 'collect').length > 0
        // Declared whether or not anything is collected, so a wire out of the loop's result
        // always has something to read — an empty array rather than a reference error.
        emit(`const ${slot(n.id)} = [];`, n.id, indent)
        emit(
          `for (const [${slot(n.id)}_i, ${slot(n.id)}_item] of Array.from(${list} ?? []).entries()) {`,
          n.id,
          indent
        )
        for (const id of order) {
          if (owner.get(id) !== n.id) continue
          const child = findNode(graph, id)
          if (child) emitNode(child, indent + 1)
        }
        if (collects) emit(`${slot(n.id)}.push(${inputExpr(n, 'collect') ?? 'undefined'});`, n.id, indent + 1)
        emit('}', n.id, indent)
        return
      }
      case 'return': {
        const v = inputExpr(n, 'in')
        emit(v ? `return ${v};` : 'return;', n.id, indent)
        return
      }
      default: {
        const expr = expressionFor(n)
        if (expr === null) return
        emit(`const ${slot(n.id)} = ${expr};`, n.id, indent)
      }
    }
  }

  for (const id of order) {
    // The exit half of a split loop is bookkeeping: the closing brace is written by the
    // entry half, which emits the whole construct in one go.
    if (id.endsWith(LOOP_END)) continue
    // A node inside a loop is emitted by the loop, not here.
    if (owner.has(id)) continue
    // The terminal is held back rather than taking its turn. Nothing depends on it, so a
    // topological order is free to place it before a box with no consumers — and every line
    // after a `return` is unreachable.
    if (id === end?.id) continue
    const n = findNode(graph, id)
    if (n) emitNode(n, 1)
  }
  if (end) emitNode(end, 1)

  const source = ['async function run(ctx) {', ...lines, '}', ''].join('\n')
  return { source, lineMap, errors }
}

/**
 * Nodes in an order where every input is bound before it is read.
 *
 * Kahn's algorithm over the split graph, with a stable tiebreak on the node's position in
 * the graph, so the same graph always generates byte-identical source — which is what makes
 * the source hash a usable staleness check rather than something that changes on every save.
 */
function topoSort(g: FlowGraph, push: (m: string, id?: string) => void): string[] {
  const { nodes, adj } = splitLoops(g)
  const index = new Map(nodes.map((id, i) => [id, i]))
  const indegree = new Map(nodes.map((id) => [id, 0]))
  for (const [, tos] of adj) for (const to of tos) indegree.set(to, (indegree.get(to) ?? 0) + 1)

  const ready = nodes.filter((id) => (indegree.get(id) ?? 0) === 0)
  const out: string[] = []
  while (ready.length) {
    ready.sort((a, b) => (index.get(a) ?? 0) - (index.get(b) ?? 0))
    const id = ready.shift()!
    out.push(id)
    for (const to of adj.get(id) ?? []) {
      const left = (indegree.get(to) ?? 0) - 1
      indegree.set(to, left)
      if (left === 0) ready.push(to)
    }
  }
  if (out.length !== nodes.length) {
    // canConnect refuses a wire that would close a loop, so this only happens to a graph
    // that arrived from somewhere else — an import, or a hand-edited file.
    const placed = new Set(out)
    for (const id of nodes) {
      if (!placed.has(id) && !id.endsWith(LOOP_END)) {
        push('This box is part of a loop of wires.', id)
      }
    }
  }
  return out
}
