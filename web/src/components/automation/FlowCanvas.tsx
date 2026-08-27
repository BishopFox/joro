import { useCallback, useMemo, useState, type RefObject } from 'react'
import {
  Background,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  Handle,
  Position,
  ReactFlow,
  getBezierPath,
  useConnection,
  useReactFlow,
  type Connection,
  type Edge as RFEdge,
  type EdgeChange,
  type EdgeProps,
  type Node as RFNode,
  type NodeChange,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import {
  ChevronDown,
  CornerDownLeft,
  Filter,
  LayoutGrid,
  Plus,
  Repeat,
  ScrollText,
  Terminal,
  Trash2,
  X,
  Zap,
} from 'lucide-react'
import type { SdkMethod, Trigger } from '../../lib/api'
import {
  NODE_SPECS,
  addNode,
  canConnect,
  findNode,
  inputsOf,
  nodeSize,
  orphans,
  outputsOf,
  patchNode,
  removeEdge,
  removeNode,
  tidy,
  type FlowGraph,
  type FlowNode,
  type FlowNodeType,
  type FlowPort,
} from '../../lib/flowGraph'
import FlowNodeInspector, { describeFlowNode } from './FlowNodeInspector'

/**
 * The automation canvas: drag boxes, add boxes, drag port to port to wire them.
 *
 * The same construction as TriggerCanvas, and deliberately so — an operator who has built a
 * trigger should not have to learn a second set of gestures. React Flow does pan, zoom,
 * dragging and selection; this file owns which ports exist, what may connect to what, and
 * what a node looks like.
 *
 * The graph stays the document. React Flow's nodes and edges are derived from it on every
 * render and never held as separate state, positions included, so a drag writes straight
 * back to the graph and there is no synchronisation step that can be skipped.
 *
 * One case has no document to write to. A hand-written script and a command automation are
 * shown as a wiring diagram — what wakes it, the body, what it produces — derived from the
 * manifest rather than stored, because it holds nothing the manifest does not. Its boxes
 * still drag: the positions live in this component and are forgotten on unmount, which is
 * the honest behaviour for a picture that is itself recomputed. Adding and removing a
 * trigger there is real, because that writes the manifest's trigger list.
 *
 * The rail lives outside this component — see FlowRail. The editor owns one rail for the
 * whole surface, so the automation's own settings and the selected box's are in the same
 * place rather than in two competing sidebars.
 */

/** How many times a new node steps clear of what it landed on before giving up. */
const MaxNudge = 12

interface NodeData extends Record<string, unknown> {
  node: FlowNode
  problem?: boolean
  errors?: string[]
  inputs: FlowPort[]
  outputs: FlowPort[]
  size: { width: number; height: number }
  label: string
  detail: string
  triggerLabel?: string
  triggerProblem?: string
}

export interface CanvasProps {
  graph: FlowGraph
  methods: SdkMethod[]
  onChange: (g: FlowGraph) => void
  /** Compile errors, keyed by the node that produced them. */
  errors?: Record<string, string[]>
  /** Trigger display names and problems by id, so a trigger node reads as what the operator
   *  named rather than as a bare reference. */
  triggerInfo?: Record<string, { name: string; on: string; problem?: string }>
  /** A derived wiring diagram: positions are local and there is nothing to rewire. */
  derived?: boolean
  selected: string | null
  onSelect: (id: string | null) => void
  /** Opens the trigger a trigger node stands for. */
  onEditTrigger?: (id: string) => void
  /** Opens the body a code or command node stands for. */
  onOpenBody?: () => void
  /** Removing a trigger box is removing the automation's declaration of it, which lives on
   *  the manifest — the box is only a picture of it. */
  onRemoveTrigger?: (ref: string) => void
  /** The canvas element, so the rail can place a new box in the middle of what is on
   *  screen rather than in the middle of the window. */
  wrapRef?: RefObject<HTMLDivElement | null>
}

export default function FlowCanvas({
  graph,
  methods,
  onChange,
  errors,
  triggerInfo,
  derived,
  selected,
  onSelect,
  onEditTrigger,
  onOpenBody,
  onRemoveTrigger,
  wrapRef,
}: CanvasProps) {
  // Positions for the derived diagram, which has no document to write them to. Held here
  // rather than pushed up, because they are worth exactly as much as the diagram is: it is
  // recomputed from the manifest on every render, so there is nothing to persist them to
  // that would not also be a second copy of the trigger list.
  const [localPos, setLocalPos] = useState<Record<string, { x: number; y: number }>>({})

  const positioned = useMemo(
    () =>
      derived
        ? { ...graph, nodes: graph.nodes.map((n) => ({ ...n, ...(localPos[n.id] ?? {}) })) }
        : graph,
    [graph, derived, localPos]
  )

  const loose = useMemo(() => new Set(orphans(positioned)), [positioned])

  // Derived on every render, which keeps one source of truth — but React Flow hangs its
  // measured dimensions off the node object it was given, and a rebuilt object has none.
  // During a drag that means every frame produces nodes of unknown size, which React Flow
  // will not paint until it has re-measured them: the whole canvas blinks. Declaring width
  // and height is what fixes it, and nodeSize is the same function the layout helpers use,
  // which is also what makes Tidy's columns line up.
  const nodes: RFNode<NodeData>[] = useMemo(
    () =>
      positioned.nodes.map((n) => {
        const method = methods.find((m) => m.js === n.data?.method)
        const info = n.type === 'trigger' ? triggerInfo?.[n.data?.ref ?? ''] : undefined
        return {
          id: n.id,
          type: rendererFor(n.type),
          position: { x: n.x, y: n.y },
          ...nodeSize(n, method),
          data: {
            node: n,
            problem: loose.has(n.id) || !!errors?.[n.id]?.length,
            errors: errors?.[n.id],
            inputs: inputsOf(n, methods),
            outputs: outputsOf(n),
            size: nodeSize(n, method),
            label: NODE_SPECS[n.type].label,
            detail: describeFlowNode(n, triggerInfo),
            triggerLabel: info?.name,
            triggerProblem: info?.problem,
          },
          selected: selected === n.id,
          // Everything drags, always. A diagram you cannot arrange is a diagram you cannot
          // read, and where a box sits costs nothing to honour even when it is not saved.
          draggable: true,
          deletable: !derived && n.type !== 'return' && n.type !== 'body',
        }
      }),
    [positioned, selected, loose, errors, methods, triggerInfo, derived]
  )

  const edges: RFEdge[] = useMemo(
    () =>
      positioned.edges.map((e) => ({
        id: edgeId(e.from, e.fromPort, e.to, e.toPort),
        source: e.from,
        sourceHandle: e.fromPort ?? null,
        target: e.to,
        targetHandle: e.toPort,
        type: derived ? 'default' : 'removable',
        animated: findNode(positioned, e.from)?.type === 'trigger',
        // The delete button removes the wire from the graph directly rather than through
        // React Flow's own setEdges. The graph is the document and these edges are derived
        // from it on every render, so an internal removal is undone by the next render
        // unless it happens to echo back as a change — which is a dependency on controlled
        // -state timing, not something to rely on for the only way to undo a connection.
        data: { onRemove: () => onChange(removeEdge(graph, e)) },
      })),
    [positioned, derived, graph, onChange]
  )

  const onNodesChange = useCallback(
    (changes: NodeChange<RFNode<NodeData>>[]) => {
      let next = graph
      for (const c of changes) {
        if (c.type === 'position' && c.position) {
          if (derived) {
            const at = c.position
            setLocalPos((p) => ({ ...p, [c.id]: at }))
          } else {
            next = patchNode(next, c.id, { x: c.position.x, y: c.position.y })
          }
        } else if (c.type === 'remove' && !derived) {
          const n = findNode(next, c.id)
          if (n?.type === 'trigger' && n.data?.ref) onRemoveTrigger?.(n.data.ref)
          else next = removeNode(next, c.id)
          if (selected === c.id) onSelect(null)
        } else if (c.type === 'select') {
          onSelect(c.selected ? c.id : null)
        }
      }
      if (next !== graph) onChange(next)
    },
    [graph, onChange, derived, selected, onSelect, onRemoveTrigger]
  )

  const onEdgesChange = useCallback(
    (changes: EdgeChange<RFEdge>[]) => {
      if (derived) return
      let next = graph
      for (const c of changes) {
        if (c.type !== 'remove') continue
        next = { ...next, edges: next.edges.filter((e) => edgeId(e.from, e.fromPort, e.to, e.toPort) !== c.id) }
      }
      if (next !== graph) onChange(next)
    },
    [graph, onChange, derived]
  )

  const onConnect = useCallback(
    (c: Connection) => {
      if (derived) return
      const e = asEdge(c)
      if (!e.from || !e.to || !canConnect(graph, e, methods)) return
      onChange({ ...graph, edges: [...graph.edges, e] })
    },
    [graph, onChange, methods, derived]
  )

  const isValidConnection = useCallback(
    (c: Connection | RFEdge) => !derived && canConnect(graph, asEdge(c), methods),
    [graph, methods, derived]
  )

  const nodeTypes = useMemo(
    () => ({ trigger: TriggerNode, terminal: TerminalNode, body: BodyNode, box: BoxNode }),
    []
  )
  const edgeTypes = useMemo(() => ({ removable: RemovableEdge }), [])

  return (
    <div ref={wrapRef} className="flex-1 min-h-0 rounded-sm border border-border overflow-hidden joro-flow">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        isValidConnection={isValidConnection}
        onPaneClick={() => onSelect(null)}
        onNodeDoubleClick={(_, n) => {
          const node = findNode(positioned, n.id)
          if (node?.type === 'trigger' && node.data?.ref) onEditTrigger?.(node.data.ref)
          if (node?.type === 'body') onOpenBody?.()
        }}
        fitView
        minZoom={0.2}
        maxZoom={2}
      >
        <Background />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  )
}

/** The palette, grouped so a list of sixteen reads as five short ones. */
const PALETTE: { group: string; types: FlowNodeType[] }[] = [
  { group: 'Source', types: ['context', 'literal'] },
  { group: 'Value', types: ['get', 'template', 'arith'] },
  { group: 'Logic', types: ['compare', 'all', 'any', 'not', 'select'] },
  { group: 'Action', types: ['call', 'storage', 'log'] },
  { group: 'Control', types: ['each', 'guard'] },
]

/**
 * The palette: everything that can be put on the canvas.
 *
 * A toolbar in the header rather than a column in the rail. Adding a box is a canvas action
 * and belongs over the canvas, and stacking fifteen buttons down a 18rem rail pushed the
 * automation's own settings — which is what a rail is for — below the fold.
 *
 * Mounted inside the same ReactFlowProvider as the canvas so Add can read the viewport and
 * put a new box in the middle of what is on screen.
 */
export function FlowPalette({
  graph,
  methods,
  onChange,
  onSelect,
  derived,
  triggers,
  declared,
  onAddTrigger,
  onPromote,
  wrapRef,
}: {
  graph: FlowGraph
  methods: SdkMethod[]
  onChange: (g: FlowGraph) => void
  onSelect: (id: string | null) => void
  derived?: boolean
  /** The whole catalog, so a trigger can be added by name. */
  triggers: Trigger[]
  /** The refs this automation already declares, which are the boxes already on the canvas. */
  declared: string[]
  onAddTrigger: (ref: string) => void
  /**
   * Give a hand-written automation a canvas, then apply the edit that asked for it.
   *
   * Present for a script whose body is still hand-written, and it fires silently: this
   * canvas is where an automation is authored, so adding a box to it is not a mode the
   * operator has to opt into first — it is the thing they just did. What it costs is stated
   * where the cost lands, on a banner above the canvas that stays up until they save or
   * detach. Absent for a command, which has no dataflow to author.
   */
  onPromote?: (apply: (g: FlowGraph) => FlowGraph) => void
  wrapRef?: RefObject<HTMLDivElement | null>
}) {
  const { screenToFlowPosition } = useReactFlow()
  const [triggerOpen, setTriggerOpen] = useState(false)
  // A derived diagram still offers the palette when there is something to promote to: the
  // canvas is how an automation is authored, and having to find that behind the code tab
  // made it look like a different feature.
  const authorable = !derived || !!onPromote

  /** Where a new box should land: the middle of the canvas, nudged clear of whatever is
   *  already there.
   *
   *  The centre of the *canvas*, not the window — they differ by the width of the rails, and
   *  the difference is enough to drop a box somewhere the operator is not looking. Landing
   *  exactly on top of an existing one looks like nothing happened. */
  const freeSpot = useCallback(
    (type: FlowNodeType) => {
      const box = wrapRef?.current?.getBoundingClientRect()
      const at = screenToFlowPosition(
        box
          ? { x: box.left + box.width / 2, y: box.top + box.height / 2 }
          : { x: window.innerWidth / 2, y: window.innerHeight / 2 }
      )
      const size = nodeSize({ id: '', type, x: 0, y: 0 })
      at.x -= size.width / 2
      at.y -= size.height / 2
      for (let i = 0; i < MaxNudge; i++) {
        const clash = graph.nodes.some((n) => {
          const s2 = nodeSize(n, methods.find((m) => m.js === n.data?.method))
          return (
            at.x < n.x + s2.width && at.x + size.width > n.x && at.y < n.y + s2.height && at.y + size.height > n.y
          )
        })
        if (!clash) break
        at.y += size.height + 24
      }
      return at
    },
    [graph, methods, screenToFlowPosition, wrapRef]
  )

  const add = useCallback(
    (type: FlowNodeType) => {
      // Seeded so a new box is already valid rather than flagged until it is filled in.
      const seed =
        type === 'context'
          ? { path: 'input' as const }
          : type === 'compare'
            ? { op: 'eq' }
            : type === 'arith'
              ? { op: 'add' }
              : type === 'storage'
                ? { action: 'get' }
                : type === 'call'
                  ? { method: methods[0]?.js }
                  : undefined
      const at = freeSpot(type)
      // On a derived diagram the box cannot be added to what is on screen — there is
      // nothing to add it to. Promotion builds the real graph and the box lands on that,
      // so the click does what it looked like it would.
      if (derived && onPromote) {
        onPromote((g) => addNode(g, type, at, seed))
        return
      }
      const next = addNode(graph, type, at, seed)
      onChange(next)
      onSelect(next.nodes[next.nodes.length - 1].id)
    },
    [graph, methods, onChange, onSelect, freeSpot, derived, onPromote]
  )

  const addable = triggers.filter((t) => !declared.includes(t.id))
  const btn =
    'inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover disabled:opacity-40'

  // A fragment, not a row: the header decides where these sit and how they wrap, because it
  // is the header that has to keep them level with the action buttons above them.
  return (
    <>
      <div className="relative">
        <button
          onClick={() => setTriggerOpen((o) => !o)}
          disabled={addable.length === 0}
          title={addable.length === 0 ? 'Every trigger is already on the canvas' : 'Add a trigger box'}
          className={`${btn} text-accent-secondary`}
        >
          <Plus size={10} strokeWidth={2.4} aria-hidden="true" />
          Trigger
          <ChevronDown size={9} strokeWidth={2.4} aria-hidden="true" />
        </button>
        {triggerOpen && (
          <>
            {/* A backdrop rather than a blur handler: a click on one of the items below must
                land before the menu closes. */}
            <div className="fixed inset-0 z-20" onClick={() => setTriggerOpen(false)} />
            <div className="absolute left-0 top-full mt-1 z-30 w-56 max-h-64 overflow-y-auto bg-surface-card border border-border rounded-sm shadow-sm py-1">
              {addable.map((t) => (
                <button
                  key={t.id}
                  onClick={() => {
                    setTriggerOpen(false)
                    onAddTrigger(t.id)
                  }}
                  title={t.description}
                  className="w-full text-left px-2.5 py-1 text-[11px] text-content-secondary hover:bg-surface-hover hover:text-content-primary"
                >
                  <span className="truncate block">{t.builtin ? t.id : t.name}</span>
                  {!t.builtin && <span className="block text-[9px] font-mono text-content-muted">{t.on}</span>}
                </button>
              ))}
            </div>
          </>
        )}
      </div>

      {!derived && (
        <button onClick={() => onChange(tidy(graph, methods))} className={`${btn} text-content-secondary`} title="Lay the graph out again">
          <LayoutGrid size={10} strokeWidth={2.4} aria-hidden="true" />
          Tidy
        </button>
      )}

      {authorable &&
        PALETTE.map((g) => (
          <div key={g.group} className="flex items-center gap-1">
            {/* A rule and a group name, so a run of fifteen buttons still reads as five
                short lists rather than one long one. */}
            <span className="ml-1 pl-2 border-l border-border-subtle text-[9px] uppercase tracking-wide text-content-muted">
              {g.group}
            </span>
            {g.types.map((t) => (
              <button key={t} onClick={() => add(t)} title={NODE_SPECS[t].hint} className={`${btn} text-content-secondary`}>
                <Plus size={10} strokeWidth={2.4} aria-hidden="true" />
                {NODE_SPECS[t].label}
              </button>
            ))}
          </div>
        ))}
    </>
  )
}

/**
 * The fields for whichever box is selected, and what the canvas has to say about itself.
 *
 * Rendered by the editor into its one rail, under the automation's own settings.
 */
export function FlowRail({
  graph,
  methods,
  onChange,
  selected,
  onSelect,
  errors,
  derived,
  onRemoveTrigger,
  onEditTrigger,
  onOpenBody,
}: {
  graph: FlowGraph
  methods: SdkMethod[]
  onChange: (g: FlowGraph) => void
  selected: string | null
  onSelect: (id: string | null) => void
  errors?: Record<string, string[]>
  derived?: boolean
  onRemoveTrigger: (ref: string) => void
  onEditTrigger?: (id: string) => void
  onOpenBody?: () => void
}) {
  const loose = useMemo(() => new Set(orphans(graph)), [graph])
  const active = selected ? findNode(graph, selected) : undefined

  return (
    <div className="space-y-2">
      <ConnectionHint />

      {derived && (
        <p className="text-[10px] text-content-muted leading-snug">
          This diagram is read from the manifest, so there is nothing to rewire. Boxes still move,
          and adding or removing a trigger is real.
        </p>
      )}

      {loose.size > 0 && (
        <p className="text-[10px] text-semantic-warning leading-snug">
          {loose.size} box{loose.size === 1 ? '' : 'es'} not reached from Return and with no effect of
          their own. Nothing runs them.
        </p>
      )}

      <div className="border-t border-border-subtle pt-2">
        <div className="text-[10px] uppercase tracking-wide text-content-muted mb-1">
          {active ? NODE_SPECS[active.type].label : 'Nothing selected'}
        </div>
        {!active ? (
          <p className="text-[10px] text-content-muted leading-snug">
            Click a box to edit it. Drag from a port to wire two together, and drag a box to move it
            {derived ? '.' : ' — where you leave it is saved.'}
          </p>
        ) : (
          <div className="space-y-2">
            {errors?.[active.id]?.map((e, i) => (
              <p key={i} className="text-[10px] text-semantic-error leading-snug">
                {e}
              </p>
            ))}
            <FlowNodeInspector
              graph={graph}
              node={active}
              methods={methods}
              readOnly={!!derived}
              onChange={onChange}
              onEditTrigger={onEditTrigger}
              onOpenBody={onOpenBody}
            />
            {active.type === 'trigger' && active.data?.ref && (
              <button
                onClick={() => {
                  onRemoveTrigger(active.data!.ref!)
                  onSelect(null)
                }}
                className="inline-flex items-center gap-1 text-[10px] text-semantic-error hover:underline"
              >
                <Trash2 size={10} strokeWidth={2} aria-hidden="true" />
                Remove trigger
              </button>
            )}
            {!derived && active.type !== 'return' && active.type !== 'body' && active.type !== 'trigger' && (
              <button
                onClick={() => {
                  onChange(removeNode(graph, active.id))
                  onSelect(null)
                }}
                className="inline-flex items-center gap-1 text-[10px] text-semantic-error hover:underline"
              >
                <Trash2 size={10} strokeWidth={2} aria-hidden="true" />
                Remove
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function asEdge(c: Connection | RFEdge) {
  return {
    from: c.source,
    fromPort: c.sourceHandle ?? undefined,
    to: c.target,
    toPort: c.targetHandle ?? '',
  }
}

function edgeId(from: string, fromPort: string | undefined, to: string, toPort: string): string {
  return `${from}:${fromPort ?? ''}->${to}:${toPort}`
}

/** Which renderer draws a node. Most are the same box with different ports, which is the
 *  point — the shape of a box should say how it connects, not what it is called. */
function rendererFor(t: FlowNodeType): string {
  if (t === 'trigger') return 'trigger'
  if (t === 'return') return 'terminal'
  if (t === 'body') return 'body'
  return 'box'
}

/** What is being dragged, and why some targets will not take it. Without this the rule is
 *  invisible: a value dropped on a boolean port simply vanishes, which reads as the canvas
 *  being broken rather than as the connection being refused. */
function ConnectionHint() {
  const conn = useConnection()
  if (!conn.inProgress) return null
  return (
    <p className="text-[10px] text-semantic-info leading-snug">
      Drop on an input port. A port already holding a wire will not take a second unless it
      says it combines them, and only a true/false reaches AND, OR, NOT, Choose and Stop
      unless.
    </p>
  )
}

/** An edge with a delete button on it. React Flow will delete a selected edge on the Delete
 *  key, which is no use to anyone who has not been told. */
function RemovableEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  style,
  data,
}: EdgeProps) {
  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })
  const remove = (data as { onRemove?: () => void } | undefined)?.onRemove
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} />
      <EdgeLabelRenderer>
        <button
          // pointer-events has to be turned back on: the label layer disables it so edges do
          // not swallow clicks meant for the canvas.
          className="joro-edge-remove nodrag nopan"
          style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
          onClick={() => remove?.()}
          title="Remove this connection"
          aria-label="Remove this connection"
        >
          <X size={9} strokeWidth={3} aria-hidden="true" />
        </button>
      </EdgeLabelRenderer>
    </>
  )
}

// ---- node renderers ----

const handleCls = '!w-2 !h-2 !border-2 !bg-surface-card'

function shell(selected: boolean, problem: boolean, accent: string) {
  return `rounded-sm border bg-surface-card px-2.5 py-1.5 ${
    problem ? 'border-semantic-warning' : selected ? 'border-accent' : accent
  }`
}

/** Whether this port can end the connection currently being dragged.
 *
 *  Handed to React Flow as isConnectableEnd rather than only being refused on drop, which is
 *  what makes the rule visible: a handle that cannot end the drag stops advertising itself as
 *  a target and the CSS in index.css fades it. */
function useAcceptsEnd(kind: 'value' | 'bool'): boolean {
  const conn = useConnection()
  if (!conn.inProgress) return true
  if (kind !== 'bool') return true
  // A boolean port only takes a boolean, and the only boxes that make one say so in their
  // output list. The arity and cycle checks still happen on drop.
  const from = conn.fromNode?.data as NodeData | undefined
  const out = from?.outputs?.find((p) => p.id === (conn.fromHandle?.id ?? from?.outputs?.[0]?.id))
  return out?.kind === 'bool'
}

/**
 * What one port carries and where it may go, for its tooltip.
 *
 * A port's shape says it takes a wire and its colour says which kind, and neither says what
 * to do with it — which is the question in front of someone looking at a trigger's out for
 * the first time. Naming the boxes that accept it turns the palette from a list into a set
 * of next steps.
 */
function portHelp(node: FlowNode, port: FlowPort, side: 'target' | 'source'): string {
  if (side === 'source') {
    if (node.type === 'trigger') {
      return (
        'Carries ctx.trigger — why this run happened, including which trigger fired. ' +
        'Drop it on Read field to pull one property out, or on any argument of an SDK call.'
      )
    }
    if (node.type === 'each' && port.id === 'item') {
      return 'One element of the list, inside the loop. Everything wired to this runs once per element.'
    }
    if (node.type === 'each' && port.id === 'index') {
      return 'The position of the current element, counting from zero.'
    }
    if (node.type === 'each') {
      return 'Everything collected by the loop, as an array. Available after the loop has finished.'
    }
    return port.kind === 'bool'
      ? 'Carries a true or false. Only AND, OR, NOT, Choose and Stop unless accept one.'
      : 'Carries a value. Drop it on any input port — Read field, Text, Compare, or an argument of an SDK call.'
  }

  const many = port.many ? ' Takes more than one wire.' : ' Takes one wire.'
  const req = port.required ? ' Required.' : ''
  return port.kind === 'bool'
    ? `Accepts a true or false — from Compare, AND, OR or NOT.${many}${req}`
    : `Accepts any value.${many}${req}`
}

/** The stack of input handles down the left edge, and outputs down the right. Positioned by
 *  arithmetic off the node's own fixed height, which is why nodeSize is shared with the
 *  layout helpers rather than measured. */
function Ports({ data }: { data: NodeData }) {
  const rowY = (i: number, total: number) => 24 + (i * (data.size.height - 32)) / Math.max(1, total)
  return (
    <>
      {data.inputs.map((p, i) => (
        <PortHandle key={p.id} node={data.node} port={p} side="target" top={rowY(i, data.inputs.length)} />
      ))}
      {data.outputs.map((p, i) => (
        <PortHandle key={p.id} node={data.node} port={p} side="source" top={rowY(i, data.outputs.length)} />
      ))}
    </>
  )
}

function PortHandle({
  node,
  port,
  side,
  top,
}: {
  node: FlowNode
  port: FlowPort
  side: 'target' | 'source'
  top: number
}) {
  const accepts = useAcceptsEnd(port.kind)
  const border = port.kind === 'bool' ? '!border-accent-tertiary' : '!border-border'
  const help = portHelp(node, port, side)
  return (
    <>
      <Handle
        id={port.id}
        type={side}
        position={side === 'target' ? Position.Left : Position.Right}
        isConnectableEnd={side === 'target' ? accepts : undefined}
        style={{ top }}
        title={help}
        className={`${handleCls} ${border}`}
      />
      {/* The label carries the same tooltip. The handle is eight pixels across, which is a
          small target to have to find before the explanation appears. */}
      <span
        className="absolute text-[8px] text-content-muted cursor-help"
        style={{ top: top - 6, [side === 'target' ? 'left' : 'right']: 6 }}
        title={help}
      >
        {port.label}
      </span>
    </>
  )
}

function BoxNode({ data, selected }: NodeProps<RFNode<NodeData>>) {
  const Icon =
    data.node.type === 'call'
      ? Zap
      : data.node.type === 'log'
        ? ScrollText
        : data.node.type === 'each'
          ? Repeat
          : Filter
  return (
    <div className={`${shell(!!selected, !!data.problem, 'border-border')} relative`} style={data.size}>
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-semantic-info mb-0.5 px-3">
        <Icon size={10} strokeWidth={2.4} aria-hidden="true" />
        <span className="truncate">{data.label}</span>
      </div>
      <div className="text-[10px] font-mono text-content-secondary leading-snug line-clamp-2 break-all px-3">
        {data.detail}
      </div>
      <Ports data={data} />
    </div>
  )
}

function TriggerNode({ data, selected }: NodeProps<RFNode<NodeData>>) {
  return (
    <div
      className={`${shell(!!selected, !!data.triggerProblem, 'border-accent-secondary')} relative`}
      style={data.size}
    >
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-accent-secondary mb-0.5">
        <Zap size={10} strokeWidth={2.4} aria-hidden="true" />
        Trigger
      </div>
      <div className="text-[11px] text-content-primary truncate">{data.triggerLabel ?? data.node.data?.ref}</div>
      <div className="text-[9px] font-mono text-content-muted truncate">{data.detail}</div>
      {data.triggerProblem && <div className="text-[9px] text-semantic-error truncate">broken</div>}
      <Ports data={data} />
    </div>
  )
}

function BodyNode({ data, selected }: NodeProps<RFNode<NodeData>>) {
  const command = data.node.data?.value === 'command'
  return (
    <div className={`${shell(!!selected, !!data.problem, 'border-border')} relative`} style={data.size}>
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-content-muted mb-0.5 px-3">
        <Terminal size={10} strokeWidth={2.4} aria-hidden="true" />
        {command ? 'Command' : 'Code'}
      </div>
      <div className="text-[10px] font-mono text-content-secondary leading-snug line-clamp-2 break-all px-3">
        {data.detail}
      </div>
      <Ports data={data} />
    </div>
  )
}

function TerminalNode({ data, selected }: NodeProps<RFNode<NodeData>>) {
  const lens = data.node.data?.value
  return (
    <div className={`${shell(!!selected, !!data.problem, 'border-accent-tertiary')} relative`} style={data.size}>
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-accent-tertiary mb-0.5 px-3">
        <CornerDownLeft size={10} strokeWidth={2.4} aria-hidden="true" />
        {lens ? 'Viewer tab' : 'Return'}
      </div>
      <div className="text-[10px] text-content-secondary truncate px-3">{lens ?? data.detail}</div>
      <Ports data={data} />
    </div>
  )
}
