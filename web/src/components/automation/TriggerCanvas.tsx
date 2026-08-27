import { useCallback, useMemo, useRef, useState } from 'react'
import {
  Background,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  Handle,
  Position,
  ReactFlow,
  ReactFlowProvider,
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
import { Filter, LayoutGrid, Play, Plus, Trash2, X, Zap } from 'lucide-react'
import type { TriggerFieldSpec, TriggerGraph, TriggerNode, TriggerNodeType } from '../../lib/api'
import {
  ADDABLE,
  NODE_LABEL,
  NODE_SIZE,
  addNode,
  canConnect,
  describeNode,
  findNode,
  orphans,
  patchNode,
  removeNode,
  tidy,
} from '../../lib/triggerGraph'
import TriggerConditionFields from './TriggerConditionFields'

/**
 * The visual editor: drag boxes, add boxes, drag port to port to wire them.
 *
 * React Flow does the canvas — pan, zoom, node dragging, connection dragging, selection —
 * and this file owns the domain: which ports exist, what may connect to what, and what a
 * node looks like. The alternative was around eight hundred lines of bespoke pointer
 * handling for the same result.
 *
 * The graph stays the document. React Flow's nodes and edges are derived from it on every
 * render and never held as separate state, so there is one source of truth and no
 * synchronisation step that can be skipped — positions included, which is why a drag
 * writes straight back to the graph.
 *
 * Handles are typed. An event output only reaches a condition's event input, and booleans
 * only reach logic and the run node; canConnect mirrors the server's port rules so an
 * invalid wire is refused while it is being dragged rather than on save.
 */

/** How many times a new node steps clear of what it landed on before giving up. */
const MaxNudge = 12

interface NodeData extends Record<string, unknown> {
  node: TriggerNode
  problem?: boolean
  /** The event this trigger watches. Carried on the event node so it shows what it is
   *  subscribed to rather than its own id, which is only ever "event". */
  on?: string
}

export default function TriggerCanvas(props: {
  graph: TriggerGraph
  fields: TriggerFieldSpec[]
  valueLen: number
  on: string
  onChange: (g: TriggerGraph) => void
}) {
  // The provider is what gives screenToFlowPosition, which turns a drop point into graph
  // coordinates. Without it a node added by drop lands wherever the last pan left it.
  return (
    <ReactFlowProvider>
      <Canvas {...props} />
    </ReactFlowProvider>
  )
}

function Canvas({
  graph,
  fields,
  valueLen,
  on,
  onChange,
}: {
  graph: TriggerGraph
  fields: TriggerFieldSpec[]
  valueLen: number
  on: string
  onChange: (g: TriggerGraph) => void
}) {
  const [selected, setSelected] = useState<string | null>(null)
  const { screenToFlowPosition } = useReactFlow()
  const wrap = useRef<HTMLDivElement>(null)

  const loose = useMemo(() => new Set(orphans(graph)), [graph])

  // Nodes are derived from the graph on every render, which keeps one source of truth —
  // but React Flow hangs its measured dimensions off the node object it was given, and a
  // rebuilt object has none. During a drag that means every frame produces nodes of
  // unknown size, which React Flow will not paint until it has re-measured them: the
  // whole canvas blinks.
  //
  // Declaring width and height is what fixes it. These are the sizes the renderers are
  // already fixed to, so there was never anything to measure — NODE_SIZE is the same
  // constant the layout helpers use, which is also what makes Tidy's columns line up.
  const nodes: RFNode<NodeData>[] = useMemo(
    () =>
      graph.nodes.map((n) => ({
        id: n.id,
        type: n.type === 'condition' ? 'condition' : n.type === 'event' || n.type === 'fire' ? n.type : 'logic',
        position: { x: n.x, y: n.y },
        width: NODE_SIZE[n.type].width,
        height: NODE_SIZE[n.type].height,
        data: { node: n, problem: loose.has(n.id), on },
        selected: selected === n.id,
        // The event and run nodes are permanent, so they are draggable but never
        // removable; React Flow's own delete key would otherwise take them.
        deletable: n.type !== 'event' && n.type !== 'fire',
      })),
    [graph, selected, loose, on]
  )

  const edges: RFEdge[] = useMemo(
    () =>
      graph.edges.map((e) => ({
        id: `${e.from}->${e.to}`,
        source: e.from,
        target: e.to,
        type: 'removable',
        animated: findNode(graph, e.from)?.type === 'event',
      })),
    [graph]
  )

  const onNodesChange = useCallback(
    (changes: NodeChange<RFNode<NodeData>>[]) => {
      let next = graph
      for (const c of changes) {
        if (c.type === 'position' && c.position) {
          next = patchNode(next, c.id, { x: c.position.x, y: c.position.y })
        } else if (c.type === 'remove') {
          next = removeNode(next, c.id)
          setSelected((s) => (s === c.id ? null : s))
        } else if (c.type === 'select') {
          setSelected(c.selected ? c.id : null)
        }
      }
      if (next !== graph) onChange(next)
    },
    [graph, onChange]
  )

  const onEdgesChange = useCallback(
    (changes: EdgeChange<RFEdge>[]) => {
      let next = graph
      for (const c of changes) {
        if (c.type === 'remove') {
          const [from, to] = c.id.split('->')
          next = { ...next, edges: next.edges.filter((e) => !(e.from === from && e.to === to)) }
        }
      }
      if (next !== graph) onChange(next)
    },
    [graph, onChange]
  )

  const onConnect = useCallback(
    (c: Connection) => {
      if (!c.source || !c.target || !canConnect(graph, c.source, c.target)) return
      onChange({ ...graph, edges: [...graph.edges, { from: c.source, to: c.target }] })
    },
    [graph, onChange]
  )

  const isValidConnection = useCallback(
    (c: Connection | RFEdge) => !!c.source && !!c.target && canConnect(graph, c.source, c.target),
    [graph]
  )

  /** Add a node in the middle of the canvas, nudged clear of whatever is already there.
   *
   *  The centre of the *canvas*, not the window — they are different by the width of the
   *  sidebar and the palette rail, and the difference is enough to drop a node under the
   *  cursor rather than where the operator is looking. The nudge matters as much: landing
   *  exactly on top of an existing box looks like nothing happened. */
  const add = useCallback(
    (type: TriggerNodeType) => {
      const box = wrap.current?.getBoundingClientRect()
      const at = screenToFlowPosition(
        box
          ? { x: box.left + box.width / 2, y: box.top + box.height / 2 }
          : { x: window.innerWidth / 2, y: window.innerHeight / 2 }
      )
      const size = NODE_SIZE[type]
      at.x -= size.width / 2
      at.y -= size.height / 2
      // Step down past anything overlapping. Bounded so a crowded canvas cannot spin.
      for (let i = 0; i < MaxNudge; i++) {
        const clash = graph.nodes.some((n) => {
          const s2 = NODE_SIZE[n.type]
          return (
            at.x < n.x + s2.width &&
            at.x + size.width > n.x &&
            at.y < n.y + s2.height &&
            at.y + size.height > n.y
          )
        })
        if (!clash) break
        at.y += size.height + 24
      }
      const seed =
        type === 'condition' && fields.length > 0
          ? {
              field: fields[0].name,
              op: fields[0].ops[0],
              // A field with a closed set starts on a member of it, so a new condition is
              // valid the moment it appears rather than flagged until it is filled in.
              value: fields[0].values?.[0] ?? '',
            }
          : undefined
      const next = addNode(graph, type, at, seed)
      onChange(next)
      setSelected(next.nodes[next.nodes.length - 1].id)
    },
    [graph, fields, onChange, screenToFlowPosition]
  )

  const nodeTypes = useMemo(
    () => ({ event: EventNode, condition: ConditionNode, logic: LogicNode, fire: FireNode }),
    []
  )
  const edgeTypes = useMemo(() => ({ removable: RemovableEdge }), [])

  const active = selected ? findNode(graph, selected) : undefined

  return (
    <div className="flex flex-1 min-h-0 gap-2">
      <div
        ref={wrap}
        className="flex-1 min-h-0 rounded-sm border border-border overflow-hidden joro-flow"
      >
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          isValidConnection={isValidConnection}
          onPaneClick={() => setSelected(null)}
          fitView
          proOptions={{ hideAttribution: false }}
          minZoom={0.2}
          maxZoom={2}
        >
          <Background />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>

      <div className="w-64 shrink-0 space-y-2 overflow-y-auto">
        <div>
          <div className="text-[10px] uppercase tracking-wide text-content-muted mb-1">Add</div>
          <div className="flex flex-wrap gap-1">
            {ADDABLE.map((t) => (
              <button
                key={t}
                onClick={() => add(t)}
                disabled={t === 'condition' && fields.length === 0}
                className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-40"
              >
                <Plus size={10} strokeWidth={2.4} aria-hidden="true" />
                {NODE_LABEL[t]}
              </button>
            ))}
            <button
              onClick={() => onChange(tidy(graph))}
              className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
              title="Lay the graph out again"
            >
              <LayoutGrid size={10} strokeWidth={2.4} aria-hidden="true" />
              Tidy
            </button>
          </div>
        </div>

        <ConnectionHint />

        {loose.size > 0 && (
          <p className="text-[10px] text-semantic-warning leading-snug">
            {loose.size} node{loose.size === 1 ? '' : 's'} not connected to Run. They do nothing,
            so this fires more broadly than it looks.
          </p>
        )}

        <div className="border-t border-border-subtle pt-2">
          <div className="text-[10px] uppercase tracking-wide text-content-muted mb-1">
            {active ? NODE_LABEL[active.type] : 'Nothing selected'}
          </div>
          {!active && (
            <p className="text-[10px] text-content-muted leading-snug">
              Click a box to edit it. Drag from a port to wire two together, and drag a box to
              move it &mdash; where you leave it is saved.
            </p>
          )}
          {active?.type === 'condition' && (
            <div className="space-y-2">
              <TriggerConditionFields
                fields={fields}
                node={active}
                valueLen={valueLen}
                layout="stack"
                onChange={(p) => onChange(patchNode(graph, active.id, p))}
              />
              <button
                onClick={() => {
                  onChange(removeNode(graph, active.id))
                  setSelected(null)
                }}
                className="inline-flex items-center gap-1 text-[10px] text-semantic-error hover:underline"
              >
                <Trash2 size={10} strokeWidth={2} aria-hidden="true" />
                Remove
              </button>
            </div>
          )}
          {active && active.type !== 'condition' && active.type !== 'event' && active.type !== 'fire' && (
            <div className="space-y-2">
              <p className="text-[10px] text-content-muted leading-snug">
                {active.type === 'not'
                  ? 'Inverts the one input wired into it.'
                  : `Passes when ${active.type === 'all' ? 'every' : 'any'} input wired into it does.`}
              </p>
              <button
                onClick={() => {
                  onChange(removeNode(graph, active.id))
                  setSelected(null)
                }}
                className="inline-flex items-center gap-1 text-[10px] text-semantic-error hover:underline"
              >
                <Trash2 size={10} strokeWidth={2} aria-hidden="true" />
                Remove
              </button>
            </div>
          )}
          {active?.type === 'event' && (
            <p className="text-[10px] text-content-muted leading-snug">
              <code className="font-mono text-accent-secondary">{on}</code>. Every condition reads
              from this. Change it at the top of the editor.
            </p>
          )}
          {active?.type === 'fire' && (
            <p className="text-[10px] text-content-muted leading-snug">
              Wire one input here to say when this trigger fires. Nothing wired means every event
              fires it.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

/** What is being dragged, and why some targets will not take it.
 *
 *  Without this the rule is invisible: a boolean dropped on a condition simply vanishes,
 *  which reads as the canvas being broken rather than as the connection being refused. */
function ConnectionHint() {
  const conn = useConnection()
  if (!conn.inProgress) return null
  const fromEvent = conn.fromNode?.type === 'event'
  return (
    <p className="text-[10px] text-semantic-info leading-snug">
      {fromEvent
        ? 'Drop on a condition. The event feeds conditions; only they read from it.'
        : 'Drop on AND, OR, NOT or Run. Two conditions combine through a logic node rather ' +
          'than by connecting to each other.'}
    </p>
  )
}

/** Whether this node's input can end the connection currently being dragged.
 *
 *  Handed to React Flow as isConnectableEnd rather than only being refused on drop, which
 *  is what makes the rule visible: a handle that cannot end the drag stops advertising
 *  itself as a target, and the CSS in index.css fades it. Dropping a boolean on a
 *  condition and watching the line vanish with no explanation is the bug this closes.
 *
 *  It mirrors canConnect's port rules rather than calling it, because a Handle knows its
 *  own node's type and nothing else — the arity and cycle checks still happen on drop. */
function useAcceptsEnd(takes: 'event' | 'bool'): boolean {
  const conn = useConnection()
  if (!conn.inProgress) return true
  const fromEvent = conn.fromNode?.type === 'event'
  return takes === 'event' ? fromEvent : !fromEvent
}

/** An edge with a delete button on it.
 *
 *  React Flow will delete a selected edge on the Delete key, which is no use to anyone who
 *  has not been told. A visible control is the only discoverable way to undo a connection. */
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
}: EdgeProps) {
  const { setEdges } = useReactFlow()
  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} />
      <EdgeLabelRenderer>
        <button
          // pointer-events has to be turned back on: the label layer disables it so edges
          // do not swallow clicks meant for the canvas.
          className="joro-edge-remove nodrag nopan"
          style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
          onClick={() => setEdges((es) => es.filter((e) => e.id !== id))}
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
//
// Sized from NODE_SIZE so the layout helpers and the canvas agree about how much room a
// node takes, which is what makes Tidy's columns line up.

const handleCls = '!w-2 !h-2 !border-2 !bg-surface-card'

function shell(selected: boolean, problem: boolean, accent: string) {
  return `rounded-sm border bg-surface-card px-2.5 py-2 ${
    problem ? 'border-semantic-warning' : selected ? 'border-accent' : accent
  }`
}

function EventNode({ data, selected }: NodeProps<RFNode<NodeData>>) {
  return (
    <div
      className={shell(!!selected, false, 'border-accent-secondary')}
      style={NODE_SIZE.event}
    >
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-accent-secondary mb-0.5">
        <Zap size={10} strokeWidth={2.4} aria-hidden="true" />
        On
      </div>
      <div className="text-[11px] font-mono text-content-primary truncate">{data.on}</div>
      <Handle
        type="source"
        position={Position.Right}
        className={`${handleCls} !border-accent-secondary`}
      />
    </div>
  )
}

function ConditionNode({ data, selected }: NodeProps<RFNode<NodeData>>) {
  const acceptsEnd = useAcceptsEnd('event')
  return (
    <div
      className={shell(!!selected, !!data.problem, 'border-border')}
      style={NODE_SIZE.condition}
    >
      <Handle
        type="target"
        position={Position.Left}
        isConnectableEnd={acceptsEnd}
        className={`${handleCls} !border-accent-secondary`}
      />
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-semantic-info mb-0.5">
        <Filter size={10} strokeWidth={2.4} aria-hidden="true" />
        {data.node.field || 'condition'}
      </div>
      <div className="text-[10px] font-mono text-content-secondary leading-snug line-clamp-2 break-all">
        {describeNode(data.node)}
      </div>
      <Handle type="source" position={Position.Right} className={`${handleCls} !border-border`} />
    </div>
  )
}

function LogicNode({ data, selected }: NodeProps<RFNode<NodeData>>) {
  const acceptsEnd = useAcceptsEnd('bool')
  return (
    <div
      className={`${shell(!!selected, !!data.problem, 'border-border')} flex items-center justify-center`}
      style={NODE_SIZE[data.node.type]}
    >
      <Handle
        type="target"
        position={Position.Left}
        isConnectableEnd={acceptsEnd}
        className={`${handleCls} !border-border`}
      />
      <span className="text-[11px] font-semibold text-content-primary">
        {NODE_LABEL[data.node.type]}
      </span>
      <Handle type="source" position={Position.Right} className={`${handleCls} !border-border`} />
    </div>
  )
}

function FireNode({ selected }: NodeProps<RFNode<NodeData>>) {
  const acceptsEnd = useAcceptsEnd('bool')
  return (
    <div className={shell(!!selected, false, 'border-accent-tertiary')} style={NODE_SIZE.fire}>
      <Handle
        type="target"
        position={Position.Left}
        isConnectableEnd={acceptsEnd}
        className={`${handleCls} !border-accent-tertiary`}
      />
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-accent-tertiary mb-0.5">
        <Play size={10} strokeWidth={2.4} aria-hidden="true" />
        Run
      </div>
      <div className="text-[11px] text-content-secondary">the automation</div>
    </div>
  )
}
