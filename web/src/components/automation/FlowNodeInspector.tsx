import { ExternalLink } from 'lucide-react'
import type { SdkMethod } from '../../lib/api'
import {
  ARITH_OPS,
  COMPARE_OPS,
  NODE_SPECS,
  STORAGE_ACTIONS,
  edgesInto,
  inputsOf,
  patchData,
  type FlowGraph,
  type FlowNode,
} from '../../lib/flowGraph'

const inputCls = 'bg-surface-input text-[11px] px-1.5 py-1 rounded-sm border border-border w-full'

/**
 * The fields for whichever box is selected.
 *
 * One component for every kind, the way TriggerConditionFields is one component for the
 * canvas rail and the builder rows: a second copy is a second thing to keep in step with what
 * the compiler actually reads.
 */
export default function FlowNodeInspector({
  graph,
  node,
  methods,
  readOnly,
  onChange,
  onEditTrigger,
  onOpenBody,
}: {
  graph: FlowGraph
  node: FlowNode
  methods: SdkMethod[]
  readOnly: boolean
  onChange: (g: FlowGraph) => void
  onEditTrigger?: (id: string) => void
  onOpenBody?: () => void
}) {
  const d = node.data ?? {}
  const set = (p: Partial<typeof d>) => onChange(patchData(graph, node.id, p))
  const hint = <p className="text-[10px] text-content-muted leading-snug">{NODE_SPECS[node.type].hint}</p>

  switch (node.type) {
    case 'trigger':
      return (
        <div className="space-y-1.5">
          <p className="text-[10px] text-content-muted leading-snug">
            Wired anywhere, this reads <code className="font-mono">ctx.trigger</code> — what woke the
            run. Which triggers this automation declares is set in the options above.
          </p>
          {d.ref && onEditTrigger && (
            <button
              onClick={() => onEditTrigger(d.ref!)}
              className="inline-flex items-center gap-1 text-[10px] text-accent-secondary hover:underline"
            >
              <ExternalLink size={10} strokeWidth={2} aria-hidden="true" />
              Edit this trigger
            </button>
          )}
        </div>
      )

    case 'body':
      return (
        <div className="space-y-1.5">
          <p className="text-[10px] text-content-muted leading-snug">
            {d.value === 'command'
              ? 'The program this runs, and what it is fed. Edit it in the Command view.'
              : 'The JavaScript this runs. Edit it in the Code view.'}
          </p>
          {onOpenBody && (
            <button
              onClick={onOpenBody}
              className="inline-flex items-center gap-1 text-[10px] text-accent-secondary hover:underline"
            >
              <ExternalLink size={10} strokeWidth={2} aria-hidden="true" />
              Open it
            </button>
          )}
        </div>
      )

    case 'return':
      return (
        <p className="text-[10px] text-content-muted leading-snug">
          {d.value
            ? 'What this returns becomes the viewer tab. A lens returns { text } or a bare string.'
            : 'Wire one value here to say what the run produces. Nothing wired returns nothing, which is fine for an automation that runs for its effect.'}
        </p>
      )

    case 'context':
      return (
        <div className="space-y-1.5">
          <select className={inputCls} value={d.path ?? 'input'} disabled={readOnly} onChange={(e) => set({ path: e.target.value as 'input' })}>
            <option value="input">ctx.input — what was passed in</option>
            <option value="trigger">ctx.trigger — why this ran</option>
            <option value="run">ctx.run — this run&rsquo;s id and start</option>
          </select>
          {hint}
        </div>
      )

    case 'literal':
      return (
        <div className="space-y-1.5">
          <textarea
            className={`${inputCls} h-16 resize-none font-mono`}
            value={d.value ?? ''}
            disabled={readOnly}
            placeholder='"a string", 42, true, or {"a": 1}'
            onChange={(e) => set({ value: e.target.value })}
          />
          <p className="text-[10px] text-content-muted leading-snug">
            Read as JSON. Plain text that is not valid JSON is used as a string.
          </p>
        </div>
      )

    case 'get':
      return (
        <div className="space-y-1.5">
          <input
            className={`${inputCls} font-mono`}
            value={d.get ?? ''}
            disabled={readOnly}
            placeholder="requests[0].host"
            onChange={(e) => set({ get: e.target.value })}
          />
          {hint}
        </div>
      )

    case 'template':
      return (
        <div className="space-y-1.5">
          <textarea
            className={`${inputCls} h-16 resize-none font-mono`}
            value={d.template ?? ''}
            disabled={readOnly}
            placeholder="{{a}} returned {{b}}"
            onChange={(e) => set({ template: e.target.value })}
          />
          {hint}
        </div>
      )

    case 'arith':
    case 'compare': {
      const ops = node.type === 'arith' ? ARITH_OPS : COMPARE_OPS
      return (
        <div className="space-y-1.5">
          <select
            className={inputCls}
            value={d.op ?? (node.type === 'arith' ? 'add' : 'eq')}
            disabled={readOnly}
            onChange={(e) => set({ op: e.target.value })}
          >
            {Object.entries(ops).map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </select>
          {hint}
        </div>
      )
    }

    case 'storage':
      return (
        <div className="space-y-1.5">
          <select className={inputCls} value={d.action ?? 'get'} disabled={readOnly} onChange={(e) => set({ action: e.target.value })}>
            {Object.entries(STORAGE_ACTIONS).map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </select>
          {d.action !== 'keys' && (
            <input
              className={`${inputCls} font-mono`}
              value={d.key ?? ''}
              disabled={readOnly}
              placeholder="key — or wire one in"
              onChange={(e) => set({ key: e.target.value })}
            />
          )}
          {hint}
        </div>
      )

    case 'call': {
      const method = methods.find((m) => m.js === d.method)
      const ports = inputsOf(node, methods)
      const schema = method?.inputSchema as
        | { properties?: Record<string, { description?: string; enum?: string[]; type?: string }> }
        | undefined
      return (
        <div className="space-y-1.5">
          <select
            className={`${inputCls} font-mono`}
            value={d.method ?? ''}
            disabled={readOnly}
            // The whole argument map is cleared: the names belonged to the previous method,
            // and carrying them over would send arguments the new one does not take.
            onChange={(e) => onChange(patchData(graph, node.id, { method: e.target.value, args: {} }))}
          >
            <option value="">Pick a method…</option>
            {methods.map((m) => (
              <option key={m.js} value={m.js}>
                {m.js}
                {m.sendsTraffic ? ' — sends' : ''}
              </option>
            ))}
          </select>
          {method?.title && <p className="text-[10px] text-content-muted leading-snug">{method.title}</p>}
          {method?.sendsTraffic && (
            <p className="text-[10px] text-semantic-warning leading-snug">
              This puts bytes on the wire. A lens run has its send capabilities removed, so it will be
              refused there.
            </p>
          )}
          {ports.length > 0 && (
            <div className="space-y-1 pt-1">
              <div className="text-[10px] uppercase tracking-wide text-content-muted">Arguments</div>
              {ports.map((p) => {
                const wired = edgesInto(graph, node.id, p.id).length > 0
                const prop = schema?.properties?.[p.id]
                return (
                  <label key={p.id} className="block">
                    <span className="flex items-center gap-1 text-[10px] text-content-muted">
                      <code className="font-mono text-content-secondary">{p.id}</code>
                      {p.required && <span className="text-semantic-error">required</span>}
                      {wired && <span className="text-accent-secondary">wired</span>}
                    </span>
                    {/* A wired argument shows the wire rather than a box: two ways to set one
                        value would leave the operator guessing which the compiler used. */}
                    {wired ? (
                      <span className="block text-[10px] text-content-muted italic">
                        Comes from the box wired into this port.
                      </span>
                    ) : prop?.enum ? (
                      <select
                        className={inputCls}
                        value={stripQuotes(d.args?.[p.id] ?? '')}
                        disabled={readOnly}
                        onChange={(e) => setArg(graph, node, onChange, p.id, e.target.value ? JSON.stringify(e.target.value) : '')}
                      >
                        <option value="">default</option>
                        {prop.enum.map((v) => (
                          <option key={v} value={v}>
                            {v}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        className={`${inputCls} font-mono`}
                        value={d.args?.[p.id] ?? ''}
                        disabled={readOnly}
                        placeholder={prop?.type === 'integer' || prop?.type === 'number' ? '0' : prop?.type === 'boolean' ? 'true' : ''}
                        title={prop?.description}
                        onChange={(e) => setArg(graph, node, onChange, p.id, e.target.value)}
                      />
                    )}
                  </label>
                )
              })}
            </div>
          )}
        </div>
      )
    }

    default:
      return hint
  }
}

function setArg(
  graph: FlowGraph,
  node: FlowNode,
  onChange: (g: FlowGraph) => void,
  name: string,
  value: string
) {
  onChange(patchData(graph, node.id, { args: { ...node.data?.args, [name]: value } }))
}

function stripQuotes(s: string): string {
  try {
    const v = JSON.parse(s)
    return typeof v === 'string' ? v : s
  } catch {
    return s
  }
}

/** One box as a line of text, for its body on the canvas. The same job describeNode does for
 *  a trigger condition. */
export function describeFlowNode(
  n: FlowNode,
  triggerInfo?: Record<string, { name: string; on: string; problem?: string }>
): string {
  const d = n.data ?? {}
  switch (n.type) {
    case 'trigger':
      return triggerInfo?.[d.ref ?? '']?.on ?? d.ref ?? ''
    case 'context':
      return `ctx.${d.path ?? 'input'}`
    case 'literal':
      return d.value?.trim() || 'null'
    case 'get':
      return d.get ? `.${d.get.replace(/^\./, '')}` : 'no path'
    case 'template':
      return d.template || 'empty'
    case 'arith':
      return ARITH_OPS[d.op ?? 'add'] ?? d.op ?? ''
    case 'compare':
      return COMPARE_OPS[d.op ?? 'eq'] ?? d.op ?? ''
    case 'select':
      return 'if / then / else'
    case 'all':
      return 'every input'
    case 'any':
      return 'any input'
    case 'not':
      return 'inverted'
    case 'call':
      return d.method ?? 'pick a method'
    case 'storage':
      return `${STORAGE_ACTIONS[d.action ?? 'get']} ${d.key ?? ''}`.trim()
    case 'log':
      return 'to the run log'
    case 'guard':
      return 'return early when false'
    case 'each':
      return 'once per element'
    case 'return':
      return 'the run’s value'
    case 'body':
      return d.value === 'command' ? 'a local program' : 'hand-written JavaScript'
    default:
      return ''
  }
}
