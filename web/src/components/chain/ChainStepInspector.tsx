import { useEffect, useMemo, useRef, useState } from 'react'
import { ArrowDown, Flag, KeyRound, Plus, RotateCcw, Wand2, X } from 'lucide-react'
import { api } from '../../lib/api'
import { b64ToBytes, bytesToB64 } from '../../lib/bytes'
import { methodClass } from '../../lib/chainStatus'
import { stepTitle } from '../../lib/chainMap'
import ChainRawPane, { type RawMark } from './ChainRawPane'
import ChainBinder from './ChainBinder'
import type {
  ChainBinding, Chain, ChainOnMissing, ChainStep, ChainStepResponse,
} from '../../lib/chainTypes'

const inputCls =
  'w-full bg-surface-input border border-border rounded px-2 py-1 text-xs text-content-primary'

type Pane = 'request' | 'response'

interface Props {
  chain: Chain
  step: ChainStep
  /** The binding the operator clicked on the map, if any. */
  selectedBindingId?: string | null
  onChange: (chain: Chain) => void
}

export default function ChainStepInspector({
  chain, step, selectedBindingId, onChange,
}: Props) {
  const cards = useRef(new Map<string, HTMLDivElement>())
  const [pane, setPane] = useState<Pane>('request')
  const [resp, setResp] = useState<ChainStepResponse | null>(null)
  const [respErr, setRespErr] = useState('')
  const [binding, setBinding] = useState<string | null>(null)
  const [hoverBinding, setHoverBinding] = useState<string | null>(null)

  const goalId = chain.goalStepId || chain.steps[chain.steps.length - 1]?.id
  const consumes = useMemo(
    () => chain.bindings.filter((b) => b.toStep === step.id),
    [chain.bindings, step.id],
  )
  const produces = useMemo(
    () => chain.bindings.filter((b) => b.fromStep === step.id),
    [chain.bindings, step.id],
  )

  const label = (id: string) => chain.steps.find((s) => s.id === id)?.label ?? id

  // Clicking an arc on the map selects a binding, not a step, so the inspector
  // has to say which of a step's several bindings was meant. The flash is what
  // carries that across the pane boundary; scrolling alone is ambiguous when two
  // bindings are already in view.
  useEffect(() => {
    if (!selectedBindingId) return
    const el = cards.current.get(selectedBindingId)
    if (!el) return
    el.scrollIntoView({ block: 'nearest' })
    el.classList.add('ring-1', 'ring-accent')
    const t = setTimeout(() => el.classList.remove('ring-1', 'ring-accent'), 900)
    return () => clearTimeout(t)
  }, [selectedBindingId, step.id])

  // The recorded response is fetched rather than read off the step: the proxy
  // leaves Content-Encoding in place, so step.respRaw is usually compressed, and
  // picking a value out of gzip is not a thing anyone can do.
  useEffect(() => {
    setResp(null)
    setRespErr('')
    setBinding(null)
    if (pane !== 'response') return
    let live = true
    api
      .chainStepResponse(chain.id, step.id)
      .then((r) => live && setResp(r))
      .catch((e) => live && setRespErr(String((e as Error).message ?? e)))
    return () => {
      live = false
    }
  }, [pane, chain.id, step.id])

  function patchBinding(id: string, patch: Partial<ChainBinding>) {
    onChange({
      ...chain,
      bindings: chain.bindings.map((b) => (b.id === id ? { ...b, ...patch } : b)),
    })
  }

  function removeBinding(id: string) {
    onChange({ ...chain, bindings: chain.bindings.filter((b) => b.id !== id) })
  }

  const requestMarks: RawMark[] = useMemo(
    () =>
      consumes.flatMap((b) =>
        b.spans.map((sp) => ({
          start: sp.start,
          end: sp.end,
          id: b.id,
          label: `${b.var}, from ${label(b.fromStep)}`,
          tone: 'bound' as const,
        })),
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [consumes, chain.steps],
  )

  // Headers and body in one pane: a regex or between source resolves against
  // both, so a value in a Set-Cookie has to be selectable too.
  const responseRaw = useMemo(() => {
    if (!resp) return ''
    const h = b64ToBytes(resp.headers)
    const b = b64ToBytes(resp.body)
    const all = new Uint8Array(h.length + 2 + b.length)
    all.set(h, 0)
    all.set([13, 10], h.length)
    all.set(b, h.length + 2)
    return bytesToB64(all)
  }, [resp])

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="px-3 py-2 border-b border-border shrink-0">
        <div className="flex items-center gap-1.5">
          <span className={`font-mono text-xs font-bold ${methodClass(step.method ?? '')}`}>
            {step.method}
          </span>
          <span className="text-content-primary text-sm truncate">{stepTitle(step)}</span>
        </div>
        <div className="text-[11px] text-content-muted mt-0.5">
          {step.scheme}://{step.host}
          {step.originSeq ? ` · seq ${step.originSeq}` : ''}
        </div>
      </div>

      {binding && (
        <ChainBinder
          chain={chain}
          fromStep={step.id}
          valueB64={binding}
          onCancel={() => setBinding(null)}
          onAccept={(added) => {
            setBinding(null)
            onChange({ ...chain, bindings: [...chain.bindings, ...added] })
          }}
        />
      )}

      <div className="overflow-y-auto shrink-0 max-h-[55%]">
        <div className="px-3 py-2 border-b border-border space-y-2">
          <label className="flex items-start gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={!!step.setup}
              onChange={() =>
                onChange({
                  ...chain,
                  steps: chain.steps.map((s) => (s.id === step.id ? { ...s, setup: !s.setup } : s)),
                })
              }
              className="mt-0.5"
            />
            <span className="text-xs">
              <span className="text-content-primary flex items-center gap-1">
                <RotateCcw size={11} /> Setup step
              </span>
              <span className="text-content-muted block mt-0.5">
                Never skipped, repeated or moved, so it runs at this position in every variant.
                Mark a login or add-to-cart here, or every variant after the first runs against
                state the previous one consumed.
              </span>
            </span>
          </label>

          <label className="flex items-start gap-2 cursor-pointer">
            <input
              type="radio"
              checked={goalId === step.id}
              onChange={() => onChange({ ...chain, goalStepId: step.id })}
              className="mt-0.5"
            />
            <span className="text-xs">
              <span className="text-content-primary flex items-center gap-1">
                <Flag size={11} /> Goal step
              </span>
              <span className="text-content-muted block mt-0.5">
                This step's outcome decides every verdict - such as whether the checkout went through.
              </span>
            </span>
          </label>
        </div>

        {consumes.length > 0 && (
          <div className="px-3 py-2 border-b border-border">
            <div className="text-[11px] text-content-secondary flex items-center gap-1 mb-1.5">
              <ArrowDown size={11} /> Needs {consumes.length} value
              {consumes.length === 1 ? '' : 's'}
            </div>
            <div className="space-y-2">
              {consumes.map((b) => (
                <div
                  key={b.id}
                  ref={(el) => {
                    if (el) cards.current.set(b.id, el)
                    else cards.current.delete(b.id)
                  }}
                  className="bg-surface-input rounded px-2 py-1.5"
                  onMouseEnter={() => setHoverBinding(b.id)}
                  onMouseLeave={() => setHoverBinding(null)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-accent-secondary flex items-center gap-1">
                      {b.var}
                      <AutoBadge auto={b.auto} />
                    </span>
                    <span className="flex items-center gap-1.5">
                      <button
                        className="text-[10px] text-content-muted hover:text-accent-secondary"
                        onClick={() => setPane('request')}
                      >
                        {b.spans.length} place{b.spans.length === 1 ? '' : 's'}
                      </button>
                      <button
                        className="text-content-muted hover:text-semantic-error"
                        title={`Remove the ${b.var} binding`}
                        aria-label={`Remove the ${b.var} binding`}
                        onClick={() => removeBinding(b.id)}
                      >
                        <X size={11} />
                      </button>
                    </span>
                  </div>
                  <div className="text-[10px] text-content-muted mt-0.5">from {label(b.fromStep)}</div>
                  <label className="flex items-center gap-1.5 mt-1.5">
                    <span className="text-[10px] text-content-secondary">If missing:</span>
                    <select
                      className="bg-surface-card border border-border rounded px-1 py-0.5 text-[10px] text-content-primary"
                      value={b.onMissing ?? 'fail'}
                      onChange={(e) =>
                        patchBinding(b.id, { onMissing: e.target.value as ChainOnMissing })
                      }
                    >
                      <option value="fail">don't send</option>
                      <option value="recorded">send recorded value</option>
                    </select>
                  </label>
                  <div className="text-[10px] text-content-muted mt-1">
                    {b.onMissing === 'recorded'
                      ? 'Replays the captured value when the producer is skipped - often the actual test.'
                      : 'A variant that skips the producer reports this step unresolved rather than sending a stale value.'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="px-3 py-2 border-b border-border">
          <div className="flex items-center justify-between mb-1.5">
            <div className="text-[11px] text-content-secondary flex items-center gap-1">
              <KeyRound size={11} /> Produces {produces.length} value
              {produces.length === 1 ? '' : 's'}
            </div>
            <button
              className="flex items-center gap-0.5 text-[10px] text-content-muted hover:text-accent-secondary"
              title="Show this step's recorded response and pick a value out of it"
              onClick={() => setPane('response')}
            >
              <Plus size={10} /> Bind value
            </button>
          </div>
          {produces.length === 0 ? (
            <div className="text-[10px] text-content-muted">
              Nothing later in the chain takes a value from this response yet. Open the Response
              pane and select one.
            </div>
          ) : (
            <div className="space-y-1.5">
              {produces.map((b) => (
                <div
                  key={b.id}
                  ref={(el) => {
                    if (el) cards.current.set(b.id, el)
                    else cards.current.delete(b.id)
                  }}
                  className="bg-surface-input rounded px-2 py-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <input
                      className="font-mono text-xs text-accent-secondary bg-transparent border-none outline-none min-w-0 flex-1"
                      value={b.var}
                      onChange={(e) => patchBinding(b.id, { var: e.target.value })}
                    />
                    <span className="flex items-center gap-1.5 shrink-0">
                      <AutoBadge auto={b.auto} />
                      <span className="text-[10px] text-content-muted">→ {label(b.toStep)}</span>
                      <button
                        className="text-content-muted hover:text-semantic-error"
                        title={`Remove the ${b.var} binding`}
                        aria-label={`Remove the ${b.var} binding`}
                        onClick={() => removeBinding(b.id)}
                      >
                        <X size={11} />
                      </button>
                    </span>
                  </div>
                  <div className="text-[10px] text-content-muted mt-0.5 font-mono truncate">
                    {describeSource(b)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center gap-0.5 px-2 pt-1 shrink-0">
        <PaneTab active={pane === 'request'} onClick={() => setPane('request')}>
          Request
        </PaneTab>
        <PaneTab active={pane === 'response'} onClick={() => setPane('response')}>
          Response
        </PaneTab>
        <div className="flex-1" />
        {pane === 'response' ? (
          <span className="text-[10px] text-content-muted">
            Select a value to bind it into a later step.
          </span>
        ) : (
          <button
            className="flex items-center gap-0.5 text-[10px] text-content-muted hover:text-accent-secondary"
            title="Show this step's recorded response and pick a value out of it"
            onClick={() => setPane('response')}
          >
            <Plus size={10} /> Bind value
          </button>
        )}
      </div>

      <div className="flex-1 min-h-0 px-2 pb-2 pt-1">
        {pane === 'request' ? (
          <ChainRawPane
            className="h-full"
            raw={step.reqRaw}
            marks={requestMarks}
            activeId={hoverBinding ?? selectedBindingId}
            onMarkClick={(id) => cards.current.get(id)?.scrollIntoView({ block: 'nearest' })}
          />
        ) : respErr ? (
          <div className={`${inputCls} text-semantic-error`}>{respErr}</div>
        ) : !resp ? (
          <div className="text-[11px] text-content-muted px-1">Loading the recorded response…</div>
        ) : (
          <ChainRawPane
            className="h-full"
            raw={responseRaw}
            decodedNote={resp.decoded}
            onSelect={(sel) => setBinding(sel.valueB64)}
          />
        )}
      </div>
    </div>
  )
}

function PaneTab({
  active, onClick, children,
}: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-2 py-0.5 text-[11px] rounded ${
        active ? 'bg-surface-input text-accent' : 'text-content-secondary hover:text-content-primary'
      }`}
    >
      {children}
    </button>
  )
}

/** Auto marks a binding correlation proposed rather than one the operator wrote.
 *  Worth showing: a week later, "Correlate found this" and "I decided this" lead
 *  to different amounts of trust. */
function AutoBadge({ auto }: { auto?: boolean }) {
  if (!auto) return null
  return (
    <span className="text-content-muted" title="Proposed by Correlate">
      <Wand2 size={10} />
    </span>
  )
}

function describeSource(b: ChainBinding): string {
  const s = b.source
  switch (s.kind) {
    case 'header':
      return `header ${s.name}`
    case 'cookie':
      return `cookie ${s.name}`
    case 'json':
      return `json ${s.path}`
    case 'regex':
      return `regex ${s.expr}`
    case 'between':
      return `between "${s.prefix}" and "${s.suffix}"`
    default:
      return s.kind
  }
}
