import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, Check, Loader2, X } from 'lucide-react'
import { api } from '../../lib/api'
import { b64DecodeUTF8 } from '../../lib/bytes'
import type {
  Chain, ChainBindProposal, ChainBinding, ChainSource, ChainSourceKind,
} from '../../lib/chainTypes'

const inputCls =
  'w-full bg-surface-card border border-border rounded px-1.5 py-0.5 text-[11px] text-content-primary font-mono'

interface Props {
  chain: Chain
  fromStep: string
  /** base64 of the bytes the operator selected in the response. */
  valueB64: string
  onCancel: () => void
  onAccept: (bindings: ChainBinding[]) => void
}

/** ChainBinder turns one selected value into bindings.
 *
 *  Inline rather than a modal, which would cover the request pane showing where
 *  the value lands. */
export default function ChainBinder({ chain, fromStep, valueB64, onCancel, onAccept }: Props) {
  const [proposal, setProposal] = useState<ChainBindProposal | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [varName, setVarName] = useState('')
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [sourceIdx, setSourceIdx] = useState(0)
  const [custom, setCustom] = useState<ChainSource | null>(null)

  const load = useCallback(
    async (source?: ChainSource) => {
      setBusy(true)
      setError('')
      try {
        const p = await api.chainBindPreview(chain.id, {
          fromStep,
          value: valueB64,
          source,
        })
        setProposal(p)
        if (!source) {
          setVarName(p.var)
          // Acceptable targets start ticked: a request carrying a token in both
          // a header and a form field needs both or it is inconsistent.
          setPicked(new Set(p.proposed.filter((t) => !t.conflict).map((t) => t.binding.id)))
        }
      } catch (e) {
        setError(String((e as Error).message ?? e))
        setProposal(null)
      } finally {
        setBusy(false)
      }
    },
    [chain.id, fromStep, valueB64],
  )

  useEffect(() => {
    void load()
  }, [load])

  const label = (id: string) => chain.steps.find((s) => s.id === id)?.label ?? id
  const sources = proposal?.sources ?? []
  const chosen = custom ?? sources[sourceIdx]?.source

  function accept() {
    if (!proposal || !chosen) return
    const out = proposal.proposed
      .filter((t) => picked.has(t.binding.id) && !t.conflict)
      .map((t) => ({ ...t.binding, var: varName || proposal.var, source: chosen }))
    if (out.length > 0) onAccept(out)
  }

  const acceptable = proposal?.proposed.filter((t) => picked.has(t.binding.id) && !t.conflict) ?? []

  return (
    <div className="border border-accent rounded m-2 bg-surface-card shrink-0 max-h-[60%] overflow-y-auto">
      <div className="flex items-center justify-between px-2 py-1 border-b border-border">
        <span className="text-xs text-content-primary">Bind a value</span>
        <button className="text-content-muted hover:text-content-primary" onClick={onCancel} aria-label="Cancel">
          <X size={13} />
        </button>
      </div>

      <div className="px-2 py-1.5 space-y-2">
        <div>
          <div className="text-[10px] text-content-secondary mb-0.5">Selected</div>
          <div className="font-mono text-[11px] text-accent-secondary break-all bg-surface-input rounded px-1.5 py-1">
            {b64DecodeUTF8(valueB64)}
          </div>
        </div>

        {busy && (
          <div className="flex items-center gap-1 text-[11px] text-content-muted">
            <Loader2 size={11} className="animate-spin" /> Working out how to read it back…
          </div>
        )}
        {error && <div className="text-[11px] text-semantic-error">{error}</div>}

        {proposal && (
          <>
            <label className="block">
              <span className="text-[10px] text-content-secondary">Name</span>
              <input className={inputCls} value={varName} onChange={(e) => setVarName(e.target.value)} />
            </label>

            <div>
              <div className="text-[10px] text-content-secondary mb-0.5">
                Read it out of the next response by
              </div>
              <div className="space-y-0.5">
                {sources.map((s, i) => (
                  <label key={s.detail} className="flex items-start gap-1.5 cursor-pointer">
                    <input
                      type="radio"
                      className="mt-0.5"
                      checked={!custom && sourceIdx === i}
                      onChange={() => {
                        setCustom(null)
                        setSourceIdx(i)
                      }}
                    />
                    <span className="text-[11px] min-w-0">
                      <span className="font-mono text-content-primary break-all">{s.detail}</span>
                      <SourceProof ok={s.ok} matched={s.matched} err={s.err} />
                    </span>
                  </label>
                ))}
                <label className="flex items-start gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    className="mt-0.5"
                    checked={!!custom}
                    onChange={() => setCustom({ kind: 'regex', expr: '', group: 1 })}
                  />
                  <span className="text-[11px] text-content-primary">Custom</span>
                </label>
              </div>

              {custom && (
                <CustomSource
                  source={custom}
                  onChange={(src) => {
                    setCustom(src)
                    void load(src)
                  }}
                  proof={sources[0]}
                />
              )}
            </div>

            <div>
              <div className="text-[10px] text-content-secondary mb-0.5">
                {proposal.proposed.length > 0
                  ? 'Send it in'
                  : 'No later step sends this value.'}
              </div>
              {proposal.proposed.length === 0 && (
                <div className="text-[10px] text-content-muted">
                  Nothing after this step carries these bytes literally. Check the warnings
                  below: a step that sends the value re-encoded cannot take a span, because a
                  binding writes the raw value and the origin would reject the result.
                </div>
              )}
              <div className="space-y-0.5">
                {proposal.proposed.map((t) => (
                  <label
                    key={t.binding.id}
                    className={`flex items-start gap-1.5 ${t.conflict ? 'opacity-60' : 'cursor-pointer'}`}
                  >
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      disabled={!!t.conflict}
                      checked={picked.has(t.binding.id)}
                      onChange={() =>
                        setPicked((p) => {
                          const n = new Set(p)
                          if (n.has(t.binding.id)) n.delete(t.binding.id)
                          else n.add(t.binding.id)
                          return n
                        })
                      }
                    />
                    <span className="text-[11px] min-w-0">
                      <span className="text-content-primary">{label(t.binding.toStep)}</span>{' '}
                      <span className="text-content-muted">
                        · {t.binding.spans.length} place{t.binding.spans.length === 1 ? '' : 's'}
                        {t.note ? ` · ${t.note}` : ''}
                      </span>
                      {t.conflict && (
                        <span className="block text-semantic-error">{t.conflict}</span>
                      )}
                    </span>
                  </label>
                ))}
              </div>
            </div>

            {(proposal.warnings ?? []).map((wn) => (
              <div key={wn} className="flex items-start gap-1 text-[10px] text-semantic-warning">
                <AlertTriangle size={10} className="shrink-0 mt-0.5" />
                <span>{wn}</span>
              </div>
            ))}

            <div className="flex items-center gap-2 pt-0.5">
              <button
                className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-accent-secondary text-black disabled:opacity-40"
                disabled={acceptable.length === 0}
                onClick={accept}
              >
                <Check size={12} /> Bind{acceptable.length > 1 ? ` ${acceptable.length} steps` : ''}
              </button>
              <button className="text-xs text-content-muted hover:text-content-primary" onClick={onCancel}>
                Cancel
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

/** The readout that turns "this rule looks applicable" into "this rule returns
 *  the bytes you selected". */
function SourceProof({ ok, matched, err }: { ok: boolean; matched?: string; err?: string }) {
  if (err) return <span className="block text-semantic-error">{err}</span>
  if (ok) return <span className="block text-semantic-success">matches your selection</span>
  return (
    <span className="block text-semantic-warning break-all">
      matches {matched ? `"${matched.slice(0, 60)}"` : 'something else'}
    </span>
  )
}

const KINDS: ChainSourceKind[] = ['regex', 'between', 'header', 'cookie', 'json']

function CustomSource({
  source, onChange, proof,
}: {
  source: ChainSource
  onChange: (s: ChainSource) => void
  proof?: { ok: boolean; matched?: string; err?: string }
}) {
  const set = (patch: Partial<ChainSource>) => onChange({ ...source, ...patch })
  return (
    <div className="mt-1 pl-5 space-y-1">
      <select
        className="bg-surface-card border border-border rounded px-1 py-0.5 text-[10px] text-content-primary"
        value={source.kind}
        onChange={(e) => onChange({ kind: e.target.value as ChainSourceKind })}
      >
        {KINDS.map((k) => (
          <option key={k} value={k}>
            {k}
          </option>
        ))}
      </select>

      {source.kind === 'regex' && (
        <>
          <input
            className={inputCls}
            placeholder="pattern with a capture group"
            value={source.expr ?? ''}
            onChange={(e) => set({ expr: e.target.value })}
          />
          <input
            className={inputCls}
            type="number"
            min={0}
            value={source.group ?? 1}
            onChange={(e) => set({ group: Number(e.target.value) })}
          />
        </>
      )}
      {source.kind === 'between' && (
        <>
          <input
            className={inputCls}
            placeholder="text before"
            value={source.prefix ?? ''}
            onChange={(e) => set({ prefix: e.target.value })}
          />
          <input
            className={inputCls}
            placeholder="text after (empty means the rest)"
            value={source.suffix ?? ''}
            onChange={(e) => set({ suffix: e.target.value })}
          />
        </>
      )}
      {(source.kind === 'header' || source.kind === 'cookie') && (
        <input
          className={inputCls}
          placeholder={`${source.kind} name`}
          value={source.name ?? ''}
          onChange={(e) => set({ name: e.target.value })}
        />
      )}
      {source.kind === 'json' && (
        <input
          className={inputCls}
          placeholder="dotted path, e.g. data.items[0].id"
          value={source.path ?? ''}
          onChange={(e) => set({ path: e.target.value })}
        />
      )}
      {proof && <SourceProof ok={proof.ok} matched={proof.matched} err={proof.err} />}
    </div>
  )
}
