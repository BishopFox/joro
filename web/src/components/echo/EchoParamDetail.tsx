import { useEffect, useState } from 'react'
import { ArrowUpRight, ShieldAlert } from 'lucide-react'
import { useNavigate } from 'react-router'
import { api } from '../../lib/api'
import type { EchoEntry, EchoReflection } from '../../lib/echoTypes'
import {
  CONTEXT_LABELS,
  SOURCE_LABELS,
  TRANSFORM_LABELS,
} from '../../lib/echoTypes'

/** survivedLabel renders the characters that made it through readably. */
function survivedLabel(s?: string): string {
  if (!s) return 'nothing'
  return [...s]
    .map((c) => (c === '\n' ? 'LF' : c === '\r' ? 'CR' : c))
    .join(' ')
}

function ReflectionRow({ r }: { r: EchoReflection }) {
  return (
    <div className="border-b border-border-subtle px-3 py-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {r.breakout && (
          <span className="inline-flex items-center gap-1 text-semantic-error">
            <ShieldAlert size={12} />
            can leave context
          </span>
        )}
        <span className="text-content-secondary">
          {TRANSFORM_LABELS[r.transform] ?? r.transform}
        </span>
        <span className="text-content-muted">in</span>
        <span className="text-content-secondary">
          {CONTEXT_LABELS[r.context] ?? r.context}
          {r.attr ? ` (${r.attr}${r.quote ? `, ${r.quote}-quoted` : ', unquoted'})` : ''}
          {r.jsContext && r.jsContext !== 'code'
            ? ` / ${r.jsContext.replace('_', ' ')}`
            : ''}
        </span>
        <span className="text-content-muted">{r.confidence} confidence</span>
      </div>
      <div className="mt-1 font-mono text-[11px] text-content-muted">
        survived: <span className="text-content-secondary">{survivedLabel(r.survived)}</span>
        <span className="mx-2">·</span>
        {r.part} bytes {r.span.start}-{r.span.end}
        {r.coord === 'decoded-body' && (
          <span
            className="ml-2 text-semantic-info"
            title="The response was compressed, so these offsets index the decompressed body rather than the raw document."
          >
            decoded-body offsets
          </span>
        )}
      </div>
      <div className="mt-1 truncate font-mono text-[11px] text-content-muted">
        value: {r.value}
      </div>
    </div>
  )
}

export function EchoParamDetail({ entry }: { entry: EchoEntry }) {
  const [full, setFull] = useState<EchoEntry | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    let cancelled = false
    setFull(null)
    api
      .echoGetParam(entry.id)
      .then((e) => {
        if (!cancelled) setFull(e)
      })
      .catch(() => {
        // The row stays on screen; only the examples are missing.
      })
    return () => {
      cancelled = true
    }
  }, [entry.id])

  const examples = full?.examples ?? []

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <span className="text-sm text-content-primary">{entry.name}</span>
          <span className="rounded bg-surface-input px-1.5 py-0.5 text-[11px] text-content-muted">
            {SOURCE_LABELS[entry.source] ?? entry.source}
          </span>
          <span className="text-xs text-content-muted">{entry.host}</span>
          {entry.exampleRequestId && (
            <button
              className="ml-auto inline-flex items-center gap-1 text-xs text-accent-secondary hover:underline"
              onClick={() => navigate('/history', { state: { focusRequestId: entry.exampleRequestId } })}
            >
              Open in History <ArrowUpRight size={12} />
            </button>
          )}
        </div>
        <div className="mt-1 text-xs text-content-muted">
          seen in {entry.observations} response{entry.observations === 1 ? '' : 's'} ·{' '}
          {entry.distinctValues} distinct value{entry.distinctValues === 1 ? '' : 's'} ·{' '}
          {entry.reflections} reflection{entry.reflections === 1 ? '' : 's'}
          {entry.breakouts > 0 && (
            <span className="text-semantic-error"> · {entry.breakouts} can leave context</span>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {examples.length === 0 ? (
          <div className="px-3 py-6 text-center text-xs text-content-muted">
            {full ? 'No recorded reflections for this parameter.' : 'Loading...'}
          </div>
        ) : (
          examples.map((r, i) => <ReflectionRow key={`${r.span.start}-${i}`} r={r} />)
        )}
      </div>
    </div>
  )
}
