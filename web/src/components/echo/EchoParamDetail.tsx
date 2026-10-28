import { useEffect, useState } from 'react'
import { ArrowUpRight, ShieldAlert } from 'lucide-react'
import { useNavigate } from 'react-router'
import { api } from '../../lib/api'
import type { EchoEntry, EchoReflection, EchoSpan } from '../../lib/echoTypes'
import {
  describeReflection,
  prettyParamName,
  SOURCE_LABELS,
  survivedLabel,
} from '../../lib/echoTypes'

/** renderSnippet highlights the matched run inside the response snippet. */
function renderSnippet(snippet: string, match?: EchoSpan) {
  if (!match) return snippet
  const start = Math.max(0, Math.min(match.start, snippet.length))
  const end = Math.max(start, Math.min(match.end, snippet.length))
  return (
    <>
      {snippet.slice(0, start)}
      <mark className="bg-transparent font-semibold text-semantic-warning">
        {snippet.slice(start, end)}
      </mark>
      {snippet.slice(end)}
    </>
  )
}

function ReflectionRow({ r }: { r: EchoReflection }) {
  const navigate = useNavigate()
  return (
    <div className="border-b border-border-subtle px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        {r.breakout && (
          <span className="inline-flex items-center gap-1 rounded bg-semantic-error-bg px-1.5 py-0.5 text-[11px] font-medium text-semantic-error">
            <ShieldAlert size={12} /> Can leave context
          </span>
        )}
        <span className="text-xs text-content-primary">{describeReflection(r)}</span>
      </div>

      <div className="mt-1 font-mono text-[11px]">
        <span className="text-content-muted">{SOURCE_LABELS[r.source] ?? r.source}:</span>{' '}
        <span className="text-content-secondary">{prettyParamName(r.source, r.name)}</span>
      </div>

      {r.url && (
        <div className="mt-1 flex items-center gap-2 text-[11px]">
          <span className="truncate font-mono text-content-muted" title={r.url}>
            {r.url}
          </span>
          {r.requestId && (
            <button
              className="inline-flex shrink-0 items-center gap-1 text-accent-secondary hover:underline"
              onClick={() => navigate('/history', { state: { focusRequestId: r.requestId } })}
            >
              Open <ArrowUpRight size={11} />
            </button>
          )}
        </div>
      )}

      {r.snippet ? (
        <pre className="mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-surface-input px-1.5 py-1 font-mono text-[11px] text-content-secondary">
          {renderSnippet(r.snippet, r.snippetMatch)}
        </pre>
      ) : (
        <div className="mt-1 truncate font-mono text-[11px] text-content-muted">
          value: {r.value}
        </div>
      )}

      <div className="mt-1 flex flex-wrap items-center gap-x-2 font-mono text-[11px] text-content-muted">
        <span>
          survived:{' '}
          <span className={r.survived ? 'text-semantic-warning' : 'text-content-muted'}>
            {survivedLabel(r.survived)}
          </span>
        </span>
        <span>&middot;</span>
        <span>
          {r.part} bytes {r.span.start}-{r.span.end}
        </span>
        {r.coord === 'decoded-body' && (
          <span
            className="text-semantic-info"
            title="The response was compressed, so these offsets index the decompressed body rather than the raw document."
          >
            decoded-body offsets
          </span>
        )}
        <span>&middot;</span>
        <span>{r.confidence} confidence</span>
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
  const pretty = prettyParamName(entry.source, entry.name)

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <span className="text-sm text-content-primary">{pretty}</span>
          {pretty !== entry.name && (
            <span className="rounded bg-surface-input px-1 py-0.5 font-mono text-[11px] text-content-muted">
              {entry.name}
            </span>
          )}
          <span className="rounded bg-surface-input px-1.5 py-0.5 text-[11px] text-content-muted">
            {SOURCE_LABELS[entry.source] ?? entry.source}
          </span>
          <span className="text-xs text-content-muted">{entry.host}</span>
          {entry.exampleRequestId && (
            <button
              className="ml-auto inline-flex items-center gap-1 text-xs text-accent-secondary hover:underline"
              onClick={() =>
                navigate('/history', { state: { focusRequestId: entry.exampleRequestId } })
              }
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
