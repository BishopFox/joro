import { useEffect, useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { api } from '../../lib/api'
import type { EchoReport } from '../../lib/echoTypes'
import {
  CONTEXT_LABELS,
  SOURCE_LABELS,
  TRANSFORM_LABELS,
} from '../../lib/echoTypes'

/**
 * EchoRequestPane lists what one captured message reflected. A message with no
 * report has not been analyzed — it predates the mapper being switched on —
 * which is a different answer from one that reflected nothing, so the two are
 * worded differently.
 */
export function EchoRequestPane({ requestId }: { requestId: string }) {
  const [state, setState] = useState<
    { analyzed: boolean; report?: EchoReport } | null
  >(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let cancelled = false
    setState(null)
    setError(false)
    api
      .echoGetRequest(requestId)
      .then((d) => {
        if (!cancelled) setState({ analyzed: d.analyzed, report: d.report })
      })
      .catch(() => {
        if (!cancelled) setError(true)
      })
    return () => {
      cancelled = true
    }
  }, [requestId])

  if (error) {
    return (
      <div className="p-3 text-xs text-content-muted">
        Reflection mapping is unavailable in this mode.
      </div>
    )
  }
  if (!state) {
    return <div className="p-3 text-xs text-content-muted">Loading...</div>
  }
  if (!state.analyzed || !state.report) {
    return (
      <div className="p-3 text-xs text-content-muted">
        This message has not been analyzed. Switch reflection mapping on in the
        Echo tab, then run a backfill to cover traffic already captured.
      </div>
    )
  }

  const rep = state.report
  if (rep.reflections.length === 0) {
    return (
      <div className="p-3 text-xs text-content-muted">
        None of the {rep.needles} value{rep.needles === 1 ? '' : 's'} sent in this
        request came back in the response.
      </div>
    )
  }

  return (
    <div className="absolute inset-0 overflow-auto">
      <div className="border-b border-border-subtle px-3 py-1.5 text-xs text-content-muted">
        {rep.reflections.length} reflection{rep.reflections.length === 1 ? '' : 's'}{' '}
        from {rep.needles} of {rep.values} value{rep.values === 1 ? '' : 's'} sent
        {rep.breakouts > 0 && (
          <span className="text-semantic-error"> · {rep.breakouts} can leave context</span>
        )}
        {rep.truncated && <span> · truncated</span>}
      </div>
      <table className="w-full text-xs">
        <thead className="text-left text-content-muted">
          <tr className="border-b border-border-subtle">
            <th className="px-2 py-1 font-normal">Parameter</th>
            <th className="px-2 py-1 font-normal">As</th>
            <th className="px-2 py-1 font-normal">Context</th>
            <th className="px-2 py-1 font-normal">Survived</th>
            <th className="px-2 py-1 text-right font-normal">Offset</th>
          </tr>
        </thead>
        <tbody>
          {rep.reflections.map((r, i) => (
            <tr key={i} className="border-b border-border-subtle">
              <td className="max-w-[12rem] truncate px-2 py-1 text-content-secondary">
                {r.breakout && (
                  <ShieldAlert size={11} className="mr-1 inline text-semantic-error" />
                )}
                <span className="text-content-muted">
                  {SOURCE_LABELS[r.source] ?? r.source}:
                </span>{' '}
                {r.name}
              </td>
              <td className="px-2 py-1 text-content-muted">
                {TRANSFORM_LABELS[r.transform] ?? r.transform}
              </td>
              <td className="px-2 py-1 text-content-muted">
                {CONTEXT_LABELS[r.context] ?? r.context}
                {r.attr ? ` (${r.attr})` : ''}
                {r.jsContext && r.jsContext !== 'code'
                  ? ` / ${r.jsContext.replace('_', ' ')}`
                  : ''}
              </td>
              <td className="px-2 py-1 font-mono text-content-secondary">
                {r.survived
                  ? [...r.survived]
                      .map((c) => (c === '\n' ? 'LF' : c === '\r' ? 'CR' : c))
                      .join(' ')
                  : '-'}
              </td>
              <td
                className="px-2 py-1 text-right font-mono text-content-muted"
                title={
                  r.coord === 'decoded-body'
                    ? 'The response was compressed, so this offset indexes the decompressed body rather than the raw bytes shown in the Raw tab.'
                    : undefined
                }
              >
                {r.span.start}
                {r.coord === 'decoded-body' && <span className="text-semantic-info">*</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
