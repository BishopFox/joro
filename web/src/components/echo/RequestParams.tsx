import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import type { EchoRequestParams } from '../../lib/echoTypes'
import { SOURCE_LABELS } from '../../lib/echoTypes'

/**
 * RequestParams lists every input one captured request carried, grouped by where
 * it came from. Unlike the Reflections pane beside it, this needs nothing from
 * the reflection engine: it is the walk on its own, so it answers on a request
 * that was never analyzed and on one with no response at all.
 */
export function RequestParams({ requestId }: { requestId: string }) {
  const [state, setState] = useState<EchoRequestParams | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let cancelled = false
    setState(null)
    setError(false)
    api
      .requestParams(requestId)
      .then((d) => {
        if (!cancelled) setState(d)
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
        This request is no longer in history.
      </div>
    )
  }
  if (!state) {
    return <div className="p-3 text-xs text-content-muted">Loading...</div>
  }
  if (state.params.length === 0) {
    return (
      <div className="p-3 text-xs text-content-muted">
        This request carried no parameters.
      </div>
    )
  }

  return (
    <div className="absolute inset-0 overflow-auto">
      <div className="border-b border-border-subtle px-3 py-1.5 text-xs text-content-muted">
        {state.params.length} parameter{state.params.length === 1 ? '' : 's'} sent
        {state.truncated && <span> · truncated</span>}
      </div>
      <table className="w-full text-xs">
        <thead className="text-left text-content-muted">
          <tr className="border-b border-border-subtle">
            <th className="px-2 py-1 font-normal">Parameter</th>
            <th className="px-2 py-1 font-normal">Source</th>
            <th className="px-2 py-1 font-normal">Value</th>
          </tr>
        </thead>
        <tbody>
          {state.params.map((p, i) => (
            <tr key={i} className="border-b border-border-subtle">
              <td className="max-w-[14rem] truncate px-2 py-1 text-content-secondary" title={p.name}>
                {p.name}
              </td>
              <td className="px-2 py-1 text-content-muted">
                {SOURCE_LABELS[p.source] ?? p.source}
              </td>
              <td
                className="max-w-0 truncate px-2 py-1 font-mono text-content-secondary"
                title={p.value}
              >
                {p.value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
