import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import { ShieldAlert } from 'lucide-react'
import { api } from '../../lib/api'
import type { EchoInventory } from '../../lib/echoTypes'
import { SOURCE_LABELS } from '../../lib/echoTypes'

/**
 * ParamInventory lists every parameter the requests behind a site-map node
 * carried — the endpoint's inputs, not just the query-string names the tree
 * groups variants by.
 *
 * The Reflects column is only ever positive evidence. An empty column means
 * reflection mapping has not seen the parameter come back, which includes the
 * common case of it never having been switched on, so nothing here words it as
 * "does not reflect".
 */
export function ParamInventory({
  origin,
  path,
  filters,
}: {
  origin: string
  path?: string
  filters: Record<string, string | number>
}) {
  const navigate = useNavigate()
  const [state, setState] = useState<EchoInventory | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let cancelled = false
    setState(null)
    setError(false)
    api
      .sitemapParams(origin, path, filters)
      .then((d) => {
        if (!cancelled) setState(d)
      })
      .catch(() => {
        if (!cancelled) setError(true)
      })
    return () => {
      cancelled = true
    }
    // filters is rebuilt each render by the page's memo; keying on its identity
    // is what makes a filter change refetch.
  }, [origin, path, filters])

  const label = path === undefined ? origin : `${origin}${path}`

  if (error) {
    return (
      <div className="p-3 text-xs text-content-muted">
        Could not read parameters for {label}.
      </div>
    )
  }
  if (!state) {
    return <div className="p-3 text-xs text-content-muted">Loading...</div>
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="flex items-center gap-2 border-b border-border bg-surface-card px-2 py-1.5 shrink-0">
        <span className="text-xs font-semibold text-content-primary">Parameters</span>
        <span className="truncate text-xs text-content-muted" title={label}>
          {label}
        </span>
      </div>
      <div className="border-b border-border-subtle px-3 py-1.5 text-xs text-content-muted shrink-0">
        {state.params.length} parameter{state.params.length === 1 ? '' : 's'} across{' '}
        {state.walked} request{state.walked === 1 ? '' : 's'}
        {state.truncated && (
          <span title={`Only the ${state.walked} most recent of ${state.requests} were read.`}>
            {' '}
            · newest {state.walked} of {state.requests}
          </span>
        )}
      </div>
      {state.params.length === 0 ? (
        <div className="p-3 text-xs text-content-muted">
          No parameters were sent to this {path === undefined ? 'host' : 'endpoint'}.
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          <table className="w-full text-xs">
            <thead className="text-left text-content-muted">
              <tr className="border-b border-border-subtle">
                <th className="px-2 py-1 font-normal">Parameter</th>
                <th className="px-2 py-1 font-normal">Source</th>
                <th className="px-2 py-1 text-right font-normal">Reqs</th>
                <th className="px-2 py-1 text-right font-normal">Values</th>
                <th className="px-2 py-1 font-normal">Example</th>
                <th className="px-2 py-1 font-normal">Reflects</th>
              </tr>
            </thead>
            <tbody>
              {state.params.map((p) => (
                <tr key={`${p.source}:${p.name}`} className="border-b border-border-subtle">
                  <td
                    className="max-w-[14rem] truncate px-2 py-1 text-content-secondary"
                    title={`${p.name} · ${p.methods.join(', ')}`}
                  >
                    {p.name}
                  </td>
                  <td className="px-2 py-1 text-content-muted">
                    {SOURCE_LABELS[p.source] ?? p.source}
                  </td>
                  <td className="px-2 py-1 text-right font-mono text-content-muted">
                    {p.requests}
                  </td>
                  <td className="px-2 py-1 text-right font-mono text-content-muted">
                    {p.distinctValues}
                  </td>
                  <td
                    className="max-w-0 truncate px-2 py-1 font-mono text-content-secondary"
                    title={p.exampleValue}
                  >
                    {p.exampleValue}
                  </td>
                  <td className="px-2 py-1">
                    {p.reflected && (
                      <button
                        onClick={() => navigate('/echo')}
                        className={`hover:underline ${
                          p.breakouts > 0 ? 'text-semantic-error' : 'text-accent-secondary'
                        }`}
                        title={
                          p.breakouts > 0
                            ? 'Comes back in the response and can leave its context'
                            : 'Comes back in the response'
                        }
                      >
                        {p.breakouts > 0 && <ShieldAlert size={11} className="mr-1 inline" />}
                        {p.breakouts > 0 ? 'Breakout' : 'Yes'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
