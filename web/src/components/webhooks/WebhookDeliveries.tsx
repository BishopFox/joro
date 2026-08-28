import { useCallback, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { api, type WebhookDeliveryLog } from '../../lib/api'

/**
 * The recent delivery attempts for one webhook.
 *
 * Fetched on demand rather than pushed. Per-delivery events would be a firehose on Joro's bus
 * for something only the operator looking at this panel wants, which is why webhook.state — a
 * pause the operator did not ask for — is the only webhook event broadcast at all.
 *
 * The log lives in memory and holds the last twenty attempts. It is diagnostics, not a record:
 * persisting it would grow webhooks.json without bound and keep third parties' responses in a
 * file that also holds secrets.
 */
export default function WebhookDeliveries({ id }: { id: string }) {
  const [rows, setRows] = useState<WebhookDeliveryLog[]>([])
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setBusy(true)
    try {
      const d = await api.listWebhookDeliveries(id)
      setRows(d.deliveries ?? [])
    } catch {
      // A failure here is not worth a toast: the panel below the editor is supplementary,
      // and the next refresh either works or the webhook is gone anyway.
      setRows([])
    } finally {
      setBusy(false)
    }
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div>
      <div className="flex items-center gap-1.5 mb-1.5">
        <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-muted">
          Recent deliveries
        </div>
        <button
          onClick={load}
          disabled={busy}
          className="text-content-muted hover:text-content-primary disabled:opacity-40"
          aria-label="Refresh"
        >
          <RefreshCw size={11} strokeWidth={2} />
        </button>
      </div>

      {rows.length === 0 ? (
        <p className="text-[10px] text-content-muted italic">
          Nothing sent yet this run. The log is in memory, so a restart clears it.
        </p>
      ) : (
        <table className="w-full text-[10px] font-mono">
          <tbody>
            {rows.map((d) => (
              <tr key={d.id} className="border-t border-border-subtle align-top">
                <td className="py-0.5 pr-2 text-content-muted whitespace-nowrap">
                  {new Date(d.at).toLocaleTimeString()}
                </td>
                <td className="py-0.5 pr-2 text-content-secondary">{d.event}</td>
                <td
                  className={`py-0.5 pr-2 ${
                    d.error ? 'text-semantic-error' : 'text-semantic-success'
                  }`}
                >
                  {d.status || '—'}
                </td>
                <td className="py-0.5 pr-2 text-content-muted whitespace-nowrap">{d.durationMs}ms</td>
                <td className="py-0.5 pr-2 text-content-muted whitespace-nowrap">
                  {d.attempts > 1 ? `${d.attempts} tries` : ''}
                  {d.events > 1 ? ` ${d.events} events` : ''}
                  {d.dropped ? ` ${d.dropped} dropped` : ''}
                </td>
                <td className="py-0.5 text-semantic-error break-all">{d.error}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
