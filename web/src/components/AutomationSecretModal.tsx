import { useState } from 'react'
import { Copy, Check, AlertTriangle } from 'lucide-react'

type Props = {
  secret: string
  tokenName: string
  endpoint: string
  onClose: () => void
}

/**
 * The one-time secret reveal.
 *
 * This is the only place in the UI a plaintext token appears. The token type has
 * no secret field and no read endpoint returns one, so once this modal is closed
 * the value is unrecoverable and the operator must rotate to get a new one — which
 * is what the warning says, in those words.
 */
export default function AutomationSecretModal({ secret, tokenName, endpoint, onClose }: Props) {
  const [copied, setCopied] = useState('')

  const config = JSON.stringify(
    { mcpServers: { joro: { url: endpoint, headers: { Authorization: `Bearer ${secret}` } } } },
    null,
    2
  )

  const copy = (what: string, text: string) => {
    navigator.clipboard.writeText(text).then(
      () => {
        setCopied(what)
        setTimeout(() => setCopied(''), 1500)
      },
      () => setCopied('')
    )
  }

  const btn = 'text-[11px] px-2 py-1 rounded-sm border border-border hover:bg-surface-hover inline-flex items-center gap-1.5'

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60">
      <div className="bg-surface-card border border-border rounded p-4 w-[38rem] space-y-3">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <AlertTriangle size={15} strokeWidth={2} className="text-semantic-warning" aria-hidden="true" />
          Token for {tokenName}
        </h3>
        <p className="text-[11px] text-content-muted">
          This is the only time this secret is shown. Joro stores a hash of it, not the value — if you lose it,
          rotate the token to issue a new one.
        </p>

        <div>
          <label className="block text-[10px] uppercase tracking-wide text-content-muted mb-1">Secret</label>
          <div className="flex gap-2">
            <code className="font-mono text-[11px] bg-surface-input px-2 py-1.5 rounded-sm flex-1 break-all">{secret}</code>
            <button onClick={() => copy('secret', secret)} className={btn}>
              {copied === 'secret' ? <Check size={12} strokeWidth={2.2} /> : <Copy size={12} strokeWidth={2} />}
              Copy
            </button>
          </div>
        </div>

        <div>
          <label className="block text-[10px] uppercase tracking-wide text-content-muted mb-1">MCP client config</label>
          <pre className="font-mono text-[10px] bg-surface-input p-2 rounded-sm overflow-x-auto leading-snug">{config}</pre>
          <button onClick={() => copy('config', config)} className={`${btn} mt-1.5`}>
            {copied === 'config' ? <Check size={12} strokeWidth={2.2} /> : <Copy size={12} strokeWidth={2} />}
            Copy config with secret
          </button>
        </div>

        <div className="flex justify-end pt-1">
          <button onClick={onClose} className="text-xs px-3 py-1 rounded-sm bg-accent-secondary text-black font-semibold">
            I’ve saved it
          </button>
        </div>
      </div>
    </div>
  )
}
