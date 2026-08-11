import { useState } from 'react'
import { Check } from 'lucide-react'
import type { AutomationToken, AutomationTokenInput, Capability } from '../lib/api'
import GrantPicker from './GrantPicker'

type Props = {
  capabilities: Capability[]
  /** Present when editing; absent when creating. */
  token?: AutomationToken
  onSubmit: (body: AutomationTokenInput) => Promise<void>
  onClose: () => void
}

const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border w-full'

export default function AutomationTokenModal({ capabilities, token, onSubmit, onClose }: Props) {
  const editing = !!token
  const [name, setName] = useState(token?.name ?? '')
  const [grants, setGrants] = useState<string[]>(token?.grants ?? [])
  const [requireScope, setRequireScope] = useState(token?.requireScope ?? true)
  const [hostAllow, setHostAllow] = useState((token?.hostAllow ?? []).join(', '))
  const [rateLimit, setRateLimit] = useState(token?.rateLimitPerMin ?? 60)
  const [maxConcurrent, setMaxConcurrent] = useState(token?.maxConcurrent ?? 2)
  const [expiresInDays, setExpiresInDays] = useState(0)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const hostPatterns = hostAllow.split(',').map((s) => s.trim()).filter(Boolean)
  const sendsTraffic = capabilities.some((c) => c.sendsTraffic && grants.includes(c.id))

  async function submit() {
    setErr('')
    setBusy(true)
    try {
      const body: AutomationTokenInput = {
        name: name.trim(),
        grants,
        requireScope,
        hostAllow: hostPatterns,
        rateLimitPerMin: rateLimit,
        maxConcurrent,
      }
      if (!editing) body.expiresInDays = expiresInDays
      await onSubmit(body)
      onClose()
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50" onClick={onClose}>
      <div
        className="bg-surface-card border border-border rounded p-4 w-[42rem] max-h-[85vh] overflow-y-auto space-y-3"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="text-sm font-semibold">{editing ? `Edit ${token!.name}` : 'New automation token'}</h3>

        <div>
          <label className="block text-[10px] uppercase tracking-wide text-content-muted mb-1">Name</label>
          <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. claude-code" autoFocus={!editing} />
        </div>

        <div>
          <label className="block text-[10px] uppercase tracking-wide text-content-muted mb-1">Capabilities</label>
          <GrantPicker
            capabilities={capabilities}
            selected={grants}
            onChange={setGrants}
            highlight={token?.ungrantedCapabilities}
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-[10px] uppercase tracking-wide text-content-muted mb-1">Requests / minute</label>
            <input type="number" min={1} max={600} className={inputCls} value={rateLimit} onChange={(e) => setRateLimit(Number(e.target.value))} />
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wide text-content-muted mb-1">Max concurrent</label>
            <input type="number" min={1} max={16} className={inputCls} value={maxConcurrent} onChange={(e) => setMaxConcurrent(Number(e.target.value))} />
          </div>
        </div>

        {!editing && (
          <div>
            <label className="block text-[10px] uppercase tracking-wide text-content-muted mb-1">Expires in (days, 0 = never)</label>
            <input type="number" min={0} max={365} className={inputCls} value={expiresInDays} onChange={(e) => setExpiresInDays(Number(e.target.value))} />
          </div>
        )}

        <div className="border border-border rounded p-2.5 space-y-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={requireScope} onChange={(e) => setRequireScope(e.target.checked)} />
            <span className="text-xs">Only allow sends to in-scope targets</span>
          </label>
          <p className="text-[10px] text-content-muted leading-snug">
            {requireScope
              ? 'Sends are refused unless Joro’s scope is enabled, has at least one rule, and matches the target. This fails closed: with scope off, every send is refused.'
              : 'Sends are allowed regardless of scope. Every such call is recorded in Activity. Prefer a host whitelist below if you turn this off.'}
          </p>

          <div>
            <label className="block text-[10px] uppercase tracking-wide text-content-muted mb-1">
              Host whitelist (optional, comma-separated)
            </label>
            <input className={inputCls} value={hostAllow} onChange={(e) => setHostAllow(e.target.value)} placeholder="*.target.com, api.example.com" />
            <p className="text-[10px] text-content-muted mt-1 leading-snug">
              Combined with the scope check above, never instead of it.{' '}
              {hostPatterns.length > 0 && (
                <>
                  Note that <code className="font-mono">*</code> does not stop at a dot: <code className="font-mono">*.target.com</code> matches{' '}
                  <code className="font-mono">a.b.target.com</code> but <strong>not</strong> bare <code className="font-mono">target.com</code>.
                </>
              )}
            </p>
          </div>
        </div>

        {sendsTraffic && (
          <p className="text-[11px] text-semantic-warning">
            This token can send traffic to targets through Joro’s proxy. Those requests appear in History.
          </p>
        )}
        {err && <p className="text-semantic-error text-xs">{err}</p>}

        <div className="flex justify-end gap-2 pt-1">
          <button onClick={onClose} className="text-xs px-3 py-1 rounded-sm border border-border hover:bg-surface-hover">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={busy || !name.trim() || grants.length === 0}
            className="text-xs px-3 py-1 rounded-sm bg-accent-secondary text-black font-semibold disabled:opacity-40 inline-flex items-center gap-1.5"
          >
            <Check size={13} strokeWidth={2.2} aria-hidden="true" />
            {editing ? 'Save' : 'Create token'}
          </button>
        </div>
      </div>
    </div>
  )
}
