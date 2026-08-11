import { useState } from 'react'
import { AlertTriangle, Check, KeyRound, Unlock } from 'lucide-react'
import type { AutomationProfile, AutomationToken, AutomationTokenInput, Capability } from '../lib/api'
import GrantPicker from './GrantPicker'

type Props = {
  capabilities: Capability[]
  profiles?: AutomationProfile[]
  classes?: string[]
  /** Present when editing; absent when creating. */
  token?: AutomationToken
  onSubmit: (body: AutomationTokenInput) => Promise<void>
  onClose: () => void
}

const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border w-full'

export default function AutomationTokenModal({
  capabilities,
  profiles = [],
  classes = [],
  token,
  onSubmit,
  onClose,
}: Props) {
  const editing = !!token
  const [name, setName] = useState(token?.name ?? '')
  const [grants, setGrants] = useState<string[]>(token?.grants ?? [])
  const [requireScope, setRequireScope] = useState(token?.requireScope ?? true)
  const [hostAllow, setHostAllow] = useState((token?.hostAllow ?? []).join(', '))
  const [allowCredentials, setAllowCredentials] = useState(token?.allowCredentials ?? false)
  const [rateLimit, setRateLimit] = useState(token?.rateLimitPerMin ?? 60)
  const [maxConcurrent, setMaxConcurrent] = useState(token?.maxConcurrent ?? 2)
  const [expiresInDays, setExpiresInDays] = useState(0)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const hostPatterns = hostAllow.split(',').map((s) => s.trim()).filter(Boolean)
  const sendsTraffic = capabilities.some((c) => c.sendsTraffic && grants.includes(c.id))
  const mutating = capabilities.filter((c) => c.mutating && grants.includes(c.id))
  // Capabilities the registry refuses to a restricted token. Selecting one alongside
  // requireScope or a host whitelist is not rejected on save — it fails closed at call
  // time — but silently handing over a grant that can never fire is worse than saying so.
  const unrestrictedOnly = capabilities.filter((c) => c.unrestrictedOnly && grants.includes(c.id))
  const privileged = capabilities.filter((c) => c.privileged && grants.includes(c.id))
  const inertGrants = unrestrictedOnly.length > 0 && (requireScope || hostPatterns.length > 0)
  const canEditScope = unrestrictedOnly.length > 0 && !inertGrants

  function applyProfile(p: AutomationProfile) {
    // The grants themselves are applied by GrantPicker; this adopts the rest of the
    // token shape the profile expects, including turning requireScope off for a
    // profile whose scope grants would otherwise be inert.
    setRequireScope(p.requireScope)
    setAllowCredentials(p.allowsCredentials)
    setRateLimit(p.rateLimitPerMin)
    setMaxConcurrent(p.maxConcurrent)
  }

  async function submit() {
    setErr('')
    setBusy(true)
    try {
      const body: AutomationTokenInput = {
        name: name.trim(),
        grants,
        requireScope,
        hostAllow: hostPatterns,
        allowCredentials,
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
            profiles={profiles}
            classOrder={classes}
            onApplyProfile={applyProfile}
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

          <label className="flex items-center gap-2 cursor-pointer pt-1">
            <input type="checkbox" checked={allowCredentials} onChange={(e) => setAllowCredentials(e.target.checked)} />
            <span className="text-xs">Show credential header values</span>
          </label>
          <p className="text-[10px] text-content-muted leading-snug">
            {allowCredentials
              ? 'Authorization, Cookie, Set-Cookie and similar values are returned in full. Every session token in captured traffic is readable by this token.'
              : 'Those values are masked wherever bytes are returned. The header is still reported as present, and the agent can stay authenticated through its own session cookies without seeing them.'}
          </p>
        </div>

        {sendsTraffic && (
          <p className="text-[11px] text-semantic-warning inline-flex items-start gap-1.5">
            <AlertTriangle size={12} strokeWidth={2} className="mt-0.5 shrink-0" aria-hidden="true" />
            <span>This token can send traffic to targets through Joro’s proxy. Those requests appear in History.</span>
          </p>
        )}

        {mutating.length > 0 && (
          <p className="text-[11px] text-semantic-special leading-snug">
            This token can change Joro itself ({mutating.length} {mutating.length === 1 ? 'capability' : 'capabilities'}):
            edits apply to your own browsing as well as the agent’s, persist into the saved project, and are listed
            individually in Activity.
          </p>
        )}

        {canEditScope && (
          <p className="text-[11px] text-semantic-error leading-snug inline-flex items-start gap-1.5">
            <Unlock size={12} strokeWidth={2} className="mt-0.5 shrink-0" aria-hidden="true" />
            <span>
              This token can add scope rules. Scope is what decides which hosts Joro intercepts, so it can make Joro
              terminate TLS for and record hosts you have not scoped — and it can already read all captured traffic.
              It can only add include rules and enable scope; it cannot exclude, remove, or disable.
            </span>
          </p>
        )}

        {privileged.length > 0 && (
          <p className="text-[11px] text-semantic-error leading-snug inline-flex items-start gap-1.5">
            <KeyRound size={12} strokeWidth={2} className="mt-0.5 shrink-0" aria-hidden="true" />
            <span>
              This token can run commands: {privileged.map((c) => c.toolName).join(', ')}. Scope and the host whitelist
              do not bound the C2 capabilities — they describe web targets, not a team server — so this grant is the
              only limit on what they reach.
            </span>
          </p>
        )}

        {inertGrants && (
          <p className="text-[11px] text-semantic-warning leading-snug">
            {unrestrictedOnly.map((c) => c.toolName).join(', ')} will be refused on every call: a token restricted by
            scope or a host whitelist may not edit scope. Untick “Only allow sends to in-scope targets” and clear the
            host whitelist to use them, or drop those grants.
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
