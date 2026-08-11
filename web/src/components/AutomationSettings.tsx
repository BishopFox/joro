import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, Plus, ShieldAlert } from 'lucide-react'
import { api, type AutomationToken, type AutomationTokenInput } from '../lib/api'
import { useAutomationStore } from '../stores/automationStore'
import { useToastStore } from '../stores/toastStore'
import AutomationTokenModal from './AutomationTokenModal'
import AutomationSecretModal from './AutomationSecretModal'
import AutomationActivity from './AutomationActivity'
import ConfirmModal from './ConfirmModal'

const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border'

export default function AutomationSettings() {
  const { tokens, capabilities, profiles, classes, mcp, available, refresh, create, update, rotate, setEnabled, review, revoke, setMcp } =
    useAutomationStore()
  const addToast = useToastStore((s) => s.addToast)

  // Grants a token holds that the registry refuses it: a scope-write capability
  // needs a token with scope enforcement off and no host whitelist. These fail
  // closed at call time, so the table flags them rather than the server rejecting
  // the token — but an operator should not have to read Activity to find out.
  const inertGrants = (t: AutomationToken) =>
    !(t.requireScope || (t.hostAllow?.length ?? 0) > 0)
      ? []
      : capabilities.filter((c) => c.unrestrictedOnly && t.grants.includes(c.id)).map((c) => c.toolName)

  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<AutomationToken | null>(null)
  const [secret, setSecret] = useState<{ value: string; name: string } | null>(null)
  const [confirm, setConfirm] = useState<{ message: string; action: () => Promise<void> } | null>(null)
  const [port, setPort] = useState(0)
  const [scopeReady, setScopeReady] = useState(true)

  useEffect(() => {
    refresh()
  }, [refresh])

  useEffect(() => {
    if (mcp && port === 0) setPort(mcp.port)
  }, [mcp, port])

  // The scope banner needs to know whether scope is usable, not just enabled:
  // scope with zero rules blocks everything, which is the same practical outcome
  // for a scope-requiring token as scope being off.
  const checkScope = useCallback(async () => {
    try {
      const s = await api.getScope()
      setScopeReady(s.enabled && s.rules.length > 0)
    } catch {
      setScopeReady(true)
    }
  }, [])
  useEffect(() => {
    checkScope()
  }, [checkScope])

  if (available === false) {
    return (
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-wide mb-3">Automation</h2>
        <p className="text-content-muted text-xs">
          Automation is disabled for this run (<code className="font-mono">--no-automation</code>). Restart Joro without
          that flag to issue tokens and run the MCP server.
        </p>
      </div>
    )
  }

  const sendCapableEnabled = tokens.some((t) => !t.disabled && !t.expired && t.sendsTraffic)

  async function guard(fn: () => Promise<unknown>, ok: string) {
    try {
      await fn()
      if (ok) addToast(ok, 'info')
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    }
  }

  const handleCreate = async (body: AutomationTokenInput) => {
    const s = await create(body)
    setSecret({ value: s, name: body.name ?? 'token' })
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide">Automation</h2>
        <button
          onClick={() => setCreating(true)}
          className="bg-accent-tertiary text-black text-xs font-semibold px-2.5 py-1 rounded-sm inline-flex items-center gap-1.5"
        >
          <Plus size={13} strokeWidth={2.4} aria-hidden="true" />
          New token
        </button>
      </div>

      {/* MCP listener */}
      <div className="bg-surface-card border border-border rounded p-3 space-y-2">
        <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide">MCP server</h3>
        <p className="text-[11px] text-content-muted leading-snug">
          Serves Joro’s capabilities to a local automation client over MCP. Loopback only, off by default, and it
          refuses to start with no tokens configured. Joro embeds no model and makes no outbound AI calls.
        </p>

        <div className="flex items-center gap-3 flex-wrap">
          <label className="flex items-center gap-2 text-xs cursor-pointer">
            <input
              type="checkbox"
              checked={mcp?.enabled ?? false}
              onChange={(e) => guard(() => setMcp({ enabled: e.target.checked, port }), '')}
            />
            Enabled
          </label>
          <label className="flex items-center gap-1.5 text-xs">
            Port
            <input
              type="number"
              className={`${inputCls} w-24`}
              value={port || ''}
              onChange={(e) => setPort(Number(e.target.value))}
              onBlur={() => mcp && port !== mcp.port && guard(() => setMcp({ port }), 'MCP port updated')}
            />
          </label>
          {mcp && (
            <span
              className={`text-[11px] px-2 py-0.5 rounded-sm ${
                mcp.running
                  ? 'bg-surface-input text-semantic-success'
                  : mcp.error
                    ? 'bg-surface-input text-semantic-error'
                    : 'bg-surface-input text-content-muted'
              }`}
            >
              {mcp.running ? 'running' : mcp.error ? `error: ${mcp.error}` : 'stopped'}
            </span>
          )}
          {mcp?.running && <code className="font-mono text-[11px] text-content-secondary">{mcp.endpoint}</code>}
        </div>
        <p className="text-[10px] text-content-muted">
          A grant change does not push to a connected client — this transport initiates no messages. The client picks it
          up on its next tool listing, or on reconnect.
        </p>
      </div>

      {/* Fail-closed scope warning */}
      {sendCapableEnabled && !scopeReady && (
        <div className="border border-semantic-warning rounded p-2.5 flex items-start gap-2">
          <ShieldAlert size={15} strokeWidth={2} className="text-semantic-warning shrink-0 mt-0.5" aria-hidden="true" />
          <p className="text-[11px] leading-snug">
            A token that can send traffic is active, but scope is off or has no rules. Those sends are being{' '}
            <strong>refused</strong>, by design — set an include rule in Settings → Project → Filtering, or reissue the
            token with the scope requirement turned off.
          </p>
        </div>
      )}

      {/* Tokens */}
      {tokens.length === 0 ? (
        <div className="text-content-muted text-sm italic py-8 text-center">
          No automation tokens. Create one to connect an MCP client.
        </div>
      ) : (
        <div className="bg-surface-card border border-border rounded overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-content-muted text-[10px] uppercase tracking-wide border-b border-border">
                <th className="text-left font-medium px-3 py-2">Token</th>
                <th className="text-left font-medium px-3 py-2">Grants</th>
                <th className="text-left font-medium px-3 py-2">Scope</th>
                <th className="text-left font-medium px-3 py-2">Limits</th>
                <th className="text-left font-medium px-3 py-2">Last used</th>
                <th className="text-left font-medium px-3 py-2">Status</th>
                <th className="text-right font-medium px-3 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((t) => (
                <tr key={t.id} className="border-b border-border-subtle last:border-0 hover:bg-surface-hover">
                  <td className="px-3 py-2">
                    <div className="font-medium">{t.name}</div>
                    <code className="font-mono text-[10px] text-content-muted">joro_{t.prefix}…</code>
                  </td>
                  <td className="px-3 py-2">
                    <span title={t.grants.join('\n')}>{t.grants.length}</span>
                    {t.sendsTraffic && (
                      <AlertTriangle
                        size={12}
                        strokeWidth={2.2}
                        className="text-semantic-warning inline ml-1.5 -mt-0.5"
                        aria-label="can send traffic to targets"
                      />
                    )}
                    {t.ungrantedCapabilities && t.ungrantedCapabilities.length > 0 && (
                      <button
                        onClick={() => setEditing(t)}
                        className="block text-[10px] text-accent hover:underline mt-0.5"
                      >
                        {t.ungrantedCapabilities.length} not granted →
                      </button>
                    )}
                  </td>
                  <td className="px-3 py-2 text-content-secondary">
                    {t.requireScope ? 'required' : <span className="text-semantic-warning">off</span>}
                    {t.hostAllow && t.hostAllow.length > 0 && (
                      <span className="text-content-muted" title={t.hostAllow.join('\n')}>
                        {' '}
                        +{t.hostAllow.length} host
                      </span>
                    )}
                    {t.allowCredentials && (
                      <span
                        className="block text-[10px] text-semantic-warning"
                        title="Authorization, Cookie and similar header values are returned in full to this token."
                      >
                        credentials visible
                      </span>
                    )}
                    {inertGrants(t).length > 0 && (
                      <span
                        className="block text-[10px] text-semantic-warning"
                        title={`Refused on every call for this token: ${inertGrants(t).join(', ')}. A token restricted by scope or a host whitelist may not edit scope.`}
                      >
                        {inertGrants(t).length} grant{inertGrants(t).length === 1 ? '' : 's'} inert
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-content-muted">
                    {t.rateLimitPerMin}/min · {t.maxConcurrent} conc
                  </td>
                  <td className="px-3 py-2 text-content-muted">
                    {t.lastUsedAt ? (
                      <>
                        <div>{new Date(t.lastUsedAt).toLocaleString()}</div>
                        <div className="text-[10px]">{t.lastUsedCapability}</div>
                      </>
                    ) : (
                      'never'
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {t.expired ? (
                      <span className="text-semantic-error">expired</span>
                    ) : t.disabled ? (
                      <span className="text-content-muted">disabled</span>
                    ) : (
                      <span className="text-semantic-success">active</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right space-x-2 whitespace-nowrap">
                    <button onClick={() => setEditing(t)} className="text-accent-secondary hover:underline">
                      Edit
                    </button>
                    <button
                      onClick={() =>
                        setConfirm({
                          message: `Rotate ${t.name}? The current secret stops working immediately, and any client using it will fail on its next request.`,
                          action: async () => {
                            const s = await rotate(t.id)
                            setSecret({ value: s, name: t.name })
                          },
                        })
                      }
                      className="text-accent-secondary hover:underline"
                    >
                      Rotate
                    </button>
                    <button
                      onClick={() => guard(() => setEnabled(t.id, t.disabled), t.disabled ? 'Enabled' : 'Disabled')}
                      className="text-accent-secondary hover:underline"
                    >
                      {t.disabled ? 'Enable' : 'Disable'}
                    </button>
                    {t.ungrantedCapabilities && t.ungrantedCapabilities.length > 0 && (
                      <button onClick={() => guard(() => review(t.id), 'Marked reviewed')} className="text-content-muted hover:underline">
                        Reviewed
                      </button>
                    )}
                    <button
                      onClick={() =>
                        setConfirm({
                          message: `Revoke ${t.name}? This cannot be undone. Activity history is kept.`,
                          action: () => revoke(t.id),
                        })
                      }
                      className="text-semantic-error hover:underline"
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="text-[10px] text-content-muted leading-snug">
        Tokens limit what an automation client can do. They do not restrict other programs on this machine — Joro’s
        local API is open to local processes by design. Requests sent by automation go through Joro’s proxy and appear
        in History, where Match &amp; Replace and Custom Data rules apply to them like any other request.
      </p>

      <AutomationActivity />

      {creating && (
        <AutomationTokenModal
          capabilities={capabilities}
          profiles={profiles}
          classes={classes}
          onSubmit={handleCreate}
          onClose={() => setCreating(false)}
        />
      )}
      {editing && (
        <AutomationTokenModal
          capabilities={capabilities}
          profiles={profiles}
          classes={classes}
          token={editing}
          onSubmit={(body) => update(editing.id, body)}
          onClose={() => setEditing(null)}
        />
      )}
      {secret && mcp && (
        <AutomationSecretModal
          secret={secret.value}
          tokenName={secret.name}
          endpoint={mcp.endpoint}
          onClose={() => setSecret(null)}
        />
      )}
      {confirm && (
        <ConfirmModal
          message={confirm.message}
          onConfirm={() => {
            const run = confirm.action
            setConfirm(null)
            guard(run, 'Done')
          }}
          onClose={() => setConfirm(null)}
        />
      )}
    </div>
  )
}
