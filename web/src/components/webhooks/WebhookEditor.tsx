import { useCallback, useEffect, useMemo, useState } from 'react'
import { Plus, Save, Send, Trash2, X } from 'lucide-react'
import {
  api,
  type Trigger,
  type Webhook,
  type WebhookHeader,
  type WebhookTest,
  type WebhookToken,
} from '../../lib/api'
import { useToastStore } from '../../stores/toastStore'
import { useWebhookStore } from '../../stores/webhookStore'
import WebhookDeliveries from './WebhookDeliveries'

/**
 * The webhook editor: identity and triggers at the top, then destination, body and delivery.
 *
 * Two things about it are load-bearing rather than cosmetic.
 *
 * A secret is never in this buffer. The server returns every secret empty and keeps what it
 * already holds when one comes back empty, so an operator who edits a name does not silently
 * wipe a signing key they cannot see. The fields show a placeholder saying one is stored.
 *
 * The body is a JSON document, not a string with holes. What the server does with a custom
 * template is parse it, then substitute only inside string leaves — so what an operator writes
 * here is the finished shape, and a placeholder can only fill a value. The reference list
 * beside the box is served, so it cannot offer a field the server would refuse.
 */

const inputCls =
  'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border text-content-primary w-full'

const BLANK: Webhook = {
  id: '',
  name: '',
  enabled: false,
  triggers: [],
  url: '',
  method: 'POST',
  headers: [],
  auth: { kind: 'none' },
  signing: { enabled: false, header: 'X-Joro-Signature' },
  format: 'envelope',
  delivery: 'each',
  timeoutMs: 10000,
  retries: 2,
  minIntervalMs: 1000,
  hasAuthSecret: false,
  hasSigningSecret: false,
  secretHeaders: [],
}

const SLACK_TEMPLATE = '{\n  "text": "{{SUMMARY}}"\n}'
const STARTER_TEMPLATE = `{
  "title": "{{SUMMARY}}",
  "event": "{{EVENT}}",
  "host": "{{host}}",
  "url": "{{url}}",
  "at": "{{TIME}}"
}`

export default function WebhookEditor({
  draft,
  triggers,
  onClose,
  onSaved,
  onDeleted,
  onDirtyChange,
}: {
  /** The webhook being edited or created. Null while the list has not caught up with a
   *  selection, which a refetch resolves. */
  draft: Webhook | null
  /** The trigger catalog, built-ins first, as the reference picker offers it. */
  triggers: Trigger[]
  onClose: () => void
  /** Called after a successful write with the stored id, which a create only has once it
   *  lands and which the rail adopts so a second Save updates rather than recreating. */
  onSaved: (id: string) => void | Promise<void>
  onDeleted?: () => void | Promise<void>
  onDirtyChange?: (dirty: boolean) => void
}) {
  const addToast = useToastStore((s) => s.addToast)
  const { formats, deliveries, authKinds, methods, tokens, fields, limits } = useWebhookStore()

  const [h, setH] = useState<Webhook>(draft ?? BLANK)
  const [busy, setBusy] = useState(false)
  const [test, setTest] = useState<WebhookTest | null>(null)
  // What the buffer looked like when it was last in step with the server. Compared rather than
  // tracked with a flag, so typing a change and undoing it leaves the editor clean.
  const [pristine, setPristine] = useState(() => JSON.stringify(draft ?? BLANK))
  // Whether this webhook has ever been stored. Held rather than derived from h.id, which the
  // name field writes to on the first keystroke — deriving it would freeze the id after one
  // character.
  const [creating, setCreating] = useState(!draft?.id)

  useEffect(() => {
    if (!draft) return
    setH(draft)
    setPristine(JSON.stringify(draft))
    setCreating(!draft.id)
    setTest(null)
  }, [draft])

  const dirty = JSON.stringify(h) !== pristine
  useEffect(() => {
    onDirtyChange?.(dirty)
  }, [dirty, onDirtyChange])
  // Leaving the editor cannot leave a stale dirty flag behind on the shell.
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const patch = (p: Partial<Webhook>) => setH((cur) => ({ ...cur, ...p }))

  /** The events this webhook's triggers resolve to. What decides which placeholders are
   *  available, and whether a batched delivery makes sense. */
  const events = useMemo(() => {
    const out: string[] = []
    for (const ref of h.triggers) {
      const t = triggers.find((x) => x.id === ref)
      if (t && !out.includes(t.on)) out.push(t.on)
    }
    return out
  }, [h.triggers, triggers])

  const available = useMemo(() => {
    const names = new Set<string>()
    for (const on of events) for (const f of fields[on] ?? []) names.add(f)
    return [...names].sort()
  }, [events, fields])

  const toggleTrigger = (id: string) => {
    const has = h.triggers.includes(id)
    if (!has && h.triggers.length >= limits.triggers) {
      addToast(`A webhook watches at most ${limits.triggers} triggers.`, 'error')
      return
    }
    patch({ triggers: has ? h.triggers.filter((t) => t !== id) : [...h.triggers, id] })
  }

  const setHeader = (i: number, next: Partial<WebhookHeader>) => {
    const headers = [...(h.headers ?? [])]
    headers[i] = { ...headers[i], ...next }
    patch({ headers })
  }

  const save = async () => {
    setBusy(true)
    try {
      const saved = creating ? await api.createWebhook(h) : await api.updateWebhook(h.id, h)
      // Take the stored webhook back rather than keeping what was sent: Normalize fills
      // defaults and lowercases the id, and problem is computed on the way out. Without this
      // the editor stays dirty against a copy the server already rewrote.
      setH(saved)
      setPristine(JSON.stringify(saved))
      setCreating(false)
      await onSaved(saved.id)
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    } finally {
      setBusy(false)
    }
  }

  const runTest = useCallback(async () => {
    setBusy(true)
    try {
      setTest(await api.testWebhook(h.id))
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    } finally {
      setBusy(false)
    }
  }, [h.id, addToast])

  const remove = async () => {
    setBusy(true)
    try {
      await api.deleteWebhook(h.id)
      setPristine(JSON.stringify(h))
      await (onDeleted ? onDeleted() : onClose())
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    } finally {
      setBusy(false)
    }
  }

  // The rail selects by id and the list refetches behind it, so there is a tick where the
  // selection names a webhook the list has not produced yet.
  if (!draft) {
    return (
      <div className="flex-1 overflow-auto p-5 text-[11px] text-content-muted italic">
        Loading webhook&hellip;
      </div>
    )
  }

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="flex items-start gap-2 p-5 pb-3 border-b border-border-subtle">
        <div className="flex-1 grid grid-cols-[auto_1fr_auto_1fr] gap-2 items-center max-w-3xl">
          <label className="text-[11px] text-content-muted">
            Name
            {dirty && (
              <span className="ml-1 text-accent-tertiary" title="Unsaved changes">
                &bull;
              </span>
            )}
          </label>
          <input
            className={inputCls}
            value={h.name}
            placeholder="Team Slack"
            onChange={(e) => {
              // The id is what an automation names in joro.webhook.send, so it is derived
              // from the name once and then frozen — renaming later must not break a script.
              const name = e.target.value
              patch(creating ? { name, id: slug(name) } : { name })
            }}
          />
          <label className="text-[11px] text-content-muted">Method</label>
          <select
            className={inputCls}
            value={h.method}
            onChange={(e) => patch({ method: e.target.value })}
          >
            {methods.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>

          <label className="text-[11px] text-content-muted">Description</label>
          <input
            className={`${inputCls} col-span-3`}
            value={h.description ?? ''}
            placeholder="What this is for"
            onChange={(e) => patch({ description: e.target.value })}
          />
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={runTest}
            disabled={busy || creating || dirty}
            title={
              creating
                ? 'Save this webhook first — a test sends a real request to the endpoint'
                : dirty
                  ? 'Save first: a test sends what is stored, not what is on screen'
                  : 'Send a sample event to this endpoint for real'
            }
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-50"
          >
            <Send size={11} strokeWidth={2} aria-hidden="true" />
            Test
          </button>
          <button
            onClick={save}
            disabled={busy || !h.name.trim() || !h.url.trim()}
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-50"
          >
            <Save size={11} strokeWidth={2.4} aria-hidden="true" />
            {creating ? 'Create' : 'Save'}
          </button>
          {!creating && (
            <button
              onClick={remove}
              disabled={busy}
              title="Delete this webhook"
              className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-semantic-error disabled:opacity-40"
            >
              <Trash2 size={11} strokeWidth={2} aria-hidden="true" />
            </button>
          )}
          <button
            onClick={onClose}
            className="text-content-muted hover:text-content-primary"
            aria-label="Close"
          >
            <X size={15} strokeWidth={2} />
          </button>
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-auto p-5 pt-3 space-y-4">
        {h.problem && <p className="text-[11px] text-semantic-error">{h.problem}</p>}
        {h.paused && (
          <p className="text-[11px] text-semantic-warning">
            Paused by Joro. {h.pausedReason}
          </p>
        )}

        <Section title="Fires on">
          <p className="text-[10px] text-content-muted mb-1.5 leading-relaxed">
            Joro&rsquo;s own events fire every time they happen; a custom trigger adds conditions
            so it fires on some of them. A trigger that is deleted or unreadable never fires —
            it never means &ldquo;no filter&rdquo;.
          </p>
          <div className="flex flex-wrap gap-1">
            {triggers.map((t) => {
              const on = h.triggers.includes(t.id)
              return (
                <button
                  key={t.id}
                  onClick={() => toggleTrigger(t.id)}
                  title={t.builtin ? `Every ${t.on}` : `${t.on} — ${t.description || t.name}`}
                  className={`text-[10px] px-2 py-0.5 rounded-sm border ${
                    on
                      ? 'border-accent-secondary bg-surface-input text-content-primary'
                      : 'border-border text-content-secondary hover:bg-surface-hover'
                  }`}
                >
                  {t.builtin ? t.id : t.name}
                </button>
              )
            })}
          </div>
        </Section>

        <Section title="Destination">
          <div className="grid grid-cols-[auto_1fr] gap-2 items-center max-w-3xl">
            <label className="text-[11px] text-content-muted">URL</label>
            <input
              className={`${inputCls} font-mono joro-redact-field`}
              value={h.url}
              placeholder="https://hooks.example.com/services/..."
              onChange={(e) => patch({ url: e.target.value })}
            />

            <label className="text-[11px] text-content-muted">Auth</label>
            <div className="flex gap-2">
              <select
                className={`${inputCls} w-28`}
                value={h.auth.kind}
                onChange={(e) =>
                  patch({ auth: { ...h.auth, kind: e.target.value as Webhook['auth']['kind'] } })
                }
              >
                {authKinds.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </select>
              {h.auth.kind === 'header' && (
                <input
                  className={`${inputCls} w-48`}
                  value={h.auth.header ?? ''}
                  placeholder="X-Api-Key"
                  onChange={(e) => patch({ auth: { ...h.auth, header: e.target.value } })}
                />
              )}
              {h.auth.kind === 'basic' && (
                <input
                  className={`${inputCls} w-40 joro-redact-field`}
                  value={h.auth.user ?? ''}
                  placeholder="username"
                  onChange={(e) => patch({ auth: { ...h.auth, user: e.target.value } })}
                />
              )}
              {h.auth.kind !== 'none' && (
                <input
                  type="password"
                  className={inputCls}
                  value={h.auth.token ?? ''}
                  placeholder={h.hasAuthSecret ? 'stored — leave blank to keep' : 'secret'}
                  onChange={(e) => patch({ auth: { ...h.auth, token: e.target.value } })}
                />
              )}
            </div>

            <label className="text-[11px] text-content-muted">Signing</label>
            <div className="flex gap-2 items-center">
              <label className="flex items-center gap-1.5 text-[11px] text-content-secondary">
                <input
                  type="checkbox"
                  checked={h.signing.enabled}
                  onChange={(e) => patch({ signing: { ...h.signing, enabled: e.target.checked } })}
                />
                HMAC-SHA256
              </label>
              {h.signing.enabled && (
                <>
                  <input
                    className={`${inputCls} w-56`}
                    value={h.signing.header ?? ''}
                    placeholder="X-Joro-Signature"
                    onChange={(e) => patch({ signing: { ...h.signing, header: e.target.value } })}
                  />
                  <input
                    type="password"
                    className={inputCls}
                    value={h.signing.secret ?? ''}
                    placeholder={h.hasSigningSecret ? 'stored — leave blank to keep' : 'shared secret'}
                    onChange={(e) => patch({ signing: { ...h.signing, secret: e.target.value } })}
                  />
                </>
              )}
            </div>
          </div>
          {h.signing.enabled && (
            <p className="text-[10px] text-content-muted mt-1.5 leading-relaxed">
              Signed over <code className="font-mono">&lt;X-Joro-Timestamp&gt;.&lt;body&gt;</code>,
              sent as <code className="font-mono">sha256=&lt;hex&gt;</code>. The timestamp is inside
              the signed string so a receiver that checks it cannot be replayed.
            </p>
          )}

          <div className="mt-2">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-content-muted mb-1">
              Headers
            </div>
            <div className="space-y-1">
              {(h.headers ?? []).map((hd, i) => (
                <div
                  key={i}
                  className="rounded-sm border border-border bg-surface-card p-2 flex items-center gap-1"
                >
                  <input
                    className={`${inputCls} w-56`}
                    value={hd.name}
                    placeholder="X-Custom"
                    onChange={(e) => setHeader(i, { name: e.target.value })}
                  />
                  <input
                    type="password"
                    className={inputCls}
                    value={hd.value}
                    placeholder={
                      h.secretHeaders.includes(hd.name) ? 'stored — leave blank to keep' : 'value'
                    }
                    onChange={(e) => setHeader(i, { value: e.target.value })}
                  />
                  <button
                    onClick={() => patch({ headers: (h.headers ?? []).filter((_, j) => j !== i) })}
                    className="text-content-muted hover:text-semantic-error"
                    aria-label="Remove header"
                  >
                    <Trash2 size={11} strokeWidth={2} />
                  </button>
                </div>
              ))}
            </div>
            <button
              onClick={() => patch({ headers: [...(h.headers ?? []), { name: '', value: '' }] })}
              disabled={(h.headers ?? []).length >= limits.headers}
              className="mt-1 inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-40"
            >
              <Plus size={11} strokeWidth={2.4} aria-hidden="true" />
              Header
            </button>
          </div>
        </Section>

        <Section title="Body">
          <div className="flex items-center gap-2 mb-2">
            <select
              className={`${inputCls} w-40`}
              value={h.format}
              onChange={(e) => {
                const format = e.target.value as Webhook['format']
                // A template renders one event's fields, so it implies one request per event.
                // Set here as well as refused by the server, so the delivery select does not
                // sit on a value that will fail to save.
                const next: Partial<Webhook> = { format }
                if (format === 'template') {
                  next.delivery = 'each'
                  if (!h.template) {
                    next.template = h.url.includes('slack.com') ? SLACK_TEMPLATE : STARTER_TEMPLATE
                  }
                }
                patch(next)
              }}
            >
              {formats.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
            <select
              className={`${inputCls} w-40`}
              value={h.delivery}
              disabled={h.format === 'template'}
              title={
                h.format === 'template'
                  ? 'A template renders one event, so it sends one request per event'
                  : undefined
              }
              onChange={(e) => patch({ delivery: e.target.value as Webhook['delivery'] })}
            >
              {deliveries.map((d) => (
                <option key={d} value={d}>
                  {d === 'each' ? 'one request per event' : 'batch events together'}
                </option>
              ))}
            </select>
          </div>

          <p className="text-[10px] text-content-muted leading-relaxed">
            {h.format === 'envelope' &&
              'Joro’s own JSON: the event, the trigger that matched, a one-line summary, and every field the event carries.'}
            {h.format === 'slack' && 'Slack’s shape: {"text": "…"} carrying the one-line summary.'}
            {h.format === 'discord' && 'Discord’s shape: {"content": "…"} carrying the one-line summary.'}
            {h.format === 'template' &&
              'A JSON document you write. Placeholders are substituted into string values only, so what you write here is the finished shape — a value off the wire cannot add a key or break out of a string.'}
          </p>

          {h.format === 'template' && (
            <div className="mt-2 flex gap-3 items-start">
              <textarea
                className={`${inputCls} font-mono flex-1 min-h-48`}
                spellCheck={false}
                value={h.template ?? ''}
                maxLength={limits.templateBytes}
                onChange={(e) => patch({ template: e.target.value })}
              />
              <div className="w-64 shrink-0 text-[10px] leading-relaxed">
                <TokenList label="Always available" items={tokens.map((t) => t.token)} tokens={tokens} />
                {events.map((on) => (
                  <TokenList
                    key={on}
                    label={on}
                    items={(fields[on] ?? []).map((f) => `{{${f}}}`)}
                  />
                ))}
                {events.length === 0 && (
                  <p className="text-content-muted italic mt-1">
                    Choose a trigger above to see the fields its event carries.
                  </p>
                )}
                {events.length > 1 && available.length > 0 && (
                  <p className="text-content-muted mt-2">
                    This webhook watches more than one event. A placeholder the firing event does
                    not carry renders empty.
                  </p>
                )}
              </div>
            </div>
          )}
        </Section>

        <Section title="Delivery">
          <div className="grid grid-cols-[auto_1fr_auto_1fr] gap-2 items-center max-w-2xl">
            <label className="text-[11px] text-content-muted">Minimum interval</label>
            <NumberField
              value={h.minIntervalMs ?? 1000}
              max={limits.minIntervalMs}
              suffix="ms"
              onChange={(v) => patch({ minIntervalMs: v })}
            />
            <label className="text-[11px] text-content-muted">Timeout</label>
            <NumberField
              value={h.timeoutMs ?? 10000}
              max={limits.timeoutMs}
              suffix="ms"
              onChange={(v) => patch({ timeoutMs: v })}
            />
            <label className="text-[11px] text-content-muted">Retries</label>
            <NumberField
              value={h.retries ?? 2}
              max={limits.retries}
              suffix=""
              onChange={(v) => patch({ retries: v })}
            />
          </div>
          <p className="text-[10px] text-content-muted mt-1.5 leading-relaxed">
            Retries back off, doubling from half a second, and only for a timeout, a connection
            failure, a 429 or a 5xx — a 4xx is the receiver saying the request is wrong, and
            repeating it will not make it right. Events that arrive faster than the interval queue
            up; past the queue&rsquo;s bound the oldest are dropped, and the count travels in the
            next delivery so the receiver knows it was told less than everything.
          </p>

          <label className="flex items-center gap-1.5 text-[11px] text-content-secondary mt-2">
            <input
              type="checkbox"
              checked={!!h.insecureTls}
              onChange={(e) => patch({ insecureTls: e.target.checked })}
            />
            Skip TLS certificate verification
          </label>
          <p className="text-[10px] text-content-muted leading-relaxed">
            For an internal receiver with a self-signed certificate. Leave it off for anything on
            the public internet: a webhook URL is frequently the credential itself, and an
            unverified connection hands it to whoever answered.
          </p>

          <label className="flex items-center gap-1.5 text-[11px] text-content-secondary mt-2">
            <input
              type="checkbox"
              checked={!!h.allowAutomations}
              onChange={(e) => patch({ allowAutomations: e.target.checked })}
            />
            Let automations fire this
          </label>
          <p className="text-[10px] text-content-muted leading-relaxed">
            An automation calls <code className="font-mono">joro.webhook.send</code> with this
            webhook&rsquo;s id and a one-line message. It cannot see or choose the destination, and
            the body stays the shape set above — the message fills{' '}
            <code className="font-mono">{'{{MESSAGE}}'}</code> and stands in for the summary. This
            tick is the whole gate: without it no automation can reach this endpoint, and none can
            tell it apart from one that does not exist.
          </p>
        </Section>

        {test && <TestOutcome test={test} />}

        {!creating && <WebhookDeliveries id={h.id} />}
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-muted mb-1.5">
        {title}
      </div>
      {children}
    </div>
  )
}

function NumberField({
  value,
  max,
  suffix,
  onChange,
}: {
  value: number
  max: number
  suffix: string
  onChange: (v: number) => void
}) {
  return (
    <div className="flex items-center gap-1">
      <input
        type="number"
        min={0}
        max={max}
        className={`${inputCls} w-24`}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
      {suffix && <span className="text-[10px] text-content-muted">{suffix}</span>}
    </div>
  )
}

function TokenList({
  label,
  items,
  tokens,
}: {
  label: string
  items: string[]
  tokens?: WebhookToken[]
}) {
  if (items.length === 0) return null
  return (
    <div className="mt-1.5">
      <div className="text-content-muted uppercase tracking-wide font-semibold">{label}</div>
      <div className="flex flex-wrap gap-1 mt-0.5">
        {items.map((t) => (
          <code
            key={t}
            className="font-mono text-content-secondary bg-surface-input px-1 rounded-sm"
            title={tokens?.find((x) => x.token === t)?.description}
          >
            {t}
          </code>
        ))}
      </div>
    </div>
  )
}

/** The dry run's outcome: the exact bytes sent, and what the endpoint answered. */
function TestOutcome({ test }: { test: WebhookTest }) {
  const ok = !test.error && test.status > 0 && test.status < 400
  return (
    <div
      className={`rounded-sm border p-2 space-y-1 ${
        ok ? 'border-border bg-surface-card' : 'border-semantic-error bg-surface-card'
      }`}
    >
      <div className="text-[11px]">
        {ok ? (
          <span className="text-semantic-success font-semibold">
            Delivered — {test.status} in {test.durationMs}ms
          </span>
        ) : (
          <span className="text-semantic-error font-semibold">
            {test.status > 0 ? `${test.status} — ` : ''}
            {test.error || 'no response'}
          </span>
        )}
      </div>
      <pre className="text-[10px] font-mono text-content-secondary whitespace-pre-wrap break-all max-h-40 overflow-auto">
        {test.body}
      </pre>
    </div>
  )
}

/** A name turned into an id: lowercase, hyphenated, and stripped of everything the server
 *  refuses. */
function slug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
}
