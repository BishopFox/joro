import { useCallback, useEffect, useRef, useState } from 'react'
import { Bot, Plus, Power, PowerOff } from 'lucide-react'
import { api, type Webhook } from '../../lib/api'
import { useToastStore } from '../../stores/toastStore'
import { useTriggerStore } from '../../stores/triggerStore'
import { useWebhookStore } from '../../stores/webhookStore'
import ConfirmModal from '../ConfirmModal'
import { Redacted } from '../Redacted'
import WebhookEditor from './WebhookEditor'

/**
 * Settings -> Webhooks: a rail of configured endpoints beside the one being edited.
 *
 * The same shape as the Scripting panel, for the same reason — a webhook is authored against
 * the triggers listed one tab over, and a table you drill into and cannot get back from makes
 * moving between them a one-way jump. The rail owns selection and nothing else; the editor
 * keeps its own buffer and reports whether it is dirty, so leaving one mid-edit asks first.
 */

/** What the detail pane is showing. A webhook being created has no id yet, so it travels as a
 *  draft rather than as a lookup key. */
type Selection = { id?: string; draft?: Webhook; seq?: number } | null

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

export default function WebhookSettings() {
  const addToast = useToastStore((s) => s.addToast)
  const { webhooks, limits, unavailable, refresh } = useWebhookStore()
  const { triggers, refresh: refreshTriggers } = useTriggerStore()

  const [sel, setSel] = useState<Selection>(null)
  const [leaving, setLeaving] = useState<{ to: Selection } | null>(null)
  // Read through a ref rather than state: the editor reports it on every keystroke and the rail
  // only ever asks at the moment of a click, so re-rendering the panel for it would cost a
  // render per character typed.
  const dirty = useRef(false)
  // Bumped for every unsaved draft and used as the editor's key. Two new drafts in a row both
  // have no id, so without this the second reuses the first's component — and the editor seeds
  // its buffer from the draft prop once, on mount.
  const draftSeq = useRef(0)

  useEffect(() => {
    refresh()
    refreshTriggers()
  }, [refresh, refreshTriggers])

  const setDirty = useCallback((d: boolean) => {
    dirty.current = d
  }, [])

  const select = useCallback((to: Selection) => {
    if (dirty.current) {
      setLeaving({ to })
      return
    }
    dirty.current = false
    setSel(to)
  }, [])

  const guard = useCallback(
    async (fn: () => Promise<unknown>, ok?: string) => {
      try {
        await fn()
        if (ok) addToast(ok, 'info')
        await refresh()
      } catch (e) {
        addToast(String(e instanceof Error ? e.message : e), 'error')
      }
    },
    [addToast, refresh]
  )

  if (unavailable) {
    return (
      <div className="flex-1 overflow-auto p-5">
        <h3 className="text-sm font-semibold text-content-primary mb-2">Webhooks</h3>
        <p className="text-[11px] text-content-secondary leading-relaxed max-w-xl">{unavailable}</p>
      </div>
    )
  }

  const railRow = (active: boolean) =>
    `w-full text-left px-2 py-1 rounded-sm flex items-center gap-1.5 ${
      active ? 'bg-surface-input text-content-primary' : 'text-content-secondary hover:bg-surface-hover'
    }`

  return (
    <div className="flex flex-1 min-h-0">
      <div className="w-56 shrink-0 border-r border-border overflow-y-auto flex flex-col">
        <div className="sticky top-0 bg-surface-card border-b border-border-subtle px-2 py-1.5 flex items-center gap-1 z-10">
          <button
            onClick={() => select({ seq: ++draftSeq.current, draft: BLANK })}
            disabled={webhooks.length >= limits.webhooks}
            title={
              webhooks.length >= limits.webhooks
                ? `This Joro holds ${limits.webhooks} webhooks, which is the limit`
                : undefined
            }
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-50"
          >
            <Plus size={11} strokeWidth={2.4} aria-hidden="true" />
            New
          </button>
        </div>

        <div className="p-1 pb-4">
          {webhooks.length === 0 ? (
            <p className="px-2 py-1 text-[10px] text-content-muted italic">
              None configured. A webhook posts to an endpoint you choose when something happens.
            </p>
          ) : (
            webhooks.map((h) => {
              const active = sel?.id === h.id
              return (
                <div key={h.id} className="flex items-center gap-0.5 pr-1">
                  <button onClick={() => select({ id: h.id })} className={`${railRow(active)} min-w-0 flex-1`}>
                    <span className="truncate text-[11px]">
                      <Redacted value={h.name} kind="text" />
                    </span>
                    {h.allowAutomations && (
                      <Bot
                        size={9}
                        strokeWidth={2}
                        className="shrink-0 text-content-muted"
                        aria-label="automations may fire this"
                      />
                    )}
                    {h.problem && (
                      <span className="shrink-0 text-[9px] text-semantic-error" title={h.problem}>
                        broken
                      </span>
                    )}
                    {h.paused && (
                      <span className="shrink-0 text-[9px] text-semantic-warning" title={h.pausedReason}>
                        paused
                      </span>
                    )}
                  </button>
                  <button
                    onClick={() =>
                      guard(
                        () => api.setWebhookEnabled(h.id, !h.enabled),
                        h.enabled ? `Disabled ${h.name}` : `Enabled ${h.name}`
                      )
                    }
                    className={`shrink-0 px-0.5 ${
                      h.enabled ? 'text-semantic-success' : 'text-content-muted'
                    } hover:text-accent`}
                    title={
                      h.enabled
                        ? 'Disable'
                        : h.paused
                          ? 'Enable (clears the pause)'
                          : 'Enable — starts delivering on its triggers'
                    }
                  >
                    {h.enabled ? <Power size={12} strokeWidth={2} /> : <PowerOff size={12} strokeWidth={2} />}
                  </button>
                </div>
              )
            })
          )}
        </div>
      </div>

      <div className="flex-1 min-h-0 flex flex-col">
        {sel ? (
          <WebhookEditor
            // Keyed so switching rows rebuilds the buffer instead of leaking the previous
            // webhook's fields into the next one.
            key={sel.id ?? `new-${sel.seq ?? 0}`}
            draft={sel.id ? (webhooks.find((h) => h.id === sel.id) ?? null) : (sel.draft ?? null)}
            triggers={triggers}
            onClose={() => select(null)}
            onDirtyChange={setDirty}
            onSaved={async (id) => {
              await refresh()
              // A create has no id until it lands; adopt it so the rail highlights the row and
              // a second Save updates rather than trying to create again.
              if (id && !sel.id) setSel({ id })
            }}
            onDeleted={async () => {
              await refresh()
              setSel(null)
            }}
          />
        ) : (
          <div className="flex-1 overflow-auto p-8">
            <h3 className="text-sm font-semibold text-content-primary mb-2">Webhooks</h3>
            <p className="text-[11px] text-content-muted leading-relaxed max-w-xl">
              A webhook posts to an endpoint you choose when something happens: a finding Detect
              reported, a response matching a filter you wrote, a fuzzing campaign finishing, an
              automation completing. It watches the same triggers an automation does, so a filter
              you build once decides both.
            </p>
            <p className="text-[10px] text-content-muted leading-relaxed max-w-xl mt-2">
              Configuration lives in <code className="font-mono">~/.joro/webhooks.json</code>, which
              holds secrets and never travels inside a project config. Deliveries go straight out
              rather than through Joro&rsquo;s own proxy, so they are never captured, scanned or
              rewritten &mdash; and a webhook watching traffic cannot feed itself.
            </p>
            <p className="text-[10px] text-content-muted leading-relaxed max-w-xl mt-2">
              An automation can fire one by name, but only one you have ticked open to it. It
              chooses among your endpoints; it never chooses where.
            </p>
          </div>
        )}
      </div>

      {leaving && (
        <ConfirmModal
          title="Discard changes"
          message="This editor has unsaved changes. Leaving now throws them away."
          confirmLabel="Discard"
          onConfirm={() => {
            const to = leaving.to
            setLeaving(null)
            dirty.current = false
            setSel(to)
          }}
          onClose={() => setLeaving(null)}
        />
      )}
    </div>
  )
}
