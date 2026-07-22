import { useEffect, useState } from 'react'
import { api, type CollabRequest } from '../lib/api'
import type { SharedConfigPayload } from '../stores/teamSharedConfigStore'

type Props = {
  collabId: string
  onClose: () => void
  onApplied: (resp: unknown) => void
}

type DiffRow = { label: string; added: number; removed: number }

const EMPTY: SharedConfigPayload = {
  scopeEnabled: false,
  scopeRules: [],
  replaceEnabled: false,
  replaceRules: [],
  customDataEnabled: false,
  customDataItems: [],
}

// Stable key for de-duping/diffing each rule category.
function scopeKey(r: SharedConfigPayload['scopeRules'][number]) {
  return `${r.pattern}|${r.path}|${r.include}|${(r.methods || []).join(',')}`
}
function replaceKey(r: SharedConfigPayload['replaceRules'][number]) {
  return `${r.target}|${r.matchType}|${r.match}|${r.replace}`
}
function customKey(r: SharedConfigPayload['customDataItems'][number]) {
  return `${r.type}|${r.name}|${r.value}`
}

function diffCount<T>(current: T[], incoming: T[], key: (t: T) => string): { added: number; removed: number } {
  const cur = new Set(current.map(key))
  const inc = new Set(incoming.map(key))
  let added = 0
  let removed = 0
  for (const k of inc) if (!cur.has(k)) added++
  for (const k of cur) if (!inc.has(k)) removed++
  return { added, removed }
}

export default function CollabSwapModal({ collabId, onClose, onApplied }: Props) {
  const [req, setReq] = useState<CollabRequest | null>(null)
  const [incoming, setIncoming] = useState<SharedConfigPayload | null>(null)
  const [current, setCurrent] = useState<SharedConfigPayload | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    ;(async () => {
      try {
        const [r, cur] = await Promise.all([api.getCollab(collabId), api.gatherCurrentRules()])
        setReq(r)
        setCurrent(cur)
        try {
          setIncoming(r.config ? (JSON.parse(r.config) as SharedConfigPayload) : EMPTY)
        } catch {
          setIncoming(EMPTY)
        }
      } catch (e) {
        setError(String(e))
      }
    })()
  }, [collabId])

  const diffs: DiffRow[] =
    incoming && current
      ? [
          { label: 'Scope', ...diffCount(current.scopeRules, incoming.scopeRules, scopeKey) },
          { label: 'Match & Replace', ...diffCount(current.replaceRules, incoming.replaceRules, replaceKey) },
          { label: 'Custom Data', ...diffCount(current.customDataItems, incoming.customDataItems, customKey) },
        ]
      : []

  async function act(action: 'merge' | 'save-load' | 'load' | 'keep') {
    if (!incoming) return
    setBusy(true)
    setError('')
    try {
      if (action === 'save-load') {
        let name = ''
        try {
          name = (await api.listProjectConfigs()).active || ''
        } catch { /* ignore */ }
        if (!name) name = window.prompt('Save current project as:') || ''
        if (name) await api.saveProjectConfig(name)
      }
      if (action === 'merge') {
        const resp = await api.applySharedConfig(incoming, 'merge')
        onApplied(resp)
      } else if (action === 'save-load' || action === 'load') {
        const resp = await api.applySharedConfig(incoming, 'replace')
        onApplied(resp)
      }
      // 'keep' applies nothing.
      await api.acceptCollab(collabId)
      onClose()
    } catch (e) {
      setError(String(e))
      setBusy(false)
    }
  }


  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6" onMouseDown={onClose}>
      <div
        className="flex flex-col w-full max-w-lg bg-surface-card border border-border rounded shadow-lg overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="shrink-0 px-4 py-3 border-b border-border">
          <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
            🤝 Collaboration request
          </span>
          {req && (
            <p className="text-xs text-content-secondary mt-1">
              <span className="text-accent-secondary font-medium">{req.requestor}</span>
              {req.project && <> on <span className="text-content-primary">{req.project}</span></>}
              {req.note && <> — “{req.note}”</>}
            </p>
          )}
        </div>

        <div className="px-4 py-3 space-y-2">
          <p className="text-[11px] text-content-muted uppercase tracking-wide">Differences vs your current config</p>
          {incoming && current ? (
            <div className="text-xs divide-y divide-border-subtle">
              {diffs.map((d) => (
                <div key={d.label} className="flex items-center py-1.5">
                  <span className="text-content-primary">{d.label}</span>
                  <span className="ml-auto flex gap-3">
                    <span className="text-semantic-success">+{d.added}</span>
                    <span className="text-semantic-error">−{d.removed}</span>
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-content-muted">Loading…</p>
          )}
          {error && <p className="text-semantic-error text-xs">{error}</p>}
        </div>

        <div className="shrink-0 flex flex-col gap-2 px-4 py-3 border-t border-border">
          <button
            disabled={busy || !incoming}
            onClick={() => act('merge')}
            className="w-full px-3 py-2 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
          >
            Merge into my current config
          </button>
          <button
            disabled={busy || !incoming}
            onClick={() => act('save-load')}
            className="w-full px-3 py-2 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold disabled:opacity-50"
          >
            Save my project & load theirs
          </button>
          <button
            disabled={busy || !incoming}
            onClick={() => act('load')}
            className="w-full px-3 py-2 rounded-sm bg-surface-input hover:bg-surface-hover text-content-primary text-xs font-semibold disabled:opacity-50"
          >
            Load theirs without saving
          </button>
          <button
            disabled={busy}
            onClick={() => act('keep')}
            className="w-full px-3 py-2 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs font-semibold disabled:opacity-50"
          >
            Keep my current configuration
          </button>
        </div>
      </div>
    </div>
  )
}
