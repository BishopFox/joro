import { useMemo } from 'react'
import { AlertTriangle, Pencil, Unlock } from 'lucide-react'
import type { AutomationProfile, Capability } from '../lib/api'

type Props = {
  capabilities: Capability[]
  selected: string[]
  onChange: (next: string[]) => void
  /** Capability IDs that exist but this token has never been offered, marked so an
   *  operator reviewing an old token can see what is new. */
  highlight?: string[]
  /** Curated grant bundles from the server. Applying one expands it into a concrete
   *  grant list here; the profile itself is never stored on the token. */
  profiles?: AutomationProfile[]
  /** The server's class order, so write-heavy groups render last. Falls back to the
   *  order capabilities arrive in, which is alphabetical by ID. */
  classOrder?: string[]
  /** Called when a profile is applied, so the containing form can also adopt its
   *  recommended requireScope and limits. */
  onApplyProfile?: (profile: AutomationProfile) => void
}

const CLASS_LABELS: Record<string, string> = {
  history: 'History',
  sitemap: 'Site map',
  scope: 'Scope',
  findings: 'Detection findings',
  notes: 'Notes',
  http: 'HTTP tools',
  config: 'Proxy configuration',
  detect: 'Detection rules & scanning',
}

/**
 * The grant picker.
 *
 * Class checkboxes and profile buttons are a convenience that check boxes; they never
 * store a pattern or a reference. Grants are always a fully expanded list of
 * capability IDs, so upgrading Joro can never widen an existing token — a "http.*"
 * grant written today would silently pick up a send-capable capability shipped later,
 * and the same is true of a stored profile name.
 *
 * Nothing is selected by default.
 */
export default function GrantPicker({
  capabilities,
  selected,
  onChange,
  highlight = [],
  profiles = [],
  classOrder = [],
  onApplyProfile,
}: Props) {
  const byClass = useMemo(() => {
    const groups = new Map<string, Capability[]>()
    for (const c of capabilities) {
      const list = groups.get(c.class) ?? []
      list.push(c)
      groups.set(c.class, list)
    }
    const entries = [...groups.entries()]
    if (classOrder.length === 0) return entries
    // Unknown classes sort after known ones rather than disappearing, so a build
    // that ships a class the server did not list still renders it.
    const rank = (cls: string) => {
      const i = classOrder.indexOf(cls)
      return i === -1 ? classOrder.length : i
    }
    return entries.sort((a, b) => rank(a[0]) - rank(b[0]))
  }, [capabilities, classOrder])

  const sel = new Set(selected)
  const isNew = new Set(highlight)

  const toggle = (id: string) => {
    const next = new Set(sel)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    onChange([...next].sort())
  }

  const toggleClass = (caps: Capability[], on: boolean) => {
    const next = new Set(sel)
    for (const c of caps) {
      if (on) next.add(c.id)
      else next.delete(c.id)
    }
    onChange([...next].sort())
  }

  const preset = (fn: (c: Capability) => boolean) =>
    onChange(capabilities.filter(fn).map((c) => c.id).sort())

  const applyProfile = (p: AutomationProfile) => {
    // Expand to a concrete list. Intersected with what this build actually
    // registers, so a profile naming something unknown selects nothing rather than
    // putting an unknown ID in the grant list.
    const known = new Set(capabilities.map((c) => c.id))
    onChange(p.grants.filter((id) => known.has(id)).sort())
    onApplyProfile?.(p)
  }

  return (
    <div className="space-y-3">
      {profiles.length > 0 && (
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] text-content-muted">Profiles:</span>
            {profiles.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => applyProfile(p)}
                title={`${p.description} (${p.grants.length} capabilities)`}
                className="px-2 py-0.5 text-[11px] rounded border border-border bg-surface-input hover:bg-surface-hover"
              >
                {p.title}
                {p.allowsSends && (
                  <AlertTriangle
                    size={10}
                    strokeWidth={2}
                    className="inline ml-1 -mt-0.5 text-semantic-warning"
                    aria-hidden="true"
                  />
                )}
              </button>
            ))}
          </div>
          <p className="text-[10px] text-content-muted leading-snug">
            A profile fills in a grant list you can then edit. It is not remembered on the token, so a
            capability added to a profile in a later release is never granted retroactively.
          </p>
        </div>
      )}

      <div className="flex items-center gap-2 text-[11px]">
        <span className="text-content-muted">Presets:</span>
        <button
          type="button"
          onClick={() => preset((c) => !c.mutating && !c.sendsTraffic)}
          className="text-accent-secondary hover:underline"
        >
          Read-only
        </button>
        <button
          type="button"
          onClick={() => preset(() => true)}
          className="text-accent-secondary hover:underline"
        >
          Everything
        </button>
        <button type="button" onClick={() => onChange([])} className="text-content-muted hover:underline">
          Clear
        </button>
        <span className="ml-auto text-content-muted">{sel.size} selected</span>
      </div>

      <div className="max-h-72 overflow-y-auto border border-border rounded divide-y divide-border-subtle">
        {byClass.map(([cls, caps]) => {
          const all = caps.every((c) => sel.has(c.id))
          const some = !all && caps.some((c) => sel.has(c.id))
          const sends = caps.some((c) => c.sendsTraffic)
          const writes = !sends && caps.some((c) => c.mutating)
          return (
            <div key={cls} className="p-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={all}
                  ref={(el) => {
                    if (el) el.indeterminate = some
                  }}
                  onChange={() => toggleClass(caps, !all)}
                />
                <span className="text-xs font-semibold">{CLASS_LABELS[cls] ?? cls}</span>
                {sends && (
                  <span className="text-[10px] text-semantic-warning inline-flex items-center gap-1">
                    <AlertTriangle size={11} strokeWidth={2} aria-hidden="true" />
                    these emit traffic to targets
                  </span>
                )}
                {writes && (
                  <span className="text-[10px] text-semantic-special inline-flex items-center gap-1">
                    <Pencil size={11} strokeWidth={2} aria-hidden="true" />
                    some of these change your proxy
                  </span>
                )}
              </label>

              <div className="mt-1 ml-5 space-y-1">
                {caps.map((c) => (
                  <label key={c.id} className="flex items-start gap-2 cursor-pointer group">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={sel.has(c.id)}
                      onChange={() => toggle(c.id)}
                    />
                    <span className="min-w-0">
                      <span className="text-xs flex items-center gap-1.5">
                        <code className="font-mono text-[11px]">{c.toolName}</code>
                        {c.sendsTraffic && (
                          <AlertTriangle size={11} strokeWidth={2} className="text-semantic-warning shrink-0" aria-hidden="true" />
                        )}
                        {c.mutating && !c.sendsTraffic && (
                          <span className="shrink-0 inline-flex" title="Changes Joro’s own configuration">
                            <Pencil size={11} strokeWidth={2} className="text-semantic-special" aria-hidden="true" />
                          </span>
                        )}
                        {c.unrestrictedOnly && (
                          <span
                            className="shrink-0 inline-flex"
                            title="Refused unless this token has scope enforcement off and no host whitelist"
                          >
                            <Unlock size={11} strokeWidth={2} className="text-semantic-error" aria-hidden="true" />
                          </span>
                        )}
                        {isNew.has(c.id) && <span className="w-1.5 h-1.5 rounded-full bg-accent shrink-0" title="New since this token was last reviewed" />}
                      </span>
                      <span className="block text-[10px] text-content-muted leading-snug">{c.title}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
