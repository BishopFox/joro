import { useEffect, useState } from 'react'
import { Plus, Trash2, ChevronUp, ChevronDown, ShieldOff } from 'lucide-react'
import type { SJAuthScheme } from '../../lib/sjTypes'
import type { SJProfile } from '../../stores/sjStore'

let profileSeq = 0
/** A counter, not a timestamp: two profiles added inside the same millisecond
 *  collided, and matrix columns are keyed by profile id, so React dropped one. */
export function nextProfileID(): string {
  profileSeq += 1
  return `p${profileSeq}`
}

export function makeProfile(index: number): SJProfile {
  return {
    id: nextProfileID(),
    label: index === 0 ? 'unauthenticated' : `profile ${index + 1}`,
    rank: index,
    enabled: true,
    credentials: [],
    headers: [],
  }
}

/** The auth profile manager.
 *
 *  Its own modal rather than a block inside the Auth Matrix: a single send from
 *  Operations and a bulk Automate run both authenticate too, so burying the
 *  editor in the one view that happens to need several of them put it out of
 *  reach of the two that need one. */
export default function SJProfilesModal({
  profiles,
  schemes,
  onChange,
  onClose,
}: {
  profiles: SJProfile[]
  schemes: SJAuthScheme[]
  onChange: (next: SJProfile[]) => void
  onClose: () => void
}) {
  const [editing, setEditing] = useState<string | null>(profiles.length === 1 ? profiles[0].id : null)

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onClose])

  function add() {
    const p = makeProfile(profiles.length)
    onChange([...profiles, p])
    setEditing(p.id)
  }

  function move(idx: number, delta: number) {
    const next = profiles.slice()
    const j = idx + delta
    if (j < 0 || j >= next.length) return
    ;[next[idx], next[j]] = [next[j], next[idx]]
    onChange(next.map((p, i) => ({ ...p, rank: i })))
  }

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-6"
      onMouseDown={onClose}
    >
      <div
        className="flex flex-col w-full max-w-2xl max-h-[85vh] bg-surface-card border border-border rounded shadow-lg overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="shrink-0 flex items-center gap-2 px-4 py-3 border-b border-border">
          <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
            Auth profiles
          </span>
          <span className="text-[10px] text-content-muted">ordered least to most privileged</span>
          <button
            onClick={add}
            className="ml-auto flex items-center gap-1 px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
          >
            <Plus size={13} /> Add profile
          </button>
        </div>

        <div className="flex-1 min-h-0 overflow-auto p-3 space-y-2">
          {profiles.length === 0 && (
            <div className="flex flex-col items-center gap-2 py-10 text-center">
              <ShieldOff size={22} className="text-content-muted" strokeWidth={1.5} />
              <div className="text-xs text-content-secondary">No auth profiles yet</div>
              <div className="text-[11px] text-content-muted max-w-md">
                A profile is one authentication state. Define one for each level of access you
                hold - plus one with no credentials - and the Auth Matrix will run every
                operation under each and tell you where a lower privilege reaches what a
                higher one does.
              </div>
              <div className="text-[11px] text-content-muted max-w-md">
                Credentials stay in memory for this session. They are never written to the
                project file and never returned by the API.
              </div>
              <button
                onClick={add}
                className="mt-1 flex items-center gap-1 px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
              >
                <Plus size={13} /> Add a profile
              </button>
            </div>
          )}

          {profiles.map((p, i) => (
            <div key={p.id} className="border border-border rounded-sm">
              <div className="flex items-center gap-2 px-2 py-1.5 text-xs">
                <span className="text-content-muted w-4 tabular-nums">{i}</span>
                <input
                  value={p.label}
                  onChange={(e) => {
                    const next = profiles.slice()
                    next[i] = { ...p, label: e.target.value }
                    onChange(next)
                  }}
                  className="bg-surface-input border border-border rounded-sm px-2 py-1 w-44"
                />
                <span className="text-[10px] text-content-muted">
                  {(p.credentials?.length ?? 0) > 0
                    ? `${p.credentials!.length} credential${p.credentials!.length === 1 ? '' : 's'}`
                    : 'no credentials'}
                  {(p.headers?.length ?? 0) > 0 ? ` · ${p.headers!.length} header` : ''}
                </span>
                <div className="ml-auto flex items-center gap-0.5">
                  <button
                    onClick={() => move(i, -1)}
                    className="text-content-muted hover:text-content-primary disabled:opacity-30"
                    disabled={i === 0}
                    title="Less privileged"
                  >
                    <ChevronUp size={13} />
                  </button>
                  <button
                    onClick={() => move(i, 1)}
                    className="text-content-muted hover:text-content-primary disabled:opacity-30"
                    disabled={i === profiles.length - 1}
                    title="More privileged"
                  >
                    <ChevronDown size={13} />
                  </button>
                  <button
                    onClick={() => setEditing(editing === p.id ? null : p.id)}
                    className="px-2 text-xs text-accent-secondary hover:underline"
                  >
                    {editing === p.id ? 'Done' : 'Edit'}
                  </button>
                  <button
                    onClick={() => onChange(profiles.filter((x) => x.id !== p.id))}
                    className="text-content-muted hover:text-semantic-error"
                    title="Delete"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>

              {editing === p.id && (
                <ProfileEditor
                  profile={p}
                  schemes={schemes}
                  onChange={(next) => {
                    const list = profiles.slice()
                    list[i] = next
                    onChange(list)
                  }}
                />
              )}
            </div>
          ))}
        </div>

        <div className="shrink-0 flex items-center px-4 py-2 border-t border-border">
          <span className="text-[10px] text-content-muted">
            Credentials are session-only and never reach the project file.
          </span>
          <button
            onClick={onClose}
            className="ml-auto px-3 py-1.5 rounded-sm text-xs bg-surface-input hover:bg-surface-hover text-content-secondary"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}

function ProfileEditor({
  profile,
  schemes,
  onChange,
}: {
  profile: SJProfile
  schemes: SJAuthScheme[]
  onChange: (next: SJProfile) => void
}) {
  // Secret inputs carry joro-redact-field rather than a substituted value: the
  // real string has to stay in the DOM or the next keystroke corrupts it, so
  // streamer mode paints over it instead. redact.ts states the rule.
  function setCred(schemeName: string, patch: Record<string, string>) {
    const creds = (profile.credentials ?? []).slice()
    const idx = creds.findIndex((c) => c.scheme === schemeName)
    const scheme = schemes.find((s) => s.name === schemeName)
    if (!scheme) return
    const base = { scheme: schemeName, kind: scheme.kind, in: scheme.in, name: scheme.paramName }
    if (idx >= 0) creds[idx] = { ...creds[idx], ...patch }
    else creds.push({ ...base, ...patch })
    onChange({ ...profile, credentials: creds })
  }

  const cred = (name: string) => (profile.credentials ?? []).find((c) => c.scheme === name)

  return (
    <div className="border-t border-border bg-surface-input/40 p-2 space-y-2 text-[11px]">
      {schemes.length === 0 && (
        <div className="text-content-muted">
          This document declares no security schemes. Use the extra headers below.
        </div>
      )}
      {schemes.map((s) => (
        <div key={s.name} className="space-y-1">
          <div className="text-content-secondary">
            {s.name}
            <span className="text-content-muted ml-1.5">
              {s.kind}
              {s.in ? ` · ${s.in} · ${s.paramName}` : ''}
              {!s.automatable ? ' · paste a token; Joro cannot obtain one' : ''}
            </span>
          </div>
          {s.kind === 'basic' ? (
            <div className="flex gap-1.5">
              <input
                placeholder="username"
                value={cred(s.name)?.username ?? ''}
                onChange={(e) => setCred(s.name, { username: e.target.value })}
                className="flex-1 bg-surface-body border border-border rounded-sm px-2 py-1"
              />
              <input
                type="password"
                placeholder="password"
                value={cred(s.name)?.password ?? ''}
                onChange={(e) => setCred(s.name, { password: e.target.value })}
                className="flex-1 bg-surface-body border border-border rounded-sm px-2 py-1 joro-redact-field"
              />
            </div>
          ) : (
            <input
              type="password"
              placeholder={s.kind === 'bearer' ? 'token' : 'value'}
              value={cred(s.name)?.value ?? ''}
              onChange={(e) => setCred(s.name, { value: e.target.value })}
              className="w-full bg-surface-body border border-border rounded-sm px-2 py-1 joro-redact-field"
            />
          )}
        </div>
      ))}

      <div className="pt-1.5 border-t border-border">
        <div className="text-content-secondary mb-1">Extra headers</div>
        {(profile.headers ?? []).map((h, i) => (
          <div key={i} className="flex gap-1.5 mb-1">
            <input
              value={h.name}
              placeholder="Name"
              onChange={(e) => {
                const next = (profile.headers ?? []).slice()
                next[i] = { ...h, name: e.target.value }
                onChange({ ...profile, headers: next })
              }}
              className="w-40 bg-surface-body border border-border rounded-sm px-2 py-1"
            />
            <input
              value={h.value}
              placeholder="Value"
              onChange={(e) => {
                const next = (profile.headers ?? []).slice()
                next[i] = { ...h, value: e.target.value }
                onChange({ ...profile, headers: next })
              }}
              className="flex-1 bg-surface-body border border-border rounded-sm px-2 py-1 joro-redact-field"
            />
            <button
              onClick={() => onChange({ ...profile, headers: (profile.headers ?? []).filter((_, j) => j !== i) })}
              className="text-content-muted hover:text-semantic-error"
            >
              <Trash2 size={12} />
            </button>
          </div>
        ))}
        <button
          onClick={() => onChange({ ...profile, headers: [...(profile.headers ?? []), { name: '', value: '' }] })}
          className="text-accent-secondary hover:underline"
        >
          + header
        </button>
      </div>
    </div>
  )
}
