import { useEffect, useState } from 'react'
import { RefreshCw, AlertTriangle, CheckCircle2 } from 'lucide-react'
import { useFeedsStore } from '../stores/feedsStore'
import { timeAgo } from '../lib/timeAgo'
import { MIN_FEED_INTERVAL_MINUTES, hasTimestamp, type FeedCategory } from '../lib/feedTypes'

// Settings panel for the threat-intel feeds. The master toggle and categories write the same
// feeds.json the Dashboard ticker's inline toggle does, so the two stay in lockstep through
// the store. Rendered inside the padded Settings content pane (no outer padding here).

const CATEGORY_LABELS: { id: FeedCategory; label: string; hint: string }[] = [
  { id: 'cve', label: 'High-severity CVEs', hint: 'NVD, CVSS ≥ 7.5 — the ticker' },
  { id: 'kev', label: 'CISA KEV', hint: 'Known Exploited Vulnerabilities' },
  { id: 'headline', label: 'Threat intel', hint: 'CISA, CERT/CC & Bishop Fox advisories & research' },
]

export default function FeedsSettings() {
  const available = useFeedsStore((s) => s.available)
  const settings = useFeedsStore((s) => s.settings)
  const sources = useFeedsStore((s) => s.snapshot.sources)
  const saving = useFeedsStore((s) => s.saving)
  const refreshing = useFeedsStore((s) => s.refreshing)
  const ensureLoaded = useFeedsStore((s) => s.ensureLoaded)
  const saveSettings = useFeedsStore((s) => s.saveSettings)
  const refreshNow = useFeedsStore((s) => s.refreshNow)

  const [interval, setIntervalDraft] = useState(settings.intervalMinutes)

  useEffect(() => {
    void ensureLoaded()
  }, [ensureLoaded])
  useEffect(() => {
    setIntervalDraft(settings.intervalMinutes)
  }, [settings.intervalMinutes])

  if (!available) {
    return (
      <div className="max-w-xl">
        <h2 className="text-base font-semibold text-content-primary">Threat-Intelligence Feeds</h2>
        <p className="mt-2 text-sm text-content-muted">
          Feeds are disabled on this instance (started with <code className="font-mono">--no-feeds</code>,
          or <code className="font-mono">~/.joro/feeds.json</code> could not be read).
        </p>
      </div>
    )
  }

  const commitInterval = () => {
    const v = Math.max(MIN_FEED_INTERVAL_MINUTES, Math.floor(interval) || MIN_FEED_INTERVAL_MINUTES)
    setIntervalDraft(v)
    if (v !== settings.intervalMinutes) void saveSettings({ ...settings, intervalMinutes: v })
  }

  return (
    <div className="max-w-xl space-y-6">
      <div>
        <h2 className="text-base font-semibold text-content-primary">Threat-Intelligence Feeds</h2>
        <p className="mt-1 text-sm text-content-secondary">
          Live high-severity CVEs, the CISA KEV catalog, recent public exploits, and curated
          advisories on your dashboard. Content is fetched and sanitized server-side; only validated
          links reach the UI.
        </p>
      </div>

      <label className="flex items-start gap-2 text-sm text-content-primary">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={settings.enabled}
          disabled={saving}
          onChange={(e) => void saveSettings({ ...settings, enabled: e.target.checked })}
        />
        <span>
          Enable threat-intel feeds
          <span className="mt-0.5 block text-xs text-content-muted">
            On by default. Fetches from NVD, CISA, ExploitDB and FIRST.org every{' '}
            {settings.intervalMinutes} minutes — direct from this machine&rsquo;s IP (not through your
            SOCKS proxy unless enabled below).
          </span>
        </span>
      </label>

      <label className="flex items-start gap-2 text-sm text-content-primary">
        <input
          type="checkbox"
          className="mt-0.5"
          checked={settings.routeThroughSocks}
          disabled={saving || !settings.enabled}
          onChange={(e) => void saveSettings({ ...settings, routeThroughSocks: e.target.checked })}
        />
        <span>
          Route feed traffic through the SOCKS proxy
          <span className="mt-0.5 block text-xs text-content-muted">
            Off by default. Only has an effect when a SOCKS proxy is configured in General settings.
          </span>
        </span>
      </label>

      <fieldset disabled={!settings.enabled} className="space-y-2 disabled:opacity-50">
        <legend className="text-xs font-semibold uppercase tracking-wide text-content-secondary">
          Sources
        </legend>
        {CATEGORY_LABELS.map((c) => (
          <label key={c.id} className="flex items-center gap-2 text-sm text-content-primary">
            <input
              type="checkbox"
              checked={!!settings.categories[c.id]}
              onChange={(e) =>
                void saveSettings({
                  ...settings,
                  categories: { ...settings.categories, [c.id]: e.target.checked },
                })
              }
            />
            <span>{c.label}</span>
            <span className="text-xs text-content-muted">· {c.hint}</span>
          </label>
        ))}
      </fieldset>

      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-content-primary">
          Refresh every
          <input
            type="number"
            min={MIN_FEED_INTERVAL_MINUTES}
            value={interval}
            disabled={!settings.enabled || saving}
            onChange={(e) => setIntervalDraft(Number(e.target.value))}
            onBlur={commitInterval}
            className="w-20 rounded border border-border bg-surface-input px-2 py-1 text-sm text-content-primary"
          />
          minutes
        </label>
        <button
          onClick={() => void refreshNow()}
          disabled={!settings.enabled || refreshing}
          className="inline-flex items-center gap-1.5 rounded bg-accent-secondary px-3 py-1 text-sm font-medium text-black hover:bg-accent-secondary-hover disabled:opacity-50"
        >
          <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} aria-hidden="true" />
          Refresh now
        </button>
      </div>
      <p className="-mt-3 text-xs text-content-muted">
        Minimum {MIN_FEED_INTERVAL_MINUTES} minutes — NVD rate-limits unauthenticated clients.
      </p>

      {sources.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-content-secondary">
            Source status
          </h3>
          <ul className="mt-2 divide-y divide-border-subtle rounded border border-border">
            {sources.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                <div className="min-w-0">
                  <span className="text-content-primary">{s.name}</span>
                  {s.lastError && (
                    <span className="block truncate text-xs text-semantic-error" title={s.lastError}>
                      {s.lastError}
                    </span>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-1.5 text-xs">
                  {s.stale ? (
                    <span className="inline-flex items-center gap-1 text-semantic-warning">
                      <AlertTriangle size={12} aria-hidden="true" />
                      stale
                    </span>
                  ) : hasTimestamp(s.lastSuccess) ? (
                    <span className="inline-flex items-center gap-1 text-semantic-success">
                      <CheckCircle2 size={12} aria-hidden="true" />
                      {timeAgo(s.lastSuccess)}
                    </span>
                  ) : (
                    <span className="text-content-muted">not yet fetched</span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
