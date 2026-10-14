import { useEffect, useState, type ReactNode } from 'react'
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
        <Group title="Threat Feeds">
          <p className="text-[11px] text-content-muted leading-relaxed">
            Feeds are disabled on this instance (started with <code className="font-mono">--no-feeds</code>,
            or <code className="font-mono">~/.joro/feeds.json</code> could not be read).
          </p>
        </Group>
      </div>
    )
  }

  const commitInterval = () => {
    const v = Math.max(MIN_FEED_INTERVAL_MINUTES, Math.floor(interval) || MIN_FEED_INTERVAL_MINUTES)
    setIntervalDraft(v)
    if (v !== settings.intervalMinutes) void saveSettings({ ...settings, intervalMinutes: v })
  }

  return (
    <div className="max-w-xl">
      <Group title="Feeds">
        <p className="mb-3 text-[11px] text-content-muted leading-relaxed">
          Live high-severity CVEs, the CISA KEV catalog, recent public exploits, and curated
          advisories on your dashboard. Content is fetched and sanitized server-side; only validated
          links reach the UI.
        </p>

        <label className="flex items-start gap-2 text-xs text-content-secondary">
          <input
            type="checkbox"
            className="mt-0.5 accent-accent-secondary"
            checked={settings.enabled}
            disabled={saving}
            onChange={(e) => void saveSettings({ ...settings, enabled: e.target.checked })}
          />
          <span>
            Enable threat-intel feeds
            <span className="mt-0.5 block text-[11px] text-content-muted leading-relaxed">
              On by default. Fetches from NVD, CISA, ExploitDB and FIRST.org every{' '}
              {settings.intervalMinutes} minutes — direct from this machine&rsquo;s IP (not through your
              SOCKS proxy unless enabled below).
            </span>
          </span>
        </label>

        <label className="mt-2 flex items-start gap-2 text-xs text-content-secondary">
          <input
            type="checkbox"
            className="mt-0.5 accent-accent-secondary"
            checked={settings.routeThroughSocks}
            disabled={saving || !settings.enabled}
            onChange={(e) => void saveSettings({ ...settings, routeThroughSocks: e.target.checked })}
          />
          <span>
            Route feed traffic through the SOCKS proxy
            <span className="mt-0.5 block text-[11px] text-content-muted leading-relaxed">
              Off by default. Only has an effect when a SOCKS proxy is configured in General settings.
            </span>
          </span>
        </label>
      </Group>

      <Group title="Sources">
        <fieldset disabled={!settings.enabled} className="space-y-2 disabled:opacity-50">
          {CATEGORY_LABELS.map((c) => (
            <label key={c.id} className="flex items-center gap-2 text-xs text-content-secondary">
              <input
                type="checkbox"
                className="accent-accent-secondary"
                checked={!!settings.categories[c.id]}
                onChange={(e) =>
                  void saveSettings({
                    ...settings,
                    categories: { ...settings.categories, [c.id]: e.target.checked },
                  })
                }
              />
              <span>{c.label}</span>
              <span className="text-[11px] text-content-muted">· {c.hint}</span>
            </label>
          ))}
        </fieldset>
      </Group>

      <Group title="Refresh">
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-content-secondary">
            Refresh every
            <input
              type="number"
              min={MIN_FEED_INTERVAL_MINUTES}
              value={interval}
              disabled={!settings.enabled || saving}
              onChange={(e) => setIntervalDraft(Number(e.target.value))}
              onBlur={commitInterval}
              className="w-20 rounded border border-border bg-surface-input px-2 py-1 text-xs text-content-primary"
            />
            minutes
          </label>
          <button
            onClick={() => void refreshNow()}
            disabled={!settings.enabled || refreshing}
            className="inline-flex items-center gap-1.5 rounded bg-accent-secondary px-3 py-1 text-[11px] font-semibold text-black hover:bg-accent-secondary-hover disabled:opacity-50"
          >
            <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} aria-hidden="true" />
            Refresh now
          </button>
        </div>
        <p className="mt-2 text-[11px] text-content-muted leading-relaxed">
          Minimum {MIN_FEED_INTERVAL_MINUTES} minutes — NVD rate-limits unauthenticated clients.
        </p>
      </Group>

      {sources.length > 0 && (
        <Group title="Source status">
          <ul className="divide-y divide-border-subtle rounded border border-border">
            {sources.map((s) => (
              <li key={s.id} className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
                <div className="min-w-0">
                  <span className="text-content-primary">{s.name}</span>
                  {s.lastError && (
                    <span className="block truncate text-[11px] text-semantic-error" title={s.lastError}>
                      {s.lastError}
                    </span>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-1.5 text-[11px]">
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
        </Group>
      )}
    </div>
  )
}

// Group mirrors the titled sub-section used by the General/Appearance/Testing Browser
// Settings sections (see Settings.tsx) so this panel shares their type scale and rhythm.
function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="py-5 first:pt-0 last:pb-0">
      <div className="flex items-center gap-2 mb-2">
        <span className="w-1 h-3 rounded-full bg-accent-secondary shrink-0" />
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-muted">{title}</h3>
      </div>
      {children}
    </section>
  )
}
