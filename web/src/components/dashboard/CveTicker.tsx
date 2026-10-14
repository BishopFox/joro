import { useEffect, useMemo } from 'react'
import { Link } from 'react-router'
import { Radio, AlertTriangle, Settings as SettingsIcon } from 'lucide-react'
import { useFeedsStore } from '../../stores/feedsStore'
import { EpssBadge } from './feedBadges'
import { categoryState } from './feedsShared'
import type { FeedItem } from '../../lib/feedTypes'

// The CVE "stock ticker": a thin, full-width marquee of the latest high-severity CVEs,
// docked under the global header on the Dashboard page (not a layout slot). Every field is
// server-sanitized, so values render as text nodes and the only link is the derived,
// validated NVD URL.
//
// It doubles as the feature's inline control: when feeds are off it collapses to a slim
// "Enable" prompt, satisfying the "toggleable on the Dashboard itself" requirement.

export default function CveTicker() {
  const available = useFeedsStore((s) => s.available)
  const enabled = useFeedsStore((s) => s.settings.enabled)
  const saving = useFeedsStore((s) => s.saving)
  const items = useFeedsStore((s) => s.snapshot.items.cve)
  const sources = useFeedsStore((s) => s.snapshot.sources)
  const ensureLoaded = useFeedsStore((s) => s.ensureLoaded)
  const setEnabled = useFeedsStore((s) => s.setEnabled)

  useEffect(() => {
    void ensureLoaded()
  }, [ensureLoaded])

  const cveStale = useMemo(
    () => sources.some((s) => s.category === 'cve' && s.stale),
    [sources]
  )
  const state = categoryState(sources, 'cve', items.length)

  // A slower scroll for a short list; roughly 3.5s of travel per item, floored.
  const duration = Math.max(24, items.length * 3.5)

  if (!available) return null

  const barBase =
    'shrink-0 flex items-center gap-2 h-9 px-3 bg-surface-card border-b border-border text-xs select-none'

  if (!enabled) {
    return (
      <div className={barBase}>
        <Radio size={13} className="text-content-muted" aria-hidden="true" />
        <span className="text-content-secondary">
          Threat-intel feeds are off.
        </span>
        <button
          onClick={() => void setEnabled(true)}
          disabled={saving}
          className="text-accent-secondary hover:text-accent-secondary-hover font-medium disabled:opacity-50"
        >
          Enable live CVE, KEV &amp; advisory feeds
        </button>
        <Link
          to="/settings"
          state={{ category: 'feeds' }}
          className="ml-auto text-content-muted hover:text-accent-secondary"
          title="Threat feed settings"
        >
          <SettingsIcon size={13} />
        </Link>
      </div>
    )
  }

  return (
    <div className={`joro-ticker ${barBase}`}>
      <span className="shrink-0 inline-flex items-center gap-1.5 pr-2 border-r border-border-subtle">
        <Radio size={13} className="text-accent animate-pulse" aria-hidden="true" />
        <span className="font-semibold uppercase tracking-wide text-[10px] text-content-secondary">
          Live CVEs
        </span>
      </span>

      {state === 'loading' ? (
        <LoadingMarquee />
      ) : state === 'stale' ? (
        <span className="text-content-muted">CVE feed unavailable — showing nothing new</span>
      ) : state === 'empty' ? (
        <span className="text-content-muted">No high-severity CVEs in the last day</span>
      ) : (
        <div className="joro-ticker-viewport flex-1 overflow-hidden">
          <div className="joro-ticker-track" style={{ animationDuration: `${duration}s` }}>
            <TickerRun items={items} />
            {/* A second copy makes the -50% keyframe loop seamlessly. */}
            <TickerRun items={items} ariaHidden />
          </div>
        </div>
      )}

      {cveStale && items.length > 0 && (
        <span
          title="The CVE feed's last refresh failed; showing the last-known set"
          className="shrink-0 inline-flex items-center gap-1 text-semantic-warning"
        >
          <AlertTriangle size={12} aria-hidden="true" />
          <span className="text-[10px]">stale</span>
        </span>
      )}

      <Link
        to="/settings"
        state={{ category: 'feeds' }}
        className="shrink-0 text-content-muted hover:text-accent-secondary"
        title="Threat feed settings"
      >
        <SettingsIcon size={13} />
      </Link>
    </div>
  )
}

// While the CVE feed initializes, scroll a repeating, pulsing "LOADING CVES" marquee. The
// pulse lives on the inner text spans so it does not fight the track's scroll animation.
function LoadingMarquee() {
  return (
    <div className="joro-ticker-viewport flex-1 overflow-hidden">
      <div className="joro-ticker-track" style={{ animationDuration: '24s' }}>
        <LoadingRun />
        <LoadingRun ariaHidden />
      </div>
    </div>
  )
}

function LoadingRun({ ariaHidden }: { ariaHidden?: boolean }) {
  return (
    <span className="inline-flex animate-pulse items-center" aria-hidden={ariaHidden}>
      {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => (
        <span key={i} className="inline-flex items-center">
          <span className="font-mono tracking-[0.3em] text-content-muted">LOADING CVES</span>
          <span className="mx-3 text-border" aria-hidden="true">
            •
          </span>
        </span>
      ))}
    </span>
  )
}

function TickerRun({ items, ariaHidden }: { items: FeedItem[]; ariaHidden?: boolean }) {
  return (
    <span className="inline-flex items-center" aria-hidden={ariaHidden}>
      {items.map((item, i) => (
        <span key={`${item.id}-${i}`} className="inline-flex items-center">
          <TickerCell item={item} />
          <span className="mx-3 text-border" aria-hidden="true">
            •
          </span>
        </span>
      ))}
    </span>
  )
}

function TickerCell({ item }: { item: FeedItem }) {
  const sevClass =
    item.severity === 'CRITICAL' ? 'text-semantic-error' : 'text-semantic-warning'
  const body = (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span className="font-mono text-content-primary">{item.id}</span>
      {item.vendor && <span className="text-content-secondary capitalize">{item.vendor}</span>}
      {typeof item.score === 'number' && item.score > 0 && (
        <span className={`font-semibold ${sevClass}`}>{item.score.toFixed(1)}</span>
      )}
      <EpssBadge epss={item.epss} />
      {item.alsoInKEV && (
        <span
          title="In the CISA KEV catalog (actively exploited)"
          className="text-[9px] font-bold uppercase tracking-wide text-semantic-error"
        >
          KEV
        </span>
      )}
    </span>
  )
  if (!item.url) return body
  return (
    <a
      href={item.url}
      target="_blank"
      rel="noopener noreferrer"
      title={item.title || item.id}
      className="hover:underline"
    >
      {body}
    </a>
  )
}
