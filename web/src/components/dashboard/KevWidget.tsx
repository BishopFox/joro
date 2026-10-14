import { Flame, ExternalLink } from 'lucide-react'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import { useFeedsStore } from '../../stores/feedsStore'
import { timeAgo } from '../../lib/timeAgo'
import { useEnsureFeeds, FeedsOffBody, FeedLoadingBody, categoryState } from './feedsShared'
import { EpssBadge } from './feedBadges'
import { hasTimestamp, type FeedItem } from '../../lib/feedTypes'

// CISA Known Exploited Vulnerabilities — what is being exploited in the wild right now. The
// most actionable feed for a red-teamer. Push-driven via ws (feeds.updated); seeds once.

export default function KevWidget() {
  useEnsureFeeds()
  const available = useFeedsStore((s) => s.available)
  const enabled = useFeedsStore((s) => s.settings.enabled)
  const items = useFeedsStore((s) => s.snapshot.items.kev)
  const sources = useFeedsStore((s) => s.snapshot.sources)

  const state = categoryState(sources, 'kev', items.length)

  return (
    <DashboardPanel title="CISA KEV" count={enabled ? items.length : 0}>
      {!available ? (
        <EmptyPanelBody>Feeds are unavailable on this instance</EmptyPanelBody>
      ) : !enabled ? (
        <FeedsOffBody />
      ) : state === 'loading' ? (
        <FeedLoadingBody />
      ) : state === 'stale' ? (
        <EmptyPanelBody>KEV feed unavailable — showing nothing new</EmptyPanelBody>
      ) : state === 'empty' ? (
        <EmptyPanelBody>No known-exploited vulnerabilities loaded yet</EmptyPanelBody>
      ) : (
        <ul className="divide-y divide-border-subtle">
          {items.map((item) => (
            <KevRow key={item.id} item={item} />
          ))}
        </ul>
      )}
    </DashboardPanel>
  )
}

function KevRow({ item }: { item: FeedItem }) {
  const vendorProduct = [item.vendor, item.product].filter(Boolean).join(' · ')
  return (
    <li className="px-3 py-2 hover:bg-surface-hover">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            {vendorProduct && (
              <span className="truncate text-xs font-semibold capitalize text-content-primary">
                {vendorProduct}
              </span>
            )}
            {item.ransomware && (
              <span
                title="Known ransomware-campaign use"
                className="inline-flex shrink-0 items-center gap-0.5 rounded bg-semantic-error-bg px-1 py-0.5 text-[9px] font-bold uppercase text-semantic-error"
              >
                <Flame size={9} aria-hidden="true" />
                Ransomware
              </span>
            )}
          </div>
          {item.title && (
            <div className="truncate text-xs text-content-secondary">{item.title}</div>
          )}
          <div className="mt-0.5 flex items-center gap-1.5">
            {item.url ? (
              <a
                href={item.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-0.5 font-mono text-[11px] text-accent-secondary hover:underline"
              >
                {item.id}
                <ExternalLink size={9} aria-hidden="true" />
              </a>
            ) : (
              <span className="font-mono text-[11px] text-content-muted">{item.id}</span>
            )}
            <EpssBadge epss={item.epss} />
          </div>
        </div>
        {hasTimestamp(item.published) && (
          <span className="shrink-0 whitespace-nowrap text-[10px] text-content-muted">
            {timeAgo(item.published)}
          </span>
        )}
      </div>
    </li>
  )
}
