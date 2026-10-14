import { ExternalLink } from 'lucide-react'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import { useFeedsStore } from '../../stores/feedsStore'
import { timeAgo } from '../../lib/timeAgo'
import { useEnsureFeeds, FeedsOffBody, FeedLoadingBody, categoryState } from './feedsShared'
import { hasTimestamp, type FeedItem } from '../../lib/feedTypes'

// Curated security-advisory headlines (title + source + link only; all feed HTML is stripped
// server-side) from CISA, CERT/CC, and Bishop Fox. A headline with no validated link renders
// as plain text. Push-driven.

export default function ThreatHeadlinesWidget() {
  useEnsureFeeds()
  const available = useFeedsStore((s) => s.available)
  const enabled = useFeedsStore((s) => s.settings.enabled)
  const items = useFeedsStore((s) => s.snapshot.items.headline)
  const sources = useFeedsStore((s) => s.snapshot.sources)

  const state = categoryState(sources, 'headline', items.length)

  return (
    <DashboardPanel title="Threat Intel" count={enabled ? items.length : 0}>
      {!available ? (
        <EmptyPanelBody>Feeds are unavailable on this instance</EmptyPanelBody>
      ) : !enabled ? (
        <FeedsOffBody />
      ) : state === 'loading' ? (
        <FeedLoadingBody />
      ) : state === 'stale' ? (
        <EmptyPanelBody>Threat-intel feeds unavailable — showing nothing new</EmptyPanelBody>
      ) : state === 'empty' ? (
        <EmptyPanelBody>No advisories loaded yet</EmptyPanelBody>
      ) : (
        <ul className="divide-y divide-border-subtle">
          {items.map((item) => (
            <HeadlineRow key={item.id} item={item} />
          ))}
        </ul>
      )}
    </DashboardPanel>
  )
}

function HeadlineRow({ item }: { item: FeedItem }) {
  return (
    <li className="px-3 py-2 hover:bg-surface-hover">
      {item.url ? (
        <a
          href={item.url}
          target="_blank"
          rel="noopener noreferrer"
          className="group flex items-start gap-1 text-xs text-content-primary hover:text-accent-secondary"
        >
          <span className="min-w-0 flex-1">{item.title}</span>
          <ExternalLink
            size={11}
            aria-hidden="true"
            className="mt-0.5 shrink-0 text-content-muted group-hover:text-accent-secondary"
          />
        </a>
      ) : (
        <span className="block text-xs text-content-primary">{item.title}</span>
      )}
      <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-content-muted">
        <span className="uppercase tracking-wide">{item.source}</span>
        {hasTimestamp(item.published) && (
          <>
            <span aria-hidden="true">·</span>
            <span>{timeAgo(item.published)}</span>
          </>
        )}
      </div>
    </li>
  )
}
