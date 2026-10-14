import { useEffect } from 'react'
import { useFeedsStore } from '../../stores/feedsStore'
import { hasTimestamp, type FeedCategory, type FeedSourceStatus } from '../../lib/feedTypes'

// Shared bits for the feed widgets: a one-time load trigger (feeds are push-driven, so this
// seeds the store without polling) and the "feeds are off" body with an inline enable button,
// so a feed widget on the dashboard is itself a way to turn the feature on.

// categoryState distinguishes a feed that is still initializing from one that is genuinely
// empty or failing, so a panel shows a loading placeholder only before its first fetch lands.
//   loading — no items yet, no source for this category has succeeded, and none is stale.
//   stale   — no items yet and a source for this category has errored.
//   empty   — a source succeeded but returned nothing (rare for these feeds).
//   ready   — at least one item.
export type FeedPanelState = 'loading' | 'stale' | 'empty' | 'ready'

export function categoryState(
  sources: FeedSourceStatus[],
  cat: FeedCategory,
  count: number
): FeedPanelState {
  if (count > 0) return 'ready'
  const cs = sources.filter((s) => s.category === cat)
  if (cs.some((s) => s.stale)) return 'stale'
  if (cs.length === 0 || cs.every((s) => !hasTimestamp(s.lastSuccess))) return 'loading'
  return 'empty'
}

export function useEnsureFeeds() {
  const ensureLoaded = useFeedsStore((s) => s.ensureLoaded)
  useEffect(() => {
    void ensureLoaded()
  }, [ensureLoaded])
}

export function FeedsOffBody() {
  const saving = useFeedsStore((s) => s.saving)
  const setEnabled = useFeedsStore((s) => s.setEnabled)
  return (
    <div className="flex h-full flex-col items-center justify-center gap-1.5 px-3 text-center">
      <span className="text-xs text-content-muted">Threat feeds are off</span>
      <button
        onClick={() => void setEnabled(true)}
        disabled={saving}
        className="text-xs font-medium text-accent-secondary hover:text-accent-secondary-hover disabled:opacity-50"
      >
        Enable feeds
      </button>
    </div>
  )
}

// FeedLoadingBody is the "the feed is initializing" placeholder: a few pulsing skeleton rows
// under a pulsing caption. No fabricated content — just shimmer to show the feed is loading.
export function FeedLoadingBody() {
  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 divide-y divide-border-subtle">
        {[0, 1, 2, 3, 4].map((i) => (
          <div key={i} className="animate-pulse px-3 py-2" style={{ animationDelay: `${i * 120}ms` }}>
            <div className="h-3 w-2/3 rounded bg-surface-hover" />
            <div className="mt-1.5 h-2 w-1/3 rounded bg-surface-hover" />
          </div>
        ))}
      </div>
      <div className="shrink-0 animate-pulse py-2 text-center text-xs text-content-muted">
        Loading feed…
      </div>
    </div>
  )
}
