// Threat-intel feed vocabulary and display types. Mirrors internal/feeds' model: every
// field is already sanitized server-side (bounded plain text, enum severity, derived/validated
// https URL or empty), so the UI renders strings as React text nodes and links as validated
// https anchors — never dangerouslySetInnerHTML.

export type FeedCategory = 'cve' | 'kev' | 'headline'

export interface FeedItem {
  category: FeedCategory
  id: string
  title: string
  summary?: string
  vendor?: string
  product?: string
  /** 'HIGH' | 'CRITICAL' only; may be absent. */
  severity?: string
  /** CVSS base score, 0–10. */
  score?: number
  /** EPSS probability of exploitation in the next 30 days, 0–1. */
  epss?: number
  ransomware?: boolean
  alsoInKEV?: boolean
  /** Validated https URL, or '' (render the title as plain text, no link). */
  url?: string
  source: string
  published: string
}

export interface FeedSourceStatus {
  id: string
  name: string
  category: FeedCategory
  lastAttempt?: string
  lastSuccess?: string
  lastError?: string
  itemCount: number
  stale: boolean
}

export interface FeedSnapshot {
  // The server always sends all three keys (possibly empty arrays).
  items: Record<FeedCategory, FeedItem[]>
  sources: FeedSourceStatus[]
  generatedAt?: string
}

export interface FeedSettings {
  enabled: boolean
  categories: Record<FeedCategory, boolean>
  intervalMinutes: number
  /** Route feed egress through the operator's SOCKS proxy (default false = direct). */
  routeThroughSocks: boolean
}

export interface FeedsResponse {
  settings: FeedSettings
  snapshot: FeedSnapshot
}

// The droppable hint pushed on ws `feeds.updated`; the client re-GETs the snapshot.
export interface FeedsUpdatedSummary {
  generatedAt: string
  counts: Record<string, number>
  anyStale: boolean
}

export const EMPTY_FEED_SNAPSHOT: FeedSnapshot = {
  items: { cve: [], kev: [], headline: [] },
  sources: [],
}

export const DEFAULT_FEED_SETTINGS: FeedSettings = {
  enabled: true,
  categories: { cve: true, kev: true, headline: true },
  intervalMinutes: 15,
  routeThroughSocks: false,
}

export const MIN_FEED_INTERVAL_MINUTES = 15

// A never-set Go time.Time serializes as the year-1 sentinel; treat it (and absence) as "no
// timestamp" so a widget does not render it as "millennia ago".
export function hasTimestamp(ts?: string): ts is string {
  return !!ts && !ts.startsWith('0001-01-01')
}
