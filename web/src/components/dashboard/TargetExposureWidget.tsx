import { useEffect, useMemo } from 'react'
import { ShieldAlert, ExternalLink } from 'lucide-react'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import { useFeedsStore } from '../../stores/feedsStore'
import { useTechStore } from '../../stores/techStore'
import { correlateExposure, type ExposureMatch } from '../../lib/feedCorrelate'
import { useEnsureFeeds, FeedsOffBody } from './feedsShared'
import { EpssBadge } from './feedBadges'

// Target Exposure: the engagement-specific panel. It cross-references the technologies Joro
// fingerprinted on in-scope hosts against the CVE + KEV feeds, surfacing "this target runs
// something under active exploitation". Pure client-side join (feedsStore × techStore); both
// are push-driven, so this widget only triggers their one-time loads.

const MAX_ROWS = 60

export default function TargetExposureWidget() {
  useEnsureFeeds()
  const available = useFeedsStore((s) => s.available)
  const enabled = useFeedsStore((s) => s.settings.enabled)
  const cve = useFeedsStore((s) => s.snapshot.items.cve)
  const kev = useFeedsStore((s) => s.snapshot.items.kev)

  const hosts = useTechStore((s) => s.hosts)
  const techLoaded = useTechStore((s) => s.loaded)
  const loadTech = useTechStore((s) => s.load)
  useEffect(() => {
    if (!techLoaded) void loadTech()
  }, [techLoaded, loadTech])

  const matches = useMemo(
    () => correlateExposure(hosts, [...kev, ...cve]).slice(0, MAX_ROWS),
    [hosts, kev, cve]
  )

  const body = () => {
    if (!available) return <EmptyPanelBody>Feeds are unavailable on this instance</EmptyPanelBody>
    if (!enabled) return <FeedsOffBody />
    if (hosts.length === 0) {
      return (
        <EmptyPanelBody>
          Capture and fingerprint targets to see which run something under active exploitation
        </EmptyPanelBody>
      )
    }
    if (matches.length === 0) {
      return <EmptyPanelBody>No fingerprinted technology matches the active threat feeds</EmptyPanelBody>
    }
    return (
      <ul className="divide-y divide-border-subtle">
        {matches.map((m) => (
          <ExposureRow key={`${m.host}|${m.tech.name}|${m.item.id}`} m={m} />
        ))}
      </ul>
    )
  }

  return (
    <DashboardPanel
      title="Target Exposure"
      count={enabled ? matches.length : 0}
      headerExtra={
        <span className="ml-auto float-right text-content-muted" title="Your fingerprinted targets vs active CVE/KEV feeds">
          <ShieldAlert size={13} />
        </span>
      }
    >
      {body()}
    </DashboardPanel>
  )
}

function ExposureRow({ m }: { m: ExposureMatch }) {
  const { host, tech, item } = m
  const isKev = item.category === 'kev' || item.alsoInKEV
  const sevClass = item.severity === 'CRITICAL' ? 'text-semantic-error' : 'text-semantic-warning'
  return (
    <li className="px-3 py-2 hover:bg-surface-hover">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-xs text-content-primary">
            <span className="text-content-secondary">{host}</span>
            <span className="mx-1 text-border" aria-hidden="true">›</span>
            <span className="font-medium capitalize">{tech.name}</span>
            {tech.version && <span className="text-content-muted"> {tech.version}</span>}
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
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
            {typeof item.score === 'number' && item.score > 0 && (
              <span className={`text-[11px] font-semibold ${sevClass}`}>{item.score.toFixed(1)}</span>
            )}
            {isKev && (
              <span
                title="In the CISA KEV catalog (actively exploited)"
                className="rounded bg-semantic-error-bg px-1 text-[9px] font-bold uppercase text-semantic-error"
              >
                KEV
              </span>
            )}
            <EpssBadge epss={item.epss} />
            {m.confidence === 'possible' && (
              <span className="text-[9px] uppercase tracking-wide text-content-muted" title="Heuristic name match">
                possible
              </span>
            )}
          </div>
        </div>
      </div>
    </li>
  )
}
