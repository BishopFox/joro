import { useMemo } from 'react'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import { useDashboardDataStore } from '../../stores/dashboardDataStore'
import { timeAgo } from '../../lib/timeAgo'
import { Redacted } from '../Redacted'

interface UnifiedEvent {
  id: string
  kind: 'dns' | 'http' | 'xss'
  label: string       // token name or probe name
  source: string      // source IP
  detail: string      // queryName, path, or fired URL
  timestamp: string
}

function kindClass(kind: UnifiedEvent['kind']): string {
  switch (kind) {
    case 'dns':
      return 'bg-accent-secondary/20 text-accent-secondary'
    case 'xss':
      return 'bg-semantic-special/20 text-semantic-special'
    default:
      return 'bg-accent/20 text-accent'
  }
}

export default function RecentInteractionsWidget() {
  const interactions = useDashboardDataStore((s) => s.interactions)
  const tokens = useDashboardDataStore((s) => s.tokens)
  const fires = useDashboardDataStore((s) => s.fires)
  const probes = useDashboardDataStore((s) => s.probes)

  // Merge callback interactions and XSS fires into a single sorted list
  const events = useMemo<UnifiedEvent[]>(() => {
    const tokenName = (tokenId: string) => {
      const t = tokens.find((tk) => tk.id === tokenId)
      return t ? t.note || t.token : tokenId.slice(0, 8)
    }
    const probeName = (probeId: string) => {
      const p = probes.find((pr) => pr.id === probeId)
      return p ? p.name : probeId.slice(0, 8)
    }
    return [
      ...interactions.map((i): UnifiedEvent => ({
        id: `cb-${i.id}`,
        kind: i.type as 'dns' | 'http',
        label: tokenName(i.tokenId),
        source: i.sourceIp,
        detail: i.queryName || i.path || '-',
        timestamp: i.timestamp,
      })),
      ...fires.map((f): UnifiedEvent => ({
        id: `xss-${f.id}`,
        kind: 'xss',
        label: probeName(f.probeId),
        source: f.sourceIp,
        detail: f.url || f.origin || '-',
        timestamp: f.firedAt,
      })),
    ]
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 20)
  }, [interactions, tokens, fires, probes])

  return (
    <DashboardPanel title="Recent Interactions" count={events.length}>
      {events.length === 0 ? (
        <EmptyPanelBody>No interactions yet</EmptyPanelBody>
      ) : (
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-surface-card">
            <tr className="text-content-secondary text-left">
              <th className="px-3 py-1.5 font-medium">Type</th>
              <th className="px-3 py-1.5 font-medium">Name</th>
              <th className="px-3 py-1.5 font-medium">Source</th>
              <th className="px-3 py-1.5 font-medium">Detail</th>
              <th className="px-3 py-1.5 font-medium">Time</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className="border-t border-border-subtle hover:bg-surface-hover">
                <td className="px-3 py-1.5">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${kindClass(e.kind)}`}
                  >
                    {e.kind}
                  </span>
                </td>
                <td className="px-3 py-1.5 text-content-primary">
                  <Redacted value={e.label} kind="secret" />
                </td>
                <td className="px-3 py-1.5 text-content-secondary">
                  <Redacted value={e.source} kind="ip" />
                </td>
                <td className="px-3 py-1.5 text-content-secondary truncate max-w-[200px]">
                  <Redacted value={e.detail} kind="url" />
                </td>
                <td className="px-3 py-1.5 text-content-muted">{timeAgo(e.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </DashboardPanel>
  )
}
