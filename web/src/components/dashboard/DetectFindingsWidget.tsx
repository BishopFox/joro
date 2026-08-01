import { useMemo } from 'react'
import { useNavigate } from 'react-router'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import { useDetectStore } from '../../stores/detectStore'
import { SEVERITY_ORDER, severityBadge, type Severity } from '../../lib/severity'
import { timeAgo } from '../../lib/timeAgo'

const MAX_ROWS = 8

// DetectFindingsWidget summarises passive detection: a per-severity count bar
// over the whole findings store, plus the most recent findings.
//
// The list reads detectStore.items, which is shared with the Detect page — so
// once the operator applies a filter there, this list reflects it. That is the
// accepted trade-off for having one live-merge path for detect.finding events
// instead of a second, independent one. The local sort keeps recency correct
// regardless of the sort column the Detect page is using.
export default function DetectFindingsWidget() {
  const navigate = useNavigate()
  const enabled = useDetectStore((s) => s.enabled)
  const summary = useDetectStore((s) => s.summary)
  const items = useDetectStore((s) => s.items)
  const setFilter = useDetectStore((s) => s.setFilter)
  const setSelected = useDetectStore((s) => s.setSelected)

  const recent = useMemo(
    () =>
      [...items]
        .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime())
        .slice(0, MAX_ROWS),
    [items]
  )

  const counts = SEVERITY_ORDER.map((sev) => ({
    sev,
    count: summary.bySeverity[sev] ?? 0,
  })).filter((s) => s.count > 0)

  // Jump to the Detect page showing only this band.
  const showSeverity = (sev: Severity) => {
    setFilter({ severities: [sev] })
    navigate('/detect')
  }

  return (
    <DashboardPanel
      title="Detected Findings"
      count={summary.total}
      bodyClassName="flex-1 min-h-0 flex flex-col"
    >
      {counts.length > 0 && (
        <div className="shrink-0 flex flex-wrap items-center gap-3 px-3 py-1.5 border-b border-border text-xs text-content-muted">
          {counts.map(({ sev, count }) => (
            <button
              key={sev}
              onClick={() => showSeverity(sev)}
              title={`Show ${sev} findings`}
              className="flex items-center gap-1 rounded-sm px-0.5 hover:bg-surface-hover"
            >
              {severityBadge(sev)}
              {count}
            </button>
          ))}
          {summary.falsePositives > 0 && <span>{summary.falsePositives} FP</span>}
        </div>
      )}
      <div className="flex-1 overflow-y-auto">
        {!enabled ? (
          <EmptyPanelBody>Detection is off</EmptyPanelBody>
        ) : recent.length === 0 ? (
          <EmptyPanelBody>No findings yet</EmptyPanelBody>
        ) : (
          <table className="w-full text-xs">
            <tbody>
              {recent.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => {
                    setSelected(f)
                    navigate('/detect')
                  }}
                  className="border-t border-border-subtle hover:bg-surface-hover cursor-pointer"
                >
                  <td className="px-3 py-1.5 w-px">{severityBadge(f.severity)}</td>
                  <td className="px-3 py-1.5 text-content-primary truncate max-w-[220px]" title={f.ruleName}>
                    {f.ruleName}
                  </td>
                  <td className="px-3 py-1.5 text-content-secondary truncate max-w-[160px]" title={f.host}>
                    {f.host}
                  </td>
                  <td className="px-3 py-1.5 text-content-muted text-right whitespace-nowrap">
                    {f.count > 1 && <span className="mr-2">&times;{f.count}</span>}
                    {timeAgo(f.lastSeen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </DashboardPanel>
  )
}
