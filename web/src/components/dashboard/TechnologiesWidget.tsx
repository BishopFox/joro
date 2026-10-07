import { useEffect } from 'react'
import { RefreshCw } from 'lucide-react'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import { useTechStore } from '../../stores/techStore'
import { fingerprintHosts } from '../../lib/scanMenu'
import { Redacted } from '../Redacted'

// Passive technology fingerprints per host. Push-driven via ws (tech.detected),
// so it loads once on mount and never polls.
export default function TechnologiesWidget() {
  const hosts = useTechStore((s) => s.hosts)
  const summary = useTechStore((s) => s.summary)
  const loaded = useTechStore((s) => s.loaded)
  const load = useTechStore((s) => s.load)

  useEffect(() => {
    if (!loaded) void load()
  }, [loaded, load])

  return (
    <DashboardPanel
      title="Technologies"
      count={summary.hosts}
      headerExtra={
        <button
          onClick={() => void fingerprintHosts()}
          title="Re-fingerprint all captured hosts"
          className="ml-auto float-right text-content-muted hover:text-accent-secondary"
        >
          <RefreshCw size={12} />
        </button>
      }
    >
      {hosts.length === 0 ? (
        <EmptyPanelBody>No technologies fingerprinted yet</EmptyPanelBody>
      ) : (
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-surface-card">
            <tr className="text-content-secondary text-left">
              <th className="px-3 py-1.5 font-medium">Host</th>
              <th className="px-3 py-1.5 font-medium">Technologies</th>
            </tr>
          </thead>
          <tbody>
            {hosts.slice(0, 40).map((h) => (
              <tr key={h.host} className="border-t border-border-subtle hover:bg-surface-hover align-top">
                <td className="px-3 py-1.5 text-content-primary whitespace-nowrap">
                  <Redacted value={h.host} kind="url" />
                </td>
                <td className="px-3 py-1.5">
                  <div className="flex flex-wrap gap-1">
                    {h.technologies.map((t) => (
                      <span
                        key={t.name}
                        title={t.categories?.join(', ')}
                        className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-accent-secondary/20 text-accent-secondary"
                      >
                        {t.name}
                        {t.version ? ` ${t.version}` : ''}
                      </span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </DashboardPanel>
  )
}
