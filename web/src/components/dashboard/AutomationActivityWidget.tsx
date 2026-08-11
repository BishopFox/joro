import { useNavigate } from 'react-router'
import { Bot } from 'lucide-react'
import DashboardPanel from '../DashboardPanel'
import { useDashboardDataStore } from '../../stores/dashboardDataStore'

/**
 * Automation activity on the dashboard.
 *
 * Activity is where an operator notices an agent misbehaving, so it belongs
 * somewhere they already look rather than three clicks into Settings. This is the
 * metrics-forward view — counts plus the last few calls; the full filterable list
 * lives in Settings → Automation, which the header links to.
 */
export default function AutomationActivityWidget() {
  const navigate = useNavigate()
  const audit = useDashboardDataStore((s) => s.automationActivity)

  const goToSettings = () => navigate('/settings', { state: { category: 'automation' } })

  if (!audit) {
    return (
      <DashboardPanel title="Automation">
        <div className="h-full flex items-center justify-center text-content-muted text-xs italic">Loading…</div>
      </DashboardPanel>
    )
  }

  // Distinguishing "no tokens" from "no calls yet" matters: the first is a setup
  // step the operator has not taken, the second is a quiet agent.
  if (audit.stats.tokens === 0) {
    return (
      <DashboardPanel title="Automation">
        <div className="h-full flex flex-col items-center justify-center gap-2 text-center px-4">
          <Bot size={22} strokeWidth={1.6} className="text-content-muted" aria-hidden="true" />
          <p className="text-xs text-content-muted">No automation tokens configured.</p>
          <button onClick={goToSettings} className="text-xs text-accent-secondary hover:underline">
            Set one up →
          </button>
        </div>
      </DashboardPanel>
    )
  }

  const { lastHour, deniedLastHour, errorsLastHour, tokensActive, tokens } = audit.stats

  return (
    <DashboardPanel
      title="Automation"
      headerExtra={
        <button onClick={goToSettings} className="text-[10px] text-content-muted hover:text-content-primary">
          Manage
        </button>
      }
    >
      <div className="h-full flex flex-col min-h-0">
        <div className="grid grid-cols-4 gap-2 px-3 py-2 border-b border-border-subtle shrink-0">
          <Stat label="calls / hr" value={lastHour} />
          <Stat label="denied" value={deniedLastHour} tone={deniedLastHour > 0 ? 'warning' : undefined} />
          <Stat label="errors" value={errorsLastHour} tone={errorsLastHour > 0 ? 'error' : undefined} />
          <Stat label="tokens" value={`${tokensActive}/${tokens}`} />
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto font-mono text-[10px] px-3 py-1.5">
          {audit.entries.length === 0 ? (
            <div className="h-full flex items-center justify-center text-content-muted italic">No calls yet.</div>
          ) : (
            audit.entries.slice(0, 8).map((e) => (
              <div
                key={e.seq}
                className={`flex gap-2 py-0.5 ${
                  e.result === 'denied' ? 'text-semantic-warning' : e.result === 'error' ? 'text-semantic-error' : ''
                }`}
              >
                <span className="text-content-muted shrink-0">{new Date(e.at).toLocaleTimeString()}</span>
                <span className="shrink-0 truncate max-w-[6rem]">{e.tokenName}</span>
                <span className="truncate">{e.capability}</span>
                <span className="ml-auto shrink-0 text-content-muted">{e.code || e.result}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </DashboardPanel>
  )
}

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: 'warning' | 'error' }) {
  const color = tone === 'error' ? 'text-semantic-error' : tone === 'warning' ? 'text-semantic-warning' : ''
  return (
    <div className="text-center">
      <div className={`text-base font-semibold leading-none ${color}`}>{value}</div>
      <div className="text-[9px] uppercase tracking-wide text-content-muted mt-0.5">{label}</div>
    </div>
  )
}
