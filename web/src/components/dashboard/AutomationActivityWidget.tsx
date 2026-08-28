import type { ReactNode } from 'react'
import { useNavigate } from 'react-router'
import { Bot } from 'lucide-react'
import DashboardPanel from '../DashboardPanel'
import { Redacted } from '../Redacted'
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

  if (audit === 'unavailable') {
    return (
      <Prompt onClick={goToSettings} label="Automation settings →">
        Automation is disabled for this run (<code className="font-mono">--no-automation</code>).
      </Prompt>
    )
  }

  const { lastHour, deniedLastHour, errorsLastHour, tokensActive, tokens } = audit.stats

  // Entries take precedence over the token count. A run a trigger or the operator
  // started records activity under a synthetic principal and never has a token, so
  // gating on tokens here would hide exactly the automations nobody is watching.
  // With nothing recorded, the two silences still differ: no tokens is a setup step
  // the operator has not taken, tokens with no calls is a quiet agent.
  if (audit.entries.length === 0 && tokens === 0) {
    return (
      <Prompt onClick={goToSettings} label="Set one up →">
        No automation tokens configured.
      </Prompt>
    )
  }

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
        {/* The first three tiles count every principal. The token tile is dropped
            when there are none, where it would read "0/0" beside live activity. */}
        <div
          className={`grid ${tokens > 0 ? 'grid-cols-4' : 'grid-cols-3'} gap-2 px-3 py-2 border-b border-border-subtle shrink-0`}
        >
          <Stat label="calls / hr" value={lastHour} />
          <Stat label="denied" value={deniedLastHour} tone={deniedLastHour > 0 ? 'warning' : undefined} />
          <Stat label="errors" value={errorsLastHour} tone={errorsLastHour > 0 ? 'error' : undefined} />
          {tokens > 0 && <Stat label="tokens" value={`${tokensActive}/${tokens}`} />}
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
                <span className="shrink-0 truncate max-w-[6rem]">
                  <Redacted value={e.tokenName} kind="identity" />
                </span>
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

// Prompt is the panel's non-activity state: a line of explanation and the one link
// that acts on it. Shared so the two cases it covers — automation off for the run,
// and nothing set up yet — cannot drift apart visually.
function Prompt({
  children,
  onClick,
  label,
}: {
  children: ReactNode
  onClick: () => void
  label: string
}) {
  return (
    <DashboardPanel title="Automation">
      <div className="h-full flex flex-col items-center justify-center gap-2 text-center px-4">
        <Bot size={22} strokeWidth={1.6} className="text-content-muted" aria-hidden="true" />
        <p className="text-xs text-content-muted">{children}</p>
        <button onClick={onClick} className="text-xs text-accent-secondary hover:underline">
          {label}
        </button>
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
