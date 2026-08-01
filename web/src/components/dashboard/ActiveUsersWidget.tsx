import DashboardPanel from '../DashboardPanel'
import { api } from '../../lib/api'
import { useTeamStore } from '../../stores/teamStore'
import { useSettingsStore, isTeamMode, type Settings } from '../../stores/settingsStore'
import { layoutIncludes, useDashboardLayoutStore } from '../../stores/dashboardLayoutStore'

const STATUS_OPTIONS: { value: string; label: string }[] = [
  { value: 'online', label: 'Online' },
  { value: 'away', label: 'Away' },
  { value: 'dnd', label: 'Do not disturb' },
  { value: 'offline', label: 'Appear offline' },
]

export function statusDotClass(status: string): string {
  switch (status) {
    case 'away':
      return 'bg-semantic-warning'
    case 'dnd':
      return 'bg-semantic-error'
    case 'offline':
      return 'bg-content-muted'
    default:
      return 'bg-semantic-success'
  }
}

export default function ActiveUsersWidget() {
  const settings = useSettingsStore((s) => s.settings)
  const setSettings = useSettingsStore((s) => s.setSettings)
  const teamMode = isTeamMode(settings)
  const activeUsers = useTeamStore((s) => s.activeUsers)
  // Presence is tied to the Team Chat widget (see the push in App.tsx). Without
  // it we announce 'offline' and the team server hides us, so the status
  // control would otherwise show a value that isn't what teammates see.
  const layout = useDashboardLayoutStore((s) => s.layout)
  const announcing = layoutIncludes(layout, teamMode ? 'team' : 'local', 'team-chat')

  const changeStatus = async (status: string) => {
    try {
      const updated = await api.updateSettings({ teamStatus: status })
      setSettings(updated as Settings)
    } catch { /* ignore */ }
  }

  const toggleShareProject = async (share: boolean) => {
    try {
      const updated = await api.updateSettings({ shareProjectName: share })
      setSettings(updated as Settings)
    } catch { /* ignore */ }
  }

  return (
    <DashboardPanel title="Active Users" bodyClassName="flex-1 min-h-0 flex flex-col">
      {/* My presence controls (team mode) */}
      {teamMode && (
        <div className="shrink-0 px-3 py-2 border-b border-border space-y-1.5">
          <div className="flex items-center gap-1.5">
            <span
              className={`w-2 h-2 rounded-full shrink-0 ${
                announcing ? statusDotClass(settings?.teamStatus || 'online') : 'bg-content-muted'
              }`}
            />
            <select
              value={settings?.teamStatus || 'online'}
              onChange={(e) => changeStatus(e.target.value)}
              disabled={!announcing}
              className="flex-1 min-w-0 bg-surface-input text-content-primary text-xs px-1.5 py-1 rounded border border-border focus:outline-none focus:border-accent-secondary disabled:opacity-50"
            >
              {STATUS_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          {!announcing && (
            <p className="text-[10px] text-content-muted leading-snug">
              Hidden from teammates — add the Team Chat widget to your dashboard to appear online.
            </p>
          )}
          <label className="flex items-center gap-1.5 text-xs text-content-terminal cursor-pointer">
            <input
              type="checkbox"
              checked={!!settings?.shareProjectName}
              onChange={(e) => toggleShareProject(e.target.checked)}
            />
            Share project name
          </label>
        </div>
      )}
      <div className="flex-1 overflow-y-auto px-3 py-2 space-y-2">
        {teamMode ? (
          activeUsers.length === 0 ? (
            <p className="text-[10px] text-content-muted italic">No users connected</p>
          ) : (
            activeUsers.map((user) => (
              <div key={user.nickname} className="flex items-start gap-1.5">
                <span className={`w-2 h-2 mt-1 rounded-full shrink-0 ${statusDotClass(user.status)}`} />
                <div className="min-w-0">
                  <div className="text-xs text-content-terminal truncate">{user.nickname}</div>
                  {user.project && (
                    <div className="text-[10px] text-content-muted truncate" title={user.project}>
                      {user.project}
                    </div>
                  )}
                </div>
              </div>
            ))
          )
        ) : (
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-semantic-success shrink-0" />
            <span className="text-xs text-content-terminal truncate">operator</span>
          </div>
        )}
      </div>
    </DashboardPanel>
  )
}
