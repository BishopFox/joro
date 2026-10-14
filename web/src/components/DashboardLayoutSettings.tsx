import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import {
  WIDGETS,
  NO_WIDGET,
  isAvailable,
  unavailableReason,
  type AvailabilityCtx,
} from '../lib/dashboardWidgets'
import { PRESETS, presetOrDefault, type PresetId } from '../lib/dashboardPresets'
import { layoutIncludes, useDashboardLayoutStore, type LayoutMode } from '../stores/dashboardLayoutStore'

const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border'

const MODE_LABEL: Record<LayoutMode, string> = {
  team: 'Team',
  local: 'Local',
}

// DashboardLayoutSettings edits the two stored dashboard layouts: the one used
// when joined to a team server, and the one used running a local proxy.
export default function DashboardLayoutSettings({
  liveTeamMode,
  dashboardPlugin,
}: {
  liveTeamMode: boolean
  dashboardPlugin: string | null
}) {
  const layout = useDashboardLayoutStore((s) => s.layout)
  const setPreset = useDashboardLayoutStore((s) => s.setPreset)
  const setSlot = useDashboardLayoutStore((s) => s.setSlot)
  const resetMode = useDashboardLayoutStore((s) => s.resetMode)

  // Start on the layout the operator is actually looking at.
  const [editing, setEditing] = useState<LayoutMode>(liveTeamMode ? 'team' : 'local')

  // Proxy vs listener is a property of this running instance, not of the
  // layout — it decides which widgets can ever be shown here.
  const [runMode, setRunMode] = useState('proxy')
  useEffect(() => {
    api.getMode().then((r) => setRunMode(r.mode)).catch(() => {})
  }, [])

  const modeLayout = layout[editing]
  // Presence only applies to the team layout — it's the one in use when joined
  // to a team server.
  const hiddenFromTeam = editing === 'team' && !layoutIncludes(layout, 'team', 'team-chat')
  const preset = presetOrDefault(modeLayout.preset, 'intel')
  // Availability for the layout being edited, which may not be the live one.
  const ctx: AvailabilityCtx = { mode: runMode, teamMode: editing === 'team' }
  // The Default layout ('intel') is curated and fixed — its slots can't be rearranged. The
  // Layout picker stays enabled so the operator can switch to a customizable preset.
  const locked = preset.id === 'intel'

  return (
    <div className="space-y-2">
      <p className="text-[11px] text-content-muted leading-relaxed">
        Pick a layout and choose what fills each slot. Joro keeps a separate layout for team
        sessions and for local proxy sessions, and switches between them automatically. Stored per
        operator in this browser; included when you save a User Config.
      </p>

      {hiddenFromTeam && (
        <div className="border-l-2 border-semantic-warning pl-2.5 py-1 text-[10px] text-content-secondary leading-relaxed">
          Without the <span className="text-semantic-warning font-semibold">Team Chat</span> widget
          you are hidden from the team roster - presence is only announced while chat is on your
          dashboard.
        </div>
      )}

      {dashboardPlugin && (
        <div className="border-l-2 border-semantic-warning pl-2.5 py-1 text-[10px] text-content-secondary leading-relaxed">
          The <span className="text-semantic-warning font-semibold">{dashboardPlugin}</span> plugin
          replaces the built-in dashboard - these settings won't be visible until it's removed.
        </div>
      )}

      <div className="flex items-center gap-1.5">
        {(['team', 'local'] as LayoutMode[]).map((m) => (
          <button
            key={m}
            onClick={() => setEditing(m)}
            className={`px-2.5 py-1 rounded-sm text-[11px] font-semibold ${
              editing === m
                ? 'bg-accent-secondary text-black'
                : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
            }`}
          >
            {MODE_LABEL[m]}
            {(m === 'team') === liveTeamMode && (
              <span className="ml-1 font-normal opacity-70">(current)</span>
            )}
          </button>
        ))}
        <button
          onClick={() => resetMode(editing)}
          className="ml-auto px-2.5 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-[11px] font-semibold"
        >
          Reset
        </button>
      </div>

      <div className="divide-y divide-border-subtle">
        <div className="flex items-center justify-between gap-3 py-1.5">
          <span className="text-xs text-content-secondary min-w-0 truncate" title={preset.description}>
            Layout
          </span>
          <select
            value={preset.id}
            onChange={(e) => setPreset(editing, e.target.value as PresetId)}
            className={inputCls}
          >
            {PRESETS.map((p) => (
              <option key={p.id} value={p.id}>{p.label}</option>
            ))}
          </select>
        </div>

        {locked && (
          <div className="border-l-2 border-semantic-warning pl-2.5 py-1 text-[10px] text-content-secondary leading-relaxed">
            The <span className="text-semantic-warning font-semibold">Default</span> layout is
            curated and can&rsquo;t be rearranged. Pick another layout above to customize slots.
          </div>
        )}

        {preset.slots.map((s) => (
          <div key={s.key} className="flex items-center justify-between gap-3 py-1.5">
            <span className="text-xs text-content-secondary min-w-0 truncate">{s.label}</span>
            <select
              value={modeLayout.slots[s.key] ?? NO_WIDGET}
              onChange={(e) => setSlot(editing, s.key, e.target.value)}
              disabled={locked}
              className={`${inputCls} disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <option value={NO_WIDGET}>None</option>
              {WIDGETS.map((w) => {
                // Unavailable widgets stay selectable: you may be configuring
                // the team layout while running solo, or vice versa.
                const reason = isAvailable(w, ctx) ? '' : unavailableReason(w, ctx)
                return (
                  <option key={w.id} value={w.id} title={w.description}>
                    {w.label}{reason ? ` - ${reason}` : ''}
                  </option>
                )
              })}
            </select>
          </div>
        ))}

        {/* The bottom bar is a fixed Team Chat + Active Users strip; the only control is
            whether it shows. On the Default it is pinned on (disabled). When off, the row
            area flexes to fill the page. */}
        <label className="flex items-center justify-between gap-3 py-1.5">
          <span className="min-w-0 truncate text-xs text-content-secondary">
            Show Chat
            <span className="ml-1 text-content-muted">· Team Chat + Active Users</span>
          </span>
          <input
            type="checkbox"
            checked={modeLayout.slots.barMain !== NO_WIDGET}
            disabled={locked}
            onChange={(e) => {
              setSlot(editing, 'barMain', e.target.checked ? 'team-chat' : NO_WIDGET)
              setSlot(editing, 'barAside', e.target.checked ? 'active-users' : NO_WIDGET)
            }}
            className="disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </label>
      </div>
    </div>
  )
}
