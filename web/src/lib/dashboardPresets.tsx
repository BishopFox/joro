import type { ReactNode } from 'react'
import { NO_WIDGET } from './dashboardWidgets'

// Dashboard layout presets.
//
// A preset describes only the *row* area. The bottom bar (a resizable,
// full-width strip split into a main region and a narrow sidebar) is part of
// the dashboard frame and is shared by every preset — that's what keeps the
// resizer working when the operator swaps chat out of it.

export type PresetId = 'classic' | 'triptych' | 'grid' | 'stack'

export interface SlotDef {
  key: string
  label: string
}

export interface PresetDef {
  id: PresetId
  label: string
  description: string
  /** Row slots, in visual order. */
  slots: SlotDef[]
  /** `slot(key)` renders the widget assigned to that slot, or null. */
  renderRow: (slot: (key: string) => ReactNode) => ReactNode
}

// The two bar slots exist in every preset.
export const BAR_SLOTS: SlotDef[] = [
  { key: 'barMain', label: 'Bottom bar' },
  { key: 'barAside', label: 'Bottom bar sidebar' },
]

export const PRESETS: PresetDef[] = [
  {
    id: 'classic',
    label: 'Classic',
    description: 'One large panel beside a stacked pair.',
    slots: [
      { key: 'main', label: 'Main' },
      { key: 'sideTop', label: 'Side top' },
      { key: 'sideBottom', label: 'Side bottom' },
    ],
    renderRow: (slot) => (
      <div className="flex-1 min-h-0 flex gap-2">
        {slot('main')}
        <div className="flex-1 min-w-0 flex flex-col gap-2">
          {slot('sideTop')}
          {slot('sideBottom')}
        </div>
      </div>
    ),
  },
  {
    id: 'triptych',
    label: 'Triptych',
    description: 'Three equal columns.',
    slots: [
      { key: 'left', label: 'Left' },
      { key: 'center', label: 'Centre' },
      { key: 'right', label: 'Right' },
    ],
    renderRow: (slot) => (
      <div className="flex-1 min-h-0 flex gap-2">
        {slot('left')}
        {slot('center')}
        {slot('right')}
      </div>
    ),
  },
  {
    id: 'grid',
    label: 'Grid',
    description: 'Four equal panels, two by two.',
    slots: [
      { key: 'topLeft', label: 'Top left' },
      { key: 'topRight', label: 'Top right' },
      { key: 'bottomLeft', label: 'Bottom left' },
      { key: 'bottomRight', label: 'Bottom right' },
    ],
    renderRow: (slot) => (
      <div className="flex-1 min-h-0 flex flex-col gap-2">
        <div className="flex-1 min-h-0 flex gap-2">
          {slot('topLeft')}
          {slot('topRight')}
        </div>
        <div className="flex-1 min-h-0 flex gap-2">
          {slot('bottomLeft')}
          {slot('bottomRight')}
        </div>
      </div>
    ),
  },
  {
    id: 'stack',
    label: 'Single',
    description: 'One full-width panel.',
    slots: [{ key: 'main', label: 'Main' }],
    renderRow: (slot) => <div className="flex-1 min-h-0 flex gap-2">{slot('main')}</div>,
  },
]

export const PRESET_BY_ID = new Map<string, PresetDef>(PRESETS.map((p) => [p.id, p]))

export function presetOrDefault(id: string, fallback: PresetId): PresetDef {
  return PRESET_BY_ID.get(id) ?? PRESET_BY_ID.get(fallback)!
}

// allSlots returns a preset's row slots followed by the two shared bar slots.
export function allSlots(preset: PresetDef): SlotDef[] {
  return [...preset.slots, ...BAR_SLOTS]
}

export type SlotMap = Record<string, string>

export interface ModeLayout {
  preset: PresetId
  slots: SlotMap
}

// Team default: the layout Joro shipped with, unchanged.
export const DEFAULT_TEAM_LAYOUT: ModeLayout = {
  preset: 'classic',
  slots: {
    main: 'network-graph',
    sideTop: 'recent-interactions',
    sideBottom: 'flagged-requests',
    barMain: 'team-chat',
    barAside: 'active-users',
  },
}

// Local default: what a solo operator running a proxy actually wants. Chat and
// the active-user list are dropped (they're a scratchpad and a list of one) but
// stay in the catalog, so both bar slots are empty and the bar stays hidden.
export const DEFAULT_LOCAL_LAYOUT: ModeLayout = {
  preset: 'grid',
  slots: {
    topLeft: 'detect-findings',
    topRight: 'recent-interactions',
    bottomLeft: 'automation-activity',
    bottomRight: 'proxy-health',
    barMain: NO_WIDGET,
    barAside: NO_WIDGET,
  },
}
