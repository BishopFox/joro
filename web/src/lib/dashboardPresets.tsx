import type { ReactNode } from 'react'
import { NO_WIDGET } from './dashboardWidgets'

// Dashboard layout presets.
//
// A preset describes only the *row* area. The bottom bar (a resizable,
// full-width strip split into a main region and a narrow sidebar) is part of
// the dashboard frame and is shared by every preset — that's what keeps the
// resizer working when the operator swaps chat out of it.

export type PresetId = 'intel' | 'classic' | 'triptych' | 'grid' | 'stack'

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
    // The curated "Default" dashboard: a freeform, non-customizable intel console. The CVE
    // ticker rides above the whole page; this is an asymmetric magazine layout — a tall Threat
    // Intel hero with the operator's own findings/interactions beneath it, beside a single
    // full-height CISA KEV box. Team Chat + Active Users are pinned to the bottom bar.
    //
    // The id stays 'intel' (not 'default') on purpose: renaming it would need a layout-version
    // migration and could orphan a stored layout. The operator only ever sees the label.
    // DashboardLayoutSettings locks this preset's slot editors; the arrangement is fixed.
    id: 'intel',
    label: 'Default',
    description: 'The curated intel dashboard (not customizable).',
    slots: [
      { key: 'headlines', label: 'Threat intel' },
      { key: 'findings', label: 'Findings' },
      { key: 'interactions', label: 'Interactions' },
      { key: 'kev', label: 'CISA KEV' },
    ],
    renderRow: (slot) => (
      <div className="flex-1 min-h-0 flex gap-2">
        {/* Left column: the Threat Intel hero over the operator's own session. */}
        <div className="flex-[3] min-w-0 flex flex-col gap-2">
          <div className="flex-[2] min-h-0 flex">{slot('headlines')}</div>
          <div className="flex-[1] min-h-0 flex gap-2">
            {slot('findings')}
            {slot('interactions')}
          </div>
        </div>
        {/* Right column: a single full-height CISA KEV box. */}
        <div className="flex-[2] min-w-0 flex">{slot('kev')}</div>
      </div>
    ),
  },
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

// Local default: the curated intel console. Threat Intel leads as the hero over the operator's
// own findings/interactions, beside a single CISA KEV box; the CVE ticker rides above the page,
// and Team Chat + Active Users are pinned to the bottom bar (always present, both modes).
export const DEFAULT_LOCAL_LAYOUT: ModeLayout = {
  preset: 'intel',
  slots: {
    headlines: 'threat-headlines',
    findings: 'detect-findings',
    interactions: 'recent-interactions',
    kev: 'kev-feed',
    barMain: 'team-chat',
    barAside: 'active-users',
  },
}

// Team default: the SAME curated console. The two layouts stay independent — an operator can
// still switch either to a different, customizable preset — but both default to the console.
export const DEFAULT_TEAM_LAYOUT: ModeLayout = {
  preset: 'intel',
  slots: { ...DEFAULT_LOCAL_LAYOUT.slots },
}

// V2_DEFAULT_LOCAL is the local default Joro shipped at layout version 2 (the 2×2 grid). Kept
// only so the v2→v3 migration can tell a pristine default — which it upgrades to the intel
// console — from a layout the operator arranged, which it leaves alone. See migrateV2.
export const V2_DEFAULT_LOCAL: ModeLayout = {
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
