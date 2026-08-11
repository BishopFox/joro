import { create } from 'zustand'
import {
  DEFAULT_LOCAL_LAYOUT,
  DEFAULT_TEAM_LAYOUT,
  allSlots,
  presetOrDefault,
  type ModeLayout,
  type PresetId,
  type SlotMap,
} from '../lib/dashboardPresets'
import { NO_WIDGET } from '../lib/dashboardWidgets'

const STORAGE_KEY = 'joro-dashboard-layout'
// The dashboard's bottom-bar height used to live under its own key.
const LEGACY_HEIGHT_KEY = 'joro-chat-height'

export const LAYOUT_VERSION = 2
export const DEFAULT_BAR_HEIGHT = 256
export const MIN_BAR_HEIGHT = 100
export const MAX_BAR_HEIGHT = 600

export type LayoutMode = 'team' | 'local'

export interface DashboardLayout {
  version: number
  team: ModeLayout
  local: ModeLayout
  /** Bottom-bar height in pixels, shared by both modes. */
  barHeight: number
}

function defaultFor(mode: LayoutMode): ModeLayout {
  return mode === 'team' ? DEFAULT_TEAM_LAYOUT : DEFAULT_LOCAL_LAYOUT
}

function clampHeight(n: unknown, fallback: number): number {
  const v = typeof n === 'number' ? n : NaN
  if (!Number.isFinite(v)) return fallback
  return Math.min(MAX_BAR_HEIGHT, Math.max(MIN_BAR_HEIGHT, Math.round(v)))
}

function sanitizeMode(raw: unknown, mode: LayoutMode): ModeLayout {
  const fallback = defaultFor(mode)
  if (!raw || typeof raw !== 'object') return { ...fallback, slots: { ...fallback.slots } }
  const obj = raw as { preset?: unknown; slots?: unknown }
  const preset = presetOrDefault(String(obj.preset ?? ''), fallback.preset)
  const stored = (obj.slots && typeof obj.slots === 'object' ? obj.slots : {}) as Record<string, unknown>

  // Keep only slots the chosen preset declares, and fall back per key so a
  // partially-written blob still produces a usable layout.
  //
  // Note what is deliberately NOT validated here: widget ids. An id this build
  // doesn't know is preserved verbatim. Dropping it would mean a downgrade
  // silently destroys a layout built on a newer version, since the next
  // setSlot would persist the stripped copy. Unknown and unavailable ids are
  // both resolved away at render time instead (see resolveSlot).
  const slots: SlotMap = {}
  for (const s of allSlots(preset)) {
    const v = stored[s.key]
    slots[s.key] = typeof v === 'string' && v ? v : fallback.slots[s.key] ?? NO_WIDGET
  }
  return { preset: preset.id, slots }
}

function defaults(): DashboardLayout {
  return {
    version: LAYOUT_VERSION,
    team: { ...DEFAULT_TEAM_LAYOUT, slots: { ...DEFAULT_TEAM_LAYOUT.slots } },
    local: { ...DEFAULT_LOCAL_LAYOUT, slots: { ...DEFAULT_LOCAL_LAYOUT.slots } },
    barHeight: DEFAULT_BAR_HEIGHT,
  }
}

// The slot the v1 local default put the network graph in.
const V1_LOCAL_GRAPH_SLOT = 'bottomLeft'

// migrateV1 upgrades a version-1 blob: the local dashboard's bottom-left slot
// changed from the network graph to automation activity.
//
// One slot, local only, and only where it still holds the widget the v1 default
// put there. An operator who moved the graph elsewhere, switched preset, or chose
// something else keeps what they arranged — this resurrects nothing and discards
// nothing else. Same discipline as backfillOHTTPDefaults on the Go side: patch the
// specific entry rather than unioning the whole default set, so a deliberate
// choice is never overwritten by a shipped default.
//
// There is deliberately no preset check. A local layout on any preset other than
// 'grid' has no bottomLeft key at all (sanitizeMode prunes slots to the active
// preset before anything is persisted), so the lookup misses and this no-ops.
function migrateV1(obj: Partial<DashboardLayout>): Partial<DashboardLayout> {
  const local = obj.local as { preset?: unknown; slots?: Record<string, unknown> } | undefined
  const slots = local?.slots
  if (slots && slots[V1_LOCAL_GRAPH_SLOT] === 'network-graph') {
    return {
      ...obj,
      version: LAYOUT_VERSION,
      local: { ...local, slots: { ...slots, [V1_LOCAL_GRAPH_SLOT]: 'automation-activity' } },
    } as Partial<DashboardLayout>
  }
  return { ...obj, version: LAYOUT_VERSION }
}

// sanitize is the single gate for untrusted layout data, used by both the
// localStorage load and the User Config rehydration.
//
// A *known* older version is migrated; an unrecognized one still falls back to
// defaults. Bumping LAYOUT_VERSION without adding a migration step here therefore
// resets every operator's layout — add the step.
export function sanitize(raw: unknown): DashboardLayout {
  if (!raw || typeof raw !== 'object') return defaults()
  let obj = raw as Partial<DashboardLayout>
  if (obj.version === 1) obj = migrateV1(obj)
  if (obj.version !== LAYOUT_VERSION) return defaults()
  return {
    version: LAYOUT_VERSION,
    team: sanitizeMode(obj.team, 'team'),
    local: sanitizeMode(obj.local, 'local'),
    barHeight: clampHeight(obj.barHeight, DEFAULT_BAR_HEIGHT),
  }
}

function load(): DashboardLayout {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const parsed = JSON.parse(raw)
      const layout = sanitize(parsed)
      // Persist once when the stored blob was an older schema, so the upgrade
      // actually completes rather than re-running on every load and leaving the
      // file claiming a schema it no longer has.
      //
      // This is NOT an exception to the never-written-back rule that governs
      // resolve() in Dashboard.tsx. That rule keeps render-time reconciliation
      // non-destructive, so a downgrade cannot eat a layout built on a newer
      // build. A migration is the opposite kind of operation: it has to land on
      // disk to be one.
      if ((parsed as { version?: unknown } | null)?.version !== LAYOUT_VERSION) persist(layout)
      return layout
    }
    // First run on a build that has this feature: carry over the bar height
    // from the key the chat panel used to own.
    const legacy = parseInt(localStorage.getItem(LEGACY_HEIGHT_KEY) || '', 10)
    const base = defaults()
    return Number.isNaN(legacy) ? base : { ...base, barHeight: clampHeight(legacy, base.barHeight) }
  } catch {
    return defaults()
  }
}

function persist(layout: DashboardLayout) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(layout))
  } catch {
    /* ignore quota / privacy-mode failures */
  }
}

// layoutIncludes reports whether a widget occupies a slot in one mode's layout.
// Slots are pruned to the active preset's keys by sanitizeMode, so this only
// sees widgets that would actually be drawn.
export function layoutIncludes(
  layout: DashboardLayout,
  mode: LayoutMode,
  widget: string
): boolean {
  return Object.values(layout[mode].slots).includes(widget)
}

interface DashboardLayoutState {
  layout: DashboardLayout
  setPreset: (mode: LayoutMode, preset: PresetId) => void
  setSlot: (mode: LayoutMode, slot: string, widget: string) => void
  setBarHeight: (h: number) => void
  resetMode: (mode: LayoutMode) => void
  /** Applies a layout loaded from a User Config. Sanitized like storage. */
  setLayout: (raw: unknown) => void
}

// changePreset carries widget choices across a preset change positionally, so
// trying a preset and switching back doesn't wipe the operator's picks.
function changePreset(current: ModeLayout, next: PresetId, mode: LayoutMode): ModeLayout {
  const from = presetOrDefault(current.preset, defaultFor(mode).preset)
  const to = presetOrDefault(next, defaultFor(mode).preset)
  const carried = from.slots.map((s) => current.slots[s.key]).filter((v): v is string => !!v)
  const fallback = defaultFor(mode).slots
  const slots: SlotMap = {}
  to.slots.forEach((s, i) => {
    slots[s.key] = carried[i] ?? fallback[s.key] ?? NO_WIDGET
  })
  // The bar slots exist in every preset and carry across unchanged.
  for (const s of allSlots(to).slice(to.slots.length)) {
    slots[s.key] = current.slots[s.key] ?? fallback[s.key] ?? NO_WIDGET
  }
  return { preset: to.id, slots }
}

export const useDashboardLayoutStore = create<DashboardLayoutState>((set, get) => ({
  layout: load(),

  setPreset: (mode, preset) => {
    const layout = { ...get().layout, [mode]: changePreset(get().layout[mode], preset, mode) }
    persist(layout)
    set({ layout })
  },

  setSlot: (mode, slot, widget) => {
    const current = get().layout
    const layout = {
      ...current,
      [mode]: { ...current[mode], slots: { ...current[mode].slots, [slot]: widget } },
    }
    persist(layout)
    set({ layout })
  },

  setBarHeight: (h) => {
    const layout = { ...get().layout, barHeight: clampHeight(h, DEFAULT_BAR_HEIGHT) }
    persist(layout)
    set({ layout })
  },

  resetMode: (mode) => {
    const def = defaultFor(mode)
    const layout = { ...get().layout, [mode]: { ...def, slots: { ...def.slots } } }
    persist(layout)
    set({ layout })
  },

  setLayout: (raw) => {
    const layout = sanitize(raw)
    persist(layout)
    set({ layout })
  },
}))
