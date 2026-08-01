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

export const LAYOUT_VERSION = 1
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

// sanitize is the single gate for untrusted layout data, used by both the
// localStorage load and the User Config rehydration.
export function sanitize(raw: unknown): DashboardLayout {
  if (!raw || typeof raw !== 'object') return defaults()
  const obj = raw as Partial<DashboardLayout>
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
    if (raw) return sanitize(JSON.parse(raw))
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
