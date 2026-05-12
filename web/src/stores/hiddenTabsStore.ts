import { create } from 'zustand'

const STORAGE_KEY = 'joro-hidden-tabs'

function load(): string[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === 'string') : []
  } catch {
    return []
  }
}

function persist(list: string[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list))
}

interface HiddenTabsState {
  hiddenTabs: string[]
  isHidden: (to: string) => boolean
  toggleTab: (to: string) => void
  setHiddenTabs: (list: string[]) => void
}

export const useHiddenTabsStore = create<HiddenTabsState>((set, get) => ({
  hiddenTabs: load(),
  isHidden: (to) => get().hiddenTabs.includes(to),
  toggleTab: (to) => {
    const current = get().hiddenTabs
    const next = current.includes(to) ? current.filter((t) => t !== to) : [...current, to]
    persist(next)
    set({ hiddenTabs: next })
  },
  setHiddenTabs: (list) => {
    const sanitized = Array.isArray(list) ? list.filter((x) => typeof x === 'string') : []
    persist(sanitized)
    set({ hiddenTabs: sanitized })
  },
}))
