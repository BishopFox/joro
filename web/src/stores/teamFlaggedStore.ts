import { create } from 'zustand'

// FlaggedSummary is a flagged request without its raw bytes (list/panel view).
export interface FlaggedSummary {
  id: string
  host: string
  method: string
  url: string
  status: number
  truncated: boolean
  note: string
  author: string
  createdAt: string
}

// FlaggedRequest is a flagged request including base64 raw request/response bytes.
export interface FlaggedRequest extends FlaggedSummary {
  reqRaw: string
  respRaw: string
}

interface TeamFlaggedState {
  items: FlaggedSummary[]
  setItems: (items: FlaggedSummary[]) => void
  addItem: (item: FlaggedSummary) => void
  removeItem: (id: string) => void
}

export const useTeamFlaggedStore = create<TeamFlaggedState>((set) => ({
  items: [],
  setItems: (items) => set({ items }),
  addItem: (item) =>
    set((state) => {
      if (state.items.some((f) => f.id === item.id)) return state
      return { items: [item, ...state.items] }
    }),
  removeItem: (id) =>
    set((state) => ({ items: state.items.filter((f) => f.id !== id) })),
}))
