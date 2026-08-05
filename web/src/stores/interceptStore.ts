import { create } from 'zustand'

export type InterceptKind = 'request' | 'response'

export interface PendingItem {
  id: string
  kind: InterceptKind
  method: string
  url: string
  host: string
  protocol?: string
  status?: number
  pausedAt?: string
  reqRaw: string // base64, set for both kinds
  respRaw?: string // base64, response pauses only
}

// Alias kept so existing call sites need no churn.
export type PendingRequest = PendingItem

// Both phases of one transaction share the request's id, so rows are keyed on
// kind + id. They cannot legitimately coexist, but a dropped intercept.resolved
// WS frame would otherwise leave two rows sharing a React key.
const keyOf = (i: PendingItem) => `${i.kind}:${i.id}`

interface InterceptState {
  enabled: boolean
  responsesEnabled: boolean
  items: PendingItem[]
  selected: PendingItem | null
  setEnabled: (v: boolean) => void
  setResponsesEnabled: (v: boolean) => void
  setItems: (items: PendingItem[]) => void
  addItem: (item: PendingItem) => void
  removeItem: (id: string) => void
  setSelected: (item: PendingItem | null) => void
}

export const useInterceptStore = create<InterceptState>((set) => ({
  enabled: false,
  responsesEnabled: false,
  items: [],
  selected: null,

  setEnabled: (enabled) => set({ enabled }),
  setResponsesEnabled: (responsesEnabled) => set({ responsesEnabled }),

  setItems: (items) =>
    set((s) => {
      const sel = s.selected
      return {
        items,
        // Drop a selection the server no longer knows about (timed out, drained).
        selected: sel && items.some((i) => keyOf(i) === keyOf(sel)) ? sel : null,
      }
    }),

  // Upsert rather than append, so a reconcile poll or a replayed event cannot
  // duplicate a row.
  addItem: (item) =>
    set((s) => {
      const idx = s.items.findIndex((i) => keyOf(i) === keyOf(item))
      if (idx === -1) return { items: [...s.items, item] }
      const items = [...s.items]
      items[idx] = item
      return { items }
    }),

  // Clears both phases for the id. Idempotent.
  removeItem: (id) =>
    set((s) => ({
      items: s.items.filter((i) => i.id !== id),
      selected: s.selected?.id === id ? null : s.selected,
    })),

  setSelected: (selected) => set({ selected }),
}))
