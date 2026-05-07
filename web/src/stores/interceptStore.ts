import { create } from 'zustand'

export interface PendingRequest {
  id: string
  method: string
  url: string
  host: string
  reqRaw: string // base64
}

interface InterceptState {
  enabled: boolean
  items: PendingRequest[]
  selected: PendingRequest | null
  setEnabled: (v: boolean) => void
  setItems: (items: PendingRequest[]) => void
  addItem: (item: PendingRequest) => void
  removeItem: (id: string) => void
  setSelected: (item: PendingRequest | null) => void
}

export const useInterceptStore = create<InterceptState>((set) => ({
  enabled: false,
  items: [],
  selected: null,

  setEnabled: (enabled) => set({ enabled }),
  setItems: (items) => set({ items }),
  addItem: (item) => set((s) => ({ items: [...s.items, item] })),
  removeItem: (id) =>
    set((s) => ({
      items: s.items.filter((i) => i.id !== id),
      selected: s.selected?.id === id ? null : s.selected,
    })),
  setSelected: (selected) => set({ selected }),
}))
