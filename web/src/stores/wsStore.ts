import { create } from 'zustand'
import type { CapturedWSMessage } from '../lib/api'

interface WSState {
  items: CapturedWSMessage[]
  total: number
  loading: boolean
  selectedConnectionId: string | null
  selectedMessage: CapturedWSMessage | null
  addItem: (item: CapturedWSMessage) => void
  setItems: (items: CapturedWSMessage[], total: number) => void
  setSelectedConnectionId: (id: string | null) => void
  setSelectedMessage: (msg: CapturedWSMessage | null) => void
  setLoading: (v: boolean) => void
  clear: () => void
}

export const useWSStore = create<WSState>((set) => ({
  items: [],
  total: 0,
  loading: false,
  selectedConnectionId: null,
  selectedMessage: null,

  addItem: (item) =>
    set((s) => ({ items: [item, ...s.items].slice(0, 500) })),

  setItems: (items, total) => set({ items, total }),
  setSelectedConnectionId: (selectedConnectionId) => set({ selectedConnectionId, selectedMessage: null }),
  setSelectedMessage: (selectedMessage) => set({ selectedMessage }),
  setLoading: (loading) => set({ loading }),
  clear: () => set({ items: [], total: 0, selectedConnectionId: null, selectedMessage: null }),
}))
