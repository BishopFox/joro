import { create } from 'zustand'

export interface CallbackToken {
  id: string
  note: string
  token: string
  createdAt: string
  hitCount: number
}

export interface CallbackInteraction {
  id: string
  tokenId: string
  token: string
  type: string
  sourceIp: string
  timestamp: string
  queryName?: string
  queryType?: string
  method?: string
  path?: string
  headers?: string
  body?: string
  rawRequest?: string
  source?: string
}

interface CallbackState {
  tokens: CallbackToken[]
  interactions: CallbackInteraction[]
  interactionsTotal: number
  selectedToken: string | null
  selectedInteraction: CallbackInteraction | null
  setTokens: (tokens: CallbackToken[]) => void
  addToken: (token: CallbackToken) => void
  removeToken: (id: string) => void
  setInteractions: (items: CallbackInteraction[], total: number) => void
  addInteraction: (item: CallbackInteraction) => void
  clearInteractions: () => void
  setSelectedToken: (id: string | null) => void
  setSelectedInteraction: (item: CallbackInteraction | null) => void
}

export const useCallbackStore = create<CallbackState>((set) => ({
  tokens: [],
  interactions: [],
  interactionsTotal: 0,
  selectedToken: null,
  selectedInteraction: null,

  setTokens: (tokens) => set({ tokens }),
  addToken: (token) => set((s) => ({ tokens: [token, ...s.tokens] })),
  removeToken: (id) =>
    set((s) => ({
      tokens: s.tokens.filter((t) => t.id !== id),
      selectedToken: s.selectedToken === id ? null : s.selectedToken,
    })),
  setInteractions: (items, total) => set({ interactions: items, interactionsTotal: total }),
  addInteraction: (item) =>
    set((s) => {
      const tokens = s.tokens.map((t) =>
        t.id === item.tokenId ? { ...t, hitCount: t.hitCount + 1 } : t
      )
      return {
        interactions: [item, ...s.interactions].slice(0, 500),
        interactionsTotal: s.interactionsTotal + 1,
        tokens,
      }
    }),
  clearInteractions: () => set({ interactions: [], interactionsTotal: 0, selectedInteraction: null }),
  setSelectedToken: (selectedToken) => set({ selectedToken }),
  setSelectedInteraction: (selectedInteraction) => set({ selectedInteraction }),
}))
