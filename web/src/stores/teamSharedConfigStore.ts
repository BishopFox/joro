import { create } from 'zustand'

// SharedConfigSummary is a published project config without its blob (list view).
export interface SharedConfigSummary {
  id: string
  name: string
  project: string
  author: string
  createdAt: string
}

// SharedConfig includes the opaque base64(gzipped projectConfigFile) blob.
export interface SharedConfig extends SharedConfigSummary {
  config: string
}

// SharedConfigPayload is the 3-field collaboration unit (scope/replace/customdata).
export interface SharedConfigPayload {
  scopeEnabled: boolean
  scopeRules: { pattern: string; methods: string[]; path: string; include: boolean }[]
  replaceEnabled: boolean
  replaceRules: { target: string; matchType: string; match: string; replace: string }[]
  customDataEnabled: boolean
  customDataItems: { type: string; name: string; value: string }[]
}

interface TeamSharedConfigState {
  items: SharedConfigSummary[]
  setItems: (items: SharedConfigSummary[]) => void
  addItem: (item: SharedConfigSummary) => void
  removeItem: (id: string) => void
}

export const useTeamSharedConfigStore = create<TeamSharedConfigState>((set) => ({
  items: [],
  setItems: (items) => set({ items }),
  addItem: (item) =>
    set((state) => {
      if (state.items.some((c) => c.id === item.id)) return state
      return { items: [item, ...state.items] }
    }),
  removeItem: (id) =>
    set((state) => ({ items: state.items.filter((c) => c.id !== id) })),
}))
