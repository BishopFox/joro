import { create } from 'zustand'
import { api, type HostTech } from '../lib/api'

// Passive technology fingerprints, keyed by host. The store is push-driven: it
// loads once and ws.ts folds in tech.detected / tech.summary as traffic flows,
// so it never joins the dashboard poll loop.

interface TechState {
  enabled: boolean
  hosts: HostTech[]
  summary: { hosts: number; techs: number }
  loaded: boolean
  loading: boolean

  load: () => Promise<void>
  applyDetected: (ht: HostTech) => void
  setSummary: (s: { hosts: number; techs: number }) => void
  setEnabled: (enabled: boolean) => Promise<void>
}

export const useTechStore = create<TechState>((set, get) => ({
  enabled: true,
  hosts: [],
  summary: { hosts: 0, techs: 0 },
  loaded: false,
  loading: false,

  load: async () => {
    if (get().loading) return
    set({ loading: true })
    try {
      const res = await api.techHosts()
      set({ enabled: res.enabled, hosts: res.hosts ?? [], summary: res.summary, loaded: true })
    } catch {
      // Unavailable outside proxy mode; leave the store empty.
      set({ loaded: true })
    } finally {
      set({ loading: false })
    }
  },

  // A tech.detected payload carries a host's full, current set, so it replaces
  // that host's row rather than merging — the server already folded it.
  applyDetected: (ht) => {
    const hosts = get().hosts.filter((h) => h.host !== ht.host)
    hosts.unshift(ht)
    set({ hosts })
  },

  setSummary: (s) => set({ summary: s }),

  setEnabled: async (enabled) => {
    set({ enabled })
    try {
      await api.techSetEnabled(enabled)
    } catch {
      set({ enabled: !enabled })
    }
  },
}))
