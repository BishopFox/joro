import { create } from 'zustand'
import {
  api,
  type AutomationProfile,
  type AutomationToken,
  type AutomationTokenInput,
  type Capability,
  type McpState,
} from '../lib/api'

interface AutomationState {
  tokens: AutomationToken[]
  capabilities: Capability[]
  /** Server-declared class order. The picker groups by it so the write-heavy
   *  classes render last, rather than falling out of alphabetical-by-ID. */
  classes: string[]
  profiles: AutomationProfile[]
  fingerprint: string
  mcp: McpState | null
  loading: boolean
  /** Null until the first fetch resolves; false means automation is compiled in
   *  but the endpoints 404 (--no-automation), which the UI renders as an
   *  explanation rather than an error. */
  available: boolean | null

  refresh: () => Promise<void>
  refreshMcp: () => Promise<void>
  create: (body: AutomationTokenInput) => Promise<string>
  update: (id: string, body: Partial<AutomationTokenInput>) => Promise<void>
  rotate: (id: string) => Promise<string>
  setEnabled: (id: string, enabled: boolean) => Promise<void>
  review: (id: string) => Promise<void>
  revoke: (id: string) => Promise<void>
  setMcp: (body: { enabled?: boolean; port?: number }) => Promise<void>
}

export const useAutomationStore = create<AutomationState>((set, get) => ({
  tokens: [],
  capabilities: [],
  classes: [],
  profiles: [],
  fingerprint: '',
  mcp: null,
  loading: false,
  available: null,

  refresh: async () => {
    set({ loading: true })
    try {
      const [tokens, caps, mcp] = await Promise.all([
        api.listAutomationTokens(),
        api.listCapabilities(),
        api.getMcpState(),
      ])
      set({
        tokens: tokens.tokens ?? [],
        capabilities: caps.capabilities ?? [],
        classes: caps.classes ?? [],
        profiles: caps.profiles ?? [],
        fingerprint: caps.fingerprint,
        mcp,
        available: true,
      })
    } catch {
      // A 404 here means automation is disabled for this run, which is a
      // deployment choice rather than a failure worth a toast.
      set({ available: false })
    } finally {
      set({ loading: false })
    }
  },

  refreshMcp: async () => {
    try {
      set({ mcp: await api.getMcpState() })
    } catch {
      /* covered by refresh */
    }
  },

  create: async (body) => {
    const { token, secret } = await api.createAutomationToken(body)
    set({ tokens: [token, ...get().tokens] })
    await get().refreshMcp()
    return secret
  },

  update: async (id, body) => {
    const { token } = await api.updateAutomationToken(id, body)
    set({ tokens: get().tokens.map((t) => (t.id === id ? { ...t, ...token } : t)) })
    await get().refresh()
  },

  rotate: async (id) => {
    const { token, secret } = await api.rotateAutomationToken(id)
    set({ tokens: get().tokens.map((t) => (t.id === id ? { ...t, ...token } : t)) })
    return secret
  },

  setEnabled: async (id, enabled) => {
    const { token } = await api.setAutomationTokenEnabled(id, enabled)
    set({ tokens: get().tokens.map((t) => (t.id === id ? { ...t, ...token } : t)) })
  },

  review: async (id) => {
    const { token } = await api.reviewAutomationToken(id)
    set({ tokens: get().tokens.map((t) => (t.id === id ? { ...t, ...token, ungrantedCapabilities: [] } : t)) })
  },

  revoke: async (id) => {
    await api.revokeAutomationToken(id)
    set({ tokens: get().tokens.filter((t) => t.id !== id) })
    await get().refreshMcp()
  },

  setMcp: async (body) => {
    set({ mcp: await api.setMcpState(body) })
  },
}))
