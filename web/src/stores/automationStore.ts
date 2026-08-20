import { create } from 'zustand'
import {
  api,
  type AutomationBudget,
  type AutomationPolicy,
  type AutomationProfile,
  type AutomationSummary,
  type AutomationToken,
  type AutomationTokenInput,
  type Capability,
  type McpState,
} from '../lib/api'

interface AutomationState {
  tokens: AutomationToken[]
  capabilities: Capability[]
  /** Installed automations. Held here rather than in the panel that lists them because
   *  four surfaces read it: the Automations table, the Lenses tab, History's context
   *  menu, and every response viewer. */
  scripts: AutomationSummary[]
  /** Trigger names the server accepts, for the editor's checkboxes. */
  scriptTriggers: string[]
  /** Why the automation list is empty: null when it loaded, otherwise the server's
   *  explanation, which names --no-automation or --automation-scripting. */
  scriptsUnavailable: string | null
  /** Server-declared class order. The picker groups by it so the write-heavy
   *  classes render last, rather than falling out of alphabetical-by-ID. */
  classes: string[]
  profiles: AutomationProfile[]
  fingerprint: string
  mcp: McpState | null
  /** The run budget: what the operator set, what a run gets, and the shipped defaults,
   *  ceilings and rationale the server serves alongside it. Held here rather than in the
   *  panel that edits it because the automation editor shows the same numbers as its
   *  placeholders. */
  budget: AutomationBudget | null
  loading: boolean
  /** Null until the first fetch resolves; false means automation is compiled in
   *  but the endpoints 404 (--no-automation), which the UI renders as an
   *  explanation rather than an error. */
  available: boolean | null

  refresh: () => Promise<void>
  refreshMcp: () => Promise<void>
  refreshBudget: () => Promise<void>
  setBudget: (policy: AutomationPolicy) => Promise<void>
  refreshScripts: () => Promise<void>
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
  scripts: [],
  scriptTriggers: [],
  scriptsUnavailable: null,
  classes: [],
  profiles: [],
  fingerprint: '',
  mcp: null,
  budget: null,
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

  refreshBudget: async () => {
    try {
      set({ budget: await api.getAutomationLimits(), scriptsUnavailable: null })
    } catch (e) {
      // This endpoint 404s through the same guard as the automation list, with the same
      // two messages naming --no-automation or --automation-scripting, so it feeds the
      // one field rather than a second copy of the same state.
      set({ budget: null, scriptsUnavailable: String(e instanceof Error ? e.message : e) })
    }
  },

  /** Throws on a rejected value so the caller can surface which field was refused —
   *  the server names the field and its ceiling rather than silently clamping. */
  setBudget: async (policy) => {
    set({ budget: await api.setAutomationLimits(policy) })
  },

  refreshScripts: async () => {
    try {
      const d = await api.listScripts()
      set({
        scripts: d.scripts ?? [],
        scriptTriggers: d.triggers ?? [],
        scriptsUnavailable: null,
      })
    } catch (e) {
      // Scripting can be off while automation is on, so the message is kept rather
      // than flattened to a boolean: it names which flag is missing.
      set({ scripts: [], scriptsUnavailable: String(e instanceof Error ? e.message : e) })
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
