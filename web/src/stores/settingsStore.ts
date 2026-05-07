import { create } from 'zustand'
import type { ScopeRule } from '../lib/api'

export interface Settings {
  proxyPort: number
  uiPort: number
  interceptEnabled: boolean
  interceptTimeout: number
  listenerUrl: string
  http2Enabled: boolean
  keepAliveEnabled: boolean
  socksHost: string
  socksPort: number
  socksUsername: string
  socksPassword: string
  socksDns: boolean
  scopeEnabled: boolean
  scopeRules: ScopeRule[]
  teamToken: string
  teamNickname: string
  maxRequests: number
  disableUpdateChecks: boolean
}

interface SettingsState {
  settings: Settings | null
  setSettings: (s: Settings) => void
}

export const useSettingsStore = create<SettingsState>((set) => ({
  settings: null,
  setSettings: (settings) => set({ settings }),
}))
