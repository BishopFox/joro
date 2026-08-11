import { create } from 'zustand'
import type { CallbackInteraction, CallbackToken } from './callbackStore'
import type { XSSFire, XSSProbe } from './xssHunterStore'
import type { SliverSession } from '../components/NetworkGraph'
import type { AutomationAudit } from '../lib/api'

// dashboardDataStore holds the data polled by useDashboardPolling on behalf of
// the dashboard widgets. It is a store rather than a React context so widgets
// subscribe with narrow selectors — a context value would re-render every
// widget (including the NetworkGraph SVG) on each 5s tick.
//
// Data already owned elsewhere is NOT duplicated here: flagged requests live in
// teamFlaggedStore (WS-fed), findings live in detectStore.

export interface HealthInfo {
  proxyPort: number
  uiPort: number
  bindAddr: string
  caPresent: boolean
  browserAvailable: boolean
  browserName: string
  requestCount: number
  activeProject: string
}

export interface SliverInfo {
  connected: boolean
  lhost: string
  lport: number
  sessions: SliverSession[]
  beacons: SliverSession[]
}

export interface MythicInfo {
  connected: boolean
  url: string
  callbacks: SliverSession[]
}

interface CallbackData {
  interactions: CallbackInteraction[]
  tokens: CallbackToken[]
  fires: XSSFire[]
  probes: XSSProbe[]
}

interface DashboardDataState extends CallbackData {
  mode: string
  localHost: { hostname: string; ip: string } | null
  sliver: SliverInfo
  mythic: MythicInfo
  health: HealthInfo | null
  automationActivity: AutomationAudit | null

  setMode: (mode: string) => void
  setLocalHost: (h: { hostname: string; ip: string } | null) => void
  setCallbackData: (patch: Partial<CallbackData>) => void
  setSliver: (s: SliverInfo) => void
  setMythic: (m: Partial<MythicInfo>) => void
  setHealth: (h: HealthInfo) => void
  setAutomationActivity: (a: AutomationAudit) => void
}

const emptySliver: SliverInfo = {
  connected: false,
  lhost: '',
  lport: 0,
  sessions: [],
  beacons: [],
}

const emptyMythic: MythicInfo = { connected: false, url: '', callbacks: [] }

export const useDashboardDataStore = create<DashboardDataState>((set) => ({
  mode: 'proxy',
  localHost: null,
  interactions: [],
  tokens: [],
  fires: [],
  probes: [],
  sliver: emptySliver,
  mythic: emptyMythic,
  health: null,
  automationActivity: null,

  setMode: (mode) => set({ mode }),
  setLocalHost: (localHost) => set({ localHost }),
  setCallbackData: (patch) => set(patch),
  setSliver: (sliver) => set({ sliver }),
  setMythic: (m) => set((s) => ({ mythic: { ...s.mythic, ...m } })),
  setHealth: (health) => set({ health }),
  setAutomationActivity: (automationActivity) => set({ automationActivity }),
}))
