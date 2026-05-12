import { create } from 'zustand'

export interface XSSProbe {
  id: string
  name: string
  probeId: string
  collectPages: string
  chainloadUri: string
  createdAt: string
  fireCount: number
}

export interface XSSFire {
  id: string
  probeId: string
  probeToken: string
  url: string
  origin: string
  referrer: string
  userAgent: string
  cookies: string
  pageTitle: string
  dom?: string
  screenshot?: string
  pageText?: string
  sourceIp: string
  inIframe: boolean
  browserTime: string
  injectionKey?: string
  firedAt: string
}

export interface PayloadVariant {
  name: string
  payload: string
  injectionKey: string
}

export interface CollectedPageSummary {
  id: string
  fireId: string
  url: string
  collectedAt: string
}

export interface CollectedPage extends CollectedPageSummary {
  html?: string
}

export interface XSSConfig {
  collectPages: string[]
  chainloadUri: string
}

interface XSSHunterState {
  probes: XSSProbe[]
  fires: XSSFire[]
  firesTotal: number
  selectedProbe: string | null
  selectedFire: XSSFire | null
  payloads: PayloadVariant[]
  setProbes: (probes: XSSProbe[]) => void
  addProbe: (probe: XSSProbe) => void
  removeProbe: (id: string) => void
  setFires: (items: XSSFire[], total: number) => void
  addFire: (item: XSSFire) => void
  clearFires: () => void
  setSelectedProbe: (id: string | null) => void
  setSelectedFire: (fire: XSSFire | null) => void
  setPayloads: (payloads: PayloadVariant[]) => void
}

export const useXSSHunterStore = create<XSSHunterState>((set) => ({
  probes: [],
  fires: [],
  firesTotal: 0,
  selectedProbe: null,
  selectedFire: null,
  payloads: [],

  setProbes: (probes) => set({ probes }),
  addProbe: (probe) => set((s) => ({ probes: [probe, ...s.probes] })),
  removeProbe: (id) =>
    set((s) => ({
      probes: s.probes.filter((p) => p.id !== id),
      selectedProbe: s.selectedProbe === id ? null : s.selectedProbe,
      payloads: s.selectedProbe === id ? [] : s.payloads,
    })),
  setFires: (items, total) => set({ fires: items, firesTotal: total }),
  addFire: (item) =>
    set((s) => {
      const probes = s.probes.map((p) =>
        p.id === item.probeId ? { ...p, fireCount: p.fireCount + 1 } : p
      )
      return {
        fires: [item, ...s.fires].slice(0, 500),
        firesTotal: s.firesTotal + 1,
        probes,
      }
    }),
  clearFires: () => set({ fires: [], firesTotal: 0, selectedFire: null }),
  setSelectedProbe: (selectedProbe) => set({ selectedProbe }),
  setSelectedFire: (selectedFire) => set({ selectedFire }),
  setPayloads: (payloads) => set({ payloads }),
}))
