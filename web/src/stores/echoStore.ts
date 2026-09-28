import { create } from 'zustand'
import type {
  EchoConfig,
  EchoEntry,
  EchoFilter,
  EchoScanStatus,
  EchoSummary,
} from '../lib/echoTypes'
import { EMPTY_ECHO_FILTER } from '../lib/echoTypes'

const EMPTY_SUMMARY: EchoSummary = {
  params: 0,
  hosts: 0,
  reflections: 0,
  breakouts: 0,
  scanned: 0,
  byContext: {},
  byTransform: {},
}

const DEFAULT_CONFIG: EchoConfig = {
  enabled: false,
  scopeOnly: true,
  maxBodyScanBytes: 512 * 1024,
  maxRequestBodyScanBytes: 256 * 1024,
  minValueLen: 6,
  maxValuesPerRequest: 512,
  maxReflectionsPerRequest: 200,
  transformDepth: 2,
  base64: true,
  scanHeaders: false,
}

interface EchoStoreState {
  enabled: boolean
  config: EchoConfig
  summary: EchoSummary
  hosts: string[]
  scan: EchoScanStatus

  items: EchoEntry[]
  total: number
  loading: boolean
  selected: EchoEntry | null
  filter: EchoFilter
  /**
   * Bumped to force the page to reload its list. Live events carry only counts,
   * so a new reflection cannot be merged into a row client-side the way a
   * detect finding can — the row is an aggregate the server owns.
   */
  reloadCounter: number

  setEnabled: (v: boolean) => void
  setConfig: (c: EchoConfig) => void
  setSummary: (s: EchoSummary) => void
  setHosts: (h: string[]) => void
  setScan: (s: EchoScanStatus) => void
  setItems: (items: EchoEntry[], total: number) => void
  setLoading: (v: boolean) => void
  setSelected: (e: EchoEntry | null) => void
  setFilter: (f: Partial<EchoFilter>) => void
  resetFilter: () => void
  invalidate: () => void
  clearAll: () => void
}

export const useEchoStore = create<EchoStoreState>((set) => ({
  enabled: false,
  config: DEFAULT_CONFIG,
  summary: EMPTY_SUMMARY,
  hosts: [],
  scan: { running: false, scanned: 0, total: 0 },

  items: [],
  total: 0,
  loading: false,
  selected: null,
  filter: EMPTY_ECHO_FILTER,
  reloadCounter: 0,

  setEnabled: (v) => set({ enabled: v }),
  setConfig: (c) => set({ config: c, enabled: c.enabled }),
  setSummary: (s) => set({ summary: s }),
  setHosts: (h) => set({ hosts: h }),
  setScan: (s) => set({ scan: s }),
  setItems: (items, total) => set({ items, total }),
  setLoading: (v) => set({ loading: v }),
  setSelected: (e) => set({ selected: e }),
  setFilter: (f) =>
    set((st) => ({ filter: { ...st.filter, ...f }, selected: null })),
  resetFilter: () => set({ filter: EMPTY_ECHO_FILTER, selected: null }),
  invalidate: () => set((st) => ({ reloadCounter: st.reloadCounter + 1 })),
  clearAll: () =>
    set({
      items: [],
      total: 0,
      selected: null,
      summary: EMPTY_SUMMARY,
      hosts: [],
      filter: EMPTY_ECHO_FILTER,
      scan: { running: false, scanned: 0, total: 0 },
    }),
}))

/** buildEchoQuery turns the filter into the server's query parameters. */
export function buildEchoQuery(f: EchoFilter): Record<string, string | number> {
  const q: Record<string, string | number> = {}
  if (f.host) q.host = f.host
  if (f.search) q.search = f.search
  if (f.sources.length) q.source = f.sources.join(',')
  if (f.contexts.length) q.context = f.contexts.join(',')
  if (f.transforms.length) q.transform = f.transforms.join(',')
  if (f.breakoutOnly) q.breakout = 'true'
  return q
}
