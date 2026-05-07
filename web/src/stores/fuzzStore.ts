import { create } from 'zustand'
import { api } from '../lib/api'

export interface FuzzResult {
  index: number
  payload: string
  payloads?: Record<string, string> // Multi-position: position → payload
  statusCode: number
  size: number
  words: number
  lines: number
  durationMs: number
  url: string
  error?: string
  matched: boolean
  filtered: boolean
}

export interface FuzzResultDetail {
  index: number
  payload: string
  payloads?: Record<string, string>
  statusCode: number
  size: number
  words: number
  lines: number
  durationMs: number
  url: string
  error?: string
  hasBody: boolean
  reqRaw?: string   // base64
  respRaw?: string  // base64
}

export type FilterType = 'status' | 'size' | 'words' | 'lines' | 'regex'

export interface MatchFilterRule {
  id: string
  type: FilterType
  value: string
  enabled: boolean
}

export type FuzzStatus = 'idle' | 'running' | 'stopped' | 'completed'
export type FuzzSortColumn = 'index' | 'payload' | 'statusCode' | 'size' | 'words' | 'lines' | 'durationMs'
export type SortDir = 'asc' | 'desc'
export type AttackMode = 'spray' | 'split' | 'yolo'

export interface PositionWordlist {
  position: string
  wordlist: string
  wordlistFileName: string
}

export interface FuzzTab {
  id: string
  name: string

  // Request template
  scheme: string
  host: string
  rawReq: string

  // Wordlist (single-position)
  wordlist: string
  wordlistFileName: string

  // Multi-position wordlists
  positionWordlists: PositionWordlist[]
  attackMode: AttackMode
  selectedPositionTab: string

  // Config
  concurrency: number
  rateLimit: number
  followRedirects: boolean
  updateContentLength: boolean
  fuzzKeyword: string
  maxStoredBodies: number

  // Matchers & filters
  matchers: MatchFilterRule[]
  matcherMode: 'or' | 'and'
  filters: MatchFilterRule[]
  filterMode: 'or' | 'and'

  // Run state
  status: FuzzStatus
  campaignId: string | null
  totalPayloads: number
  completedPayloads: number
  startTime: number | null

  // Results
  results: FuzzResult[]
  selectedIndex: number | null
  sortColumn: FuzzSortColumn
  sortDir: SortDir

  // Detail panel
  selectedDetail: FuzzResultDetail | null
  selectedDetailLoading: boolean

  // UI state
  configPanelOpen: boolean
  wrapReq: boolean
  showNonPrintable: boolean
}

export const MAX_TABS = 10

interface FuzzState {
  tabs: FuzzTab[]
  activeTabId: string
  nextNum: number

  // Tab management
  addTab: (partial?: Partial<FuzzTab>) => void
  removeTab: (id: string) => void
  renameTab: (id: string, name: string) => void
  setActiveTab: (id: string) => void

  // Active-tab convenience setters
  setScheme: (v: string) => void
  setHost: (v: string) => void
  setRawReq: (v: string) => void
  setWordlist: (v: string, fileName?: string) => void
  setPositionWordlist: (position: string, wordlist: string, fileName?: string) => void
  setAttackMode: (mode: AttackMode) => void
  setSelectedPositionTab: (tab: string) => void
  syncPositionWordlists: (positions: string[]) => void
  setConcurrency: (v: number) => void
  setRateLimit: (v: number) => void
  setFollowRedirects: (v: boolean) => void
  setUpdateContentLength: (v: boolean) => void
  setFuzzKeyword: (v: string) => void
  setMaxStoredBodies: (v: number) => void

  addMatcher: (rule: MatchFilterRule) => void
  updateMatcher: (id: string, updates: Partial<MatchFilterRule>) => void
  removeMatcher: (id: string) => void
  setMatcherMode: (mode: 'or' | 'and') => void

  addFilter: (rule: MatchFilterRule) => void
  updateFilter: (id: string, updates: Partial<MatchFilterRule>) => void
  removeFilter: (id: string) => void
  setFilterMode: (mode: 'or' | 'and') => void

  setStatus: (s: FuzzStatus) => void
  setCampaignId: (id: string | null) => void
  setTotalPayloads: (n: number) => void
  setCompletedPayloads: (n: number) => void
  addResult: (r: FuzzResult) => void
  addResults: (rs: FuzzResult[]) => void
  setSelectedIndex: (i: number | null) => void
  setSort: (col: FuzzSortColumn, dir: SortDir) => void

  setSelectedDetail: (d: FuzzResultDetail | null) => void
  setSelectedDetailLoading: (v: boolean) => void

  toggleConfigPanel: () => void
  setWrapReq: (v: boolean) => void
  setShowNonPrintable: (v: boolean) => void

  reset: () => void

  // Campaign-targeted actions (for WebSocket routing)
  addResultsToCampaign: (campaignId: string, rs: FuzzResult[]) => void
  setCampaignStatus: (campaignId: string, status: FuzzStatus) => void
  setCampaignStarted: (campaignId: string, total: number) => void
}

const DEFAULT_REQ = `GET /FUZZ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Joro/1.0\r\nAccept: */*\r\n\r\n`

let nextRuleId = 1
function ruleId() { return String(nextRuleId++) }

function makeTab(id: string, name: string, partial?: Partial<FuzzTab>): FuzzTab {
  return {
    id,
    name,
    scheme: 'https',
    host: 'example.com',
    rawReq: DEFAULT_REQ,
    wordlist: '',
    wordlistFileName: '',
    positionWordlists: [],
    attackMode: 'spray',
    selectedPositionTab: '',
    concurrency: 10,
    rateLimit: 0,
    followRedirects: false,
    updateContentLength: true,
    fuzzKeyword: 'FUZZ',
    maxStoredBodies: 1000,
    matchers: [],
    matcherMode: 'or',
    filters: [{ id: ruleId(), type: 'status', value: '404', enabled: true }],
    filterMode: 'or',
    status: 'idle',
    campaignId: null,
    totalPayloads: 0,
    completedPayloads: 0,
    startTime: null,
    results: [],
    selectedIndex: null,
    sortColumn: 'index',
    sortDir: 'asc',
    selectedDetail: null,
    selectedDetailLoading: false,
    configPanelOpen: false,
    wrapReq: true,
    showNonPrintable: false,
    ...partial,
  }
}

function updateActiveTab(s: FuzzState, updates: Partial<FuzzTab>): Partial<FuzzState> {
  return {
    tabs: s.tabs.map((t) => (t.id === s.activeTabId ? { ...t, ...updates } : t)),
  }
}

function updateTabById(s: FuzzState, tabId: string, updates: Partial<FuzzTab>): Partial<FuzzState> {
  return {
    tabs: s.tabs.map((t) => (t.id === tabId ? { ...t, ...updates } : t)),
  }
}

export const useFuzzStore = create<FuzzState>((set) => ({
  tabs: [makeTab('1', '1')],
  activeTabId: '1',
  nextNum: 2,

  // Tab management
  addTab: (partial) =>
    set((s) => {
      if (s.tabs.length >= MAX_TABS) return s
      const id = String(s.nextNum)
      const tab = makeTab(id, id, partial)
      return { tabs: [...s.tabs, tab], activeTabId: id, nextNum: s.nextNum + 1 }
    }),

  removeTab: (id) =>
    set((s) => {
      if (s.tabs.length <= 1) return s
      const tab = s.tabs.find((t) => t.id === id)
      if (tab?.campaignId && tab.status === 'running') {
        api.fuzzStop(tab.campaignId).catch(() => {})
      }
      const idx = s.tabs.findIndex((t) => t.id === id)
      const newTabs = s.tabs.filter((t) => t.id !== id)
      let newActive = s.activeTabId
      if (s.activeTabId === id) {
        const nextIdx = Math.min(idx, newTabs.length - 1)
        newActive = newTabs[nextIdx].id
      }
      return { tabs: newTabs, activeTabId: newActive }
    }),

  renameTab: (id, name) =>
    set((s) => ({
      tabs: s.tabs.map((t) => (t.id === id ? { ...t, name } : t)),
    })),

  setActiveTab: (id) => set({ activeTabId: id }),

  // Active-tab convenience setters
  setScheme: (v) => set((s) => updateActiveTab(s, { scheme: v })),
  setHost: (v) => set((s) => updateActiveTab(s, { host: v })),
  setRawReq: (v) => set((s) => updateActiveTab(s, { rawReq: v })),
  setWordlist: (v, fileName) => set((s) => updateActiveTab(s, { wordlist: v, wordlistFileName: fileName || '' })),
  setPositionWordlist: (position, wordlist, fileName) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, {
      positionWordlists: tab.positionWordlists.map((pw) =>
        pw.position === position ? { ...pw, wordlist, wordlistFileName: fileName || '' } : pw
      ),
    })
  }),
  setAttackMode: (mode) => set((s) => updateActiveTab(s, { attackMode: mode })),
  setSelectedPositionTab: (tab) => set((s) => updateActiveTab(s, { selectedPositionTab: tab })),
  syncPositionWordlists: (positions) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    const existing = new Map(tab.positionWordlists.map((pw) => [pw.position, pw]))
    const updated = positions.map((pos) => existing.get(pos) || { position: pos, wordlist: '', wordlistFileName: '' })
    const selTab = positions.includes(tab.selectedPositionTab) ? tab.selectedPositionTab : (positions[0] || '')
    return updateActiveTab(s, { positionWordlists: updated, selectedPositionTab: selTab })
  }),
  setConcurrency: (v) => set((s) => updateActiveTab(s, { concurrency: v })),
  setRateLimit: (v) => set((s) => updateActiveTab(s, { rateLimit: v })),
  setFollowRedirects: (v) => set((s) => updateActiveTab(s, { followRedirects: v })),
  setUpdateContentLength: (v) => set((s) => updateActiveTab(s, { updateContentLength: v })),
  setFuzzKeyword: (v) => set((s) => updateActiveTab(s, { fuzzKeyword: v })),
  setMaxStoredBodies: (v) => set((s) => updateActiveTab(s, { maxStoredBodies: v })),

  addMatcher: (rule) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, { matchers: [...tab.matchers, rule] })
  }),
  updateMatcher: (id, updates) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, { matchers: tab.matchers.map((m) => m.id === id ? { ...m, ...updates } : m) })
  }),
  removeMatcher: (id) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, { matchers: tab.matchers.filter((m) => m.id !== id) })
  }),
  setMatcherMode: (mode) => set((s) => updateActiveTab(s, { matcherMode: mode })),

  addFilter: (rule) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, { filters: [...tab.filters, rule] })
  }),
  updateFilter: (id, updates) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, { filters: tab.filters.map((f) => f.id === id ? { ...f, ...updates } : f) })
  }),
  removeFilter: (id) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, { filters: tab.filters.filter((f) => f.id !== id) })
  }),
  setFilterMode: (mode) => set((s) => updateActiveTab(s, { filterMode: mode })),

  setStatus: (s) => set((st) => updateActiveTab(st, { status: s })),
  setCampaignId: (id) => set((s) => updateActiveTab(s, { campaignId: id })),
  setTotalPayloads: (n) => set((s) => updateActiveTab(s, { totalPayloads: n })),
  setCompletedPayloads: (n) => set((s) => updateActiveTab(s, { completedPayloads: n })),
  addResult: (r) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, { results: [...tab.results, r], completedPayloads: tab.completedPayloads + 1 })
  }),
  addResults: (rs) => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, { results: [...tab.results, ...rs], completedPayloads: tab.completedPayloads + rs.length })
  }),
  setSelectedIndex: (i) => set((s) => updateActiveTab(s, { selectedIndex: i, selectedDetail: null, selectedDetailLoading: false })),
  setSort: (col, dir) => set((s) => updateActiveTab(s, { sortColumn: col, sortDir: dir })),

  setSelectedDetail: (d) => set((s) => updateActiveTab(s, { selectedDetail: d, selectedDetailLoading: false })),
  setSelectedDetailLoading: (v) => set((s) => updateActiveTab(s, { selectedDetailLoading: v })),

  toggleConfigPanel: () => set((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId)
    if (!tab) return s
    return updateActiveTab(s, { configPanelOpen: !tab.configPanelOpen })
  }),
  setWrapReq: (v) => set((s) => updateActiveTab(s, { wrapReq: v })),
  setShowNonPrintable: (v) => set((s) => updateActiveTab(s, { showNonPrintable: v })),

  reset: () => set((s) => updateActiveTab(s, {
    status: 'idle',
    campaignId: null,
    totalPayloads: 0,
    completedPayloads: 0,
    startTime: null,
    results: [],
    selectedIndex: null,
    selectedDetail: null,
    selectedDetailLoading: false,
  })),

  // Campaign-targeted actions (for WebSocket routing)
  addResultsToCampaign: (campaignId, rs) => set((s) => {
    const tab = s.tabs.find((t) => t.campaignId === campaignId)
    if (!tab) return s
    return updateTabById(s, tab.id, {
      results: [...tab.results, ...rs],
      completedPayloads: tab.completedPayloads + rs.length,
    })
  }),

  setCampaignStatus: (campaignId, status) => set((s) => {
    const tab = s.tabs.find((t) => t.campaignId === campaignId)
    if (!tab) return s
    return updateTabById(s, tab.id, { status })
  }),

  setCampaignStarted: (campaignId, total) => set((s) => {
    const tab = s.tabs.find((t) => t.campaignId === campaignId)
    if (!tab) return s
    return updateTabById(s, tab.id, { campaignId, totalPayloads: total, status: 'running' })
  }),
}))
