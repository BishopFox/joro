import { create } from 'zustand'

const DEFAULT_REQ = `GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Joro/1.0\r\nAccept: */*\r\n\r\n`

export interface HistoryEntry {
  scheme: string
  host: string
  rawReq: string
  response: string
  status: number | null
  duration: number | null
}

export interface ManipulateTab {
  id: string
  name: string
  scheme: string
  host: string
  rawReq: string
  response: string
  status: number | null
  duration: number | null
  sending: boolean
  error: string
  wrapReq: boolean
  wrapResp: boolean
  updateContentLength: boolean
  showNonPrintable: boolean
  followRedirects: boolean
  decompress: boolean
  history: HistoryEntry[]
  historyIndex: number
}

interface ManipulateState {
  tabs: ManipulateTab[]
  activeTabId: string
  nextNum: number
  addTab: (partial?: Partial<ManipulateTab>) => void
  removeTab: (id: string) => void
  renameTab: (id: string, name: string) => void
  updateTab: (id: string, updates: Partial<ManipulateTab>) => void
  setActiveTab: (id: string) => void
  pushHistory: (id: string, entry: HistoryEntry) => void
  goBack: (id: string) => void
  goForward: (id: string) => void
}

function makeTab(id: string, name: string, partial?: Partial<ManipulateTab>): ManipulateTab {
  return {
    id,
    name,
    scheme: 'https',
    host: 'example.com',
    rawReq: DEFAULT_REQ,
    response: '',
    status: null,
    duration: null,
    sending: false,
    error: '',
    wrapReq: true,
    wrapResp: true,
    updateContentLength: true,
    showNonPrintable: false,
    followRedirects: false,
    decompress: true,
    history: [],
    historyIndex: -1,
    ...partial,
  }
}

export const useManipulateStore = create<ManipulateState>((set) => ({
  tabs: [makeTab('1', '1')],
  activeTabId: '1',
  nextNum: 2,

  addTab: (partial) =>
    set((s) => {
      const id = String(s.nextNum)
      const tab = makeTab(id, id, partial)
      return { tabs: [...s.tabs, tab], activeTabId: id, nextNum: s.nextNum + 1 }
    }),

  removeTab: (id) =>
    set((s) => {
      if (s.tabs.length <= 1) return s
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

  updateTab: (id, updates) =>
    set((s) => ({
      tabs: s.tabs.map((t) => (t.id === id ? { ...t, ...updates } : t)),
    })),

  setActiveTab: (id) => set({ activeTabId: id }),

  pushHistory: (id, entry) =>
    set((s) => ({
      tabs: s.tabs.map((t) => {
        if (t.id !== id) return t
        // If we're in the middle of history, truncate forward entries
        const history = t.historyIndex >= 0
          ? [...t.history.slice(0, t.historyIndex + 1), entry]
          : [...t.history, entry]
        return { ...t, history, historyIndex: history.length - 1 }
      }),
    })),

  goBack: (id) =>
    set((s) => ({
      tabs: s.tabs.map((t) => {
        if (t.id !== id || t.history.length === 0) return t
        const newIndex = t.historyIndex <= 0 ? 0 : t.historyIndex - 1
        const entry = t.history[newIndex]
        return { ...t, historyIndex: newIndex, scheme: entry.scheme, host: entry.host, rawReq: entry.rawReq, response: entry.response, status: entry.status, duration: entry.duration, error: '' }
      }),
    })),

  goForward: (id) =>
    set((s) => ({
      tabs: s.tabs.map((t) => {
        if (t.id !== id || t.historyIndex >= t.history.length - 1) return t
        const newIndex = t.historyIndex + 1
        const entry = t.history[newIndex]
        return { ...t, historyIndex: newIndex, scheme: entry.scheme, host: entry.host, rawReq: entry.rawReq, response: entry.response, status: entry.status, duration: entry.duration, error: '' }
      }),
    })),
}))
