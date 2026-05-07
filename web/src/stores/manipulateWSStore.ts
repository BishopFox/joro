import { create } from 'zustand'

export type WSOpcode = 'text' | 'binary' | 'continuation' | 'ping' | 'pong' | 'close'
export type WSDirection = 'sent' | 'received'
export type WSTabState = 'disconnected' | 'connecting' | 'connected' | 'closing' | 'error'

const DEFAULT_UPGRADE = `GET / HTTP/1.1\r
Host: example.com\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Version: 13\r
Origin: https://example.com\r
User-Agent: Joro/1.0\r
\r
`

const MAX_FRAMES_PER_TAB = 1000

export interface WSFrameEntry {
  id: string
  direction: WSDirection
  opcode: WSOpcode
  payload: string // base64-encoded
  isText: boolean
  size: number
  ts: string
}

export interface ManipulateWSTab {
  id: string
  name: string
  url: string
  scheme: 'wss' | 'ws'
  host: string
  rawUpgrade: string
  upgradeResponse: string
  sessionId: string | null
  state: WSTabState
  error: string
  frames: WSFrameEntry[]
  sendOpcode: WSOpcode
  sendPayload: string
  selectedFrameId: string | null
  wrapUpgrade: boolean
  wrapResponse: boolean
  wrapPayload: boolean
}

interface ManipulateWSState {
  tabs: ManipulateWSTab[]
  activeTabId: string
  nextNum: number
  addTab: (partial?: Partial<ManipulateWSTab>) => string
  removeTab: (id: string) => void
  renameTab: (id: string, name: string) => void
  updateTab: (id: string, updates: Partial<ManipulateWSTab>) => void
  setActiveTab: (id: string) => void
  appendFrame: (tabId: string, frame: WSFrameEntry) => void
  appendFrameBySession: (sessionId: string, frame: WSFrameEntry) => void
  markSessionClosed: (sessionId: string, reason: string) => void
  clearFrames: (tabId: string) => void
}

function randomId(): string {
  return Math.random().toString(36).slice(2, 10)
}

function makeTab(id: string, name: string, partial?: Partial<ManipulateWSTab>): ManipulateWSTab {
  return {
    id,
    name,
    url: 'wss://example.com/',
    scheme: 'wss',
    host: 'example.com',
    rawUpgrade: DEFAULT_UPGRADE,
    upgradeResponse: '',
    sessionId: null,
    state: 'disconnected',
    error: '',
    frames: [],
    sendOpcode: 'text',
    sendPayload: '',
    selectedFrameId: null,
    wrapUpgrade: true,
    wrapResponse: true,
    wrapPayload: true,
    ...partial,
  }
}

export const useManipulateWSStore = create<ManipulateWSState>((set) => ({
  tabs: [makeTab('1', '1')],
  activeTabId: '1',
  nextNum: 2,

  addTab: (partial) => {
    let newId = ''
    set((s) => {
      const id = String(s.nextNum)
      newId = id
      return {
        tabs: [...s.tabs, makeTab(id, id, partial)],
        activeTabId: id,
        nextNum: s.nextNum + 1,
      }
    })
    return newId
  },

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

  appendFrame: (tabId, frame) =>
    set((s) => ({
      tabs: s.tabs.map((t) => {
        if (t.id !== tabId) return t
        const frames = [...t.frames, frame]
        if (frames.length > MAX_FRAMES_PER_TAB) {
          frames.splice(0, frames.length - MAX_FRAMES_PER_TAB)
        }
        return { ...t, frames }
      }),
    })),

  appendFrameBySession: (sessionId, frame) =>
    set((s) => ({
      tabs: s.tabs.map((t) => {
        if (t.sessionId !== sessionId) return t
        const frames = [...t.frames, frame]
        if (frames.length > MAX_FRAMES_PER_TAB) {
          frames.splice(0, frames.length - MAX_FRAMES_PER_TAB)
        }
        return { ...t, frames }
      }),
    })),

  markSessionClosed: (sessionId, reason) =>
    set((s) => ({
      tabs: s.tabs.map((t) => {
        if (t.sessionId !== sessionId) return t
        return {
          ...t,
          state: 'disconnected' as const,
          sessionId: null,
          error: reason && reason !== 'client disconnected' ? `Closed: ${reason}` : '',
        }
      }),
    })),

  clearFrames: (tabId) =>
    set((s) => ({
      tabs: s.tabs.map((t) => (t.id === tabId ? { ...t, frames: [], selectedFrameId: null } : t)),
    })),
}))

export { DEFAULT_UPGRADE, randomId }
