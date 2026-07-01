import { create } from 'zustand'

export interface ChatMessage {
  id: string
  author: string
  text: string
  refId?: string
  refType?: string // "flagged" | "collab" | "config"
  createdAt: string
}

export interface ActiveUser {
  nickname: string
  status: string // online | away | dnd
  projectId: string // "" unless shared
}

interface TeamState {
  messages: ChatMessage[]
  activeUsers: ActiveUser[]
  setMessages: (msgs: ChatMessage[]) => void
  addMessage: (msg: ChatMessage) => void
  setActiveUsers: (users: ActiveUser[]) => void
  handleNicknameChange: (oldNick: string, newNick: string) => void
}

const MAX_MESSAGES = 500

function appendBounded(existing: ChatMessage[], incoming: ChatMessage[]): ChatMessage[] {
  if (incoming.length === 0) return existing
  const combined = [...existing, ...incoming]
  return combined.length > MAX_MESSAGES ? combined.slice(-MAX_MESSAGES) : combined
}

export const useTeamStore = create<TeamState>((set) => ({
  messages: [],
  activeUsers: [],
  // Replace the whole log (used to load persisted history on join).
  setMessages: (msgs) =>
    set({ messages: msgs.length > MAX_MESSAGES ? msgs.slice(-MAX_MESSAGES) : msgs }),
  // Append a live message, skipping duplicates (history load + WS echo overlap).
  addMessage: (msg) =>
    set((state) => {
      if (state.messages.some((m) => m.id === msg.id)) return state
      return { messages: appendBounded(state.messages, [msg]) }
    }),
  // Presence drives the active-users sidebar only; connect/disconnect log lines
  // are now persisted server-side as system chat messages.
  setActiveUsers: (users) => set({ activeUsers: users }),
  // Update the sidebar on rename; the log line is persisted server-side.
  handleNicknameChange: (oldNick, newNick) =>
    set((state) => {
      if (oldNick === newNick) return state
      return {
        activeUsers: state.activeUsers.map((u) =>
          u.nickname === oldNick ? { ...u, nickname: newNick } : u
        ),
      }
    }),
}))
