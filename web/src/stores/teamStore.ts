import { create } from 'zustand'

export interface ChatMessage {
  id: string
  author: string
  text: string
  refId?: string
  refType?: string // "flagged" | "collab" | "config"
  createdAt: string
}

interface TeamState {
  messages: ChatMessage[]
  activeUsers: string[]
  addMessage: (msg: ChatMessage) => void
  setActiveUsers: (users: string[]) => void
  handleNicknameChange: (oldNick: string, newNick: string) => void
}

const MAX_MESSAGES = 500

function sysMessage(kind: 'join' | 'leave' | 'rename', subject: string, text: string): ChatMessage {
  return {
    id: `sys-${kind}-${subject}-${Date.now()}`,
    author: '*',
    text,
    createdAt: new Date().toISOString(),
  }
}

function appendBounded(existing: ChatMessage[], incoming: ChatMessage[]): ChatMessage[] {
  if (incoming.length === 0) return existing
  const combined = [...existing, ...incoming]
  return combined.length > MAX_MESSAGES ? combined.slice(-MAX_MESSAGES) : combined
}

export const useTeamStore = create<TeamState>((set) => ({
  messages: [],
  activeUsers: [],
  addMessage: (msg) =>
    set((state) => ({
      messages: appendBounded(state.messages, [msg]),
    })),
  setActiveUsers: (users) =>
    set((state) => {
      // Skip diffing on the very first presence event (initial load)
      if (state.activeUsers.length === 0) {
        return { activeUsers: users }
      }

      const prev = new Set(state.activeUsers)
      const next = new Set(users)
      const newMessages: ChatMessage[] = []

      for (const u of users) {
        if (!prev.has(u)) {
          newMessages.push(sysMessage('join', u, `${u} connected!`))
        }
      }
      for (const u of state.activeUsers) {
        if (!next.has(u)) {
          newMessages.push(sysMessage('leave', u, `${u} disconnected`))
        }
      }

      return {
        activeUsers: users,
        messages: appendBounded(state.messages, newMessages),
      }
    }),
  handleNicknameChange: (oldNick, newNick) =>
    set((state) => {
      if (oldNick === newNick) return state
      return {
        activeUsers: state.activeUsers.map((u) => (u === oldNick ? newNick : u)),
        messages: appendBounded(state.messages, [
          sysMessage('rename', oldNick, `${oldNick} changed nickname to ${newNick}`),
        ]),
      }
    }),
}))
