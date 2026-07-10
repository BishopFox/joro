import { create } from 'zustand'

// RelayState mirrors the backend team.relay event's `state` field.
//   connecting   — attempting to reach the team server (initial / retrying)
//   connected    — relay established
//   disconnected — team server unreachable / dropped
//   idle         — no team server configured (or user disconnected)
export type RelayState = 'connecting' | 'connected' | 'disconnected' | 'idle'

interface TeamConnectionState {
  state: RelayState
  error?: string
  httpStatus?: number
  setState: (state: RelayState, error?: string, httpStatus?: number) => void
}

// Default to 'connecting' — the indicator is hidden in solo mode anyway, and a
// non-'connected' default prevents a spurious connected→disconnected toast on
// the first event after load.
export const useTeamConnectionStore = create<TeamConnectionState>((set) => ({
  state: 'connecting',
  error: undefined,
  httpStatus: undefined,
  setState: (state, error, httpStatus) => set({ state, error, httpStatus }),
}))
