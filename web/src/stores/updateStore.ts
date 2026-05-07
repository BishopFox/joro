import { create } from 'zustand'
import type { VersionInfo } from '../lib/api'

interface UpdateState {
  info: VersionInfo | null
  dismissed: boolean
  updating: boolean
  status: string
  setInfo: (info: VersionInfo) => void
  dismiss: () => void
  setUpdating: (b: boolean) => void
  setStatus: (s: string) => void
}

export const useUpdateStore = create<UpdateState>((set) => ({
  info: null,
  dismissed: false,
  updating: false,
  status: '',
  setInfo: (info) => set((state) => {
    const isNew = info.updateAvailable && (!state.info || state.info.latestVersion !== info.latestVersion)
    return { info, dismissed: isNew ? false : state.dismissed }
  }),
  dismiss: () => set({ dismissed: true }),
  setUpdating: (updating) => set({ updating }),
  setStatus: (status) => set({ status, updating: true }),
}))
