import { create } from 'zustand'
import { api, type ProjectMeta } from '../lib/api'
import { applyProjectResp } from '../lib/applyProject'

interface ProjectState {
  projects: ProjectMeta[]
  active: string
  loading: boolean
  refresh: () => Promise<void>
  // switchTo saves the outgoing project per opts (the caller decides save vs
  // discard based on the active project's autoSave pref) then loads `name` and
  // rehydrates live state.
  switchTo: (name: string, opts?: { action?: 'save' | 'discard'; saveScratchAs?: string }) => Promise<void>
  // createFromCurrent snapshots the current session under a new name (409 on collision).
  createFromCurrent: (name: string) => Promise<void>
  // createEmpty resets live state to a fresh baseline and saves it as a new project,
  // first saving the outgoing session per opts (like a switch).
  createEmpty: (name: string, opts?: { action?: 'save' | 'discard'; saveScratchAs?: string }) => Promise<void>
  remove: (name: string) => Promise<void>
  setPrefs: (name: string, prefs: { autoSave?: boolean; saveHistory?: boolean }) => Promise<void>
}

export const useProjectStore = create<ProjectState>((set, get) => ({
  projects: [],
  active: '',
  loading: false,
  refresh: async () => {
    set({ loading: true })
    try {
      const data = await api.listProjectConfigs()
      set({ projects: data.projects ?? [], active: data.active ?? '' })
    } catch {
      // proxy-only endpoint; ignore in listener/team mode
    } finally {
      set({ loading: false })
    }
  },
  switchTo: async (name, opts) => {
    const resp = await api.switchProject(name, opts)
    applyProjectResp(resp)
    await get().refresh()
  },
  createFromCurrent: async (name) => {
    const resp = await api.newProject(name, { empty: false })
    applyProjectResp(resp)
    await get().refresh()
  },
  createEmpty: async (name, opts) => {
    const resp = await api.newProject(name, { empty: true, ...(opts ?? {}) })
    applyProjectResp(resp)
    await get().refresh()
  },
  remove: async (name) => {
    await api.deleteProjectConfig(name)
    await get().refresh()
  },
  setPrefs: async (name, prefs) => {
    await api.setProjectPrefs(name, prefs)
    await get().refresh()
  },
}))
