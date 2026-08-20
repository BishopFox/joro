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
  // remove deletes a project's files and its testing-browser profile, resolving
  // to whether it was the active one. Live state is deliberately left alone, so
  // deleting the active project leaves the session loaded but unnamed.
  remove: (name: string) => Promise<boolean>
  setPrefs: (name: string, prefs: { autoSave?: boolean; saveHistory?: boolean }) => Promise<void>
  // saveActive snapshots the current live state into the active project in place
  // (unconditional server-side save, independent of the autoSave pref). No-op if
  // there is no named active project.
  saveActive: () => Promise<void>
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
    const resp = await api.deleteProjectConfig(name)
    // No applyProjectResp here, unlike every sibling action: a delete changes no
    // live state, and rehydrating would clear the history and findings the
    // operator still has loaded. refresh() alone picks up the cleared name.
    await get().refresh()
    return resp.wasActive
  },
  setPrefs: async (name, prefs) => {
    await api.setProjectPrefs(name, prefs)
    await get().refresh()
  },
  saveActive: async () => {
    const name = get().active
    if (!name) return
    await api.saveProjectConfig(name)
    await get().refresh()
  },
}))
