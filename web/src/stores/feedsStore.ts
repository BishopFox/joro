import { create } from 'zustand'
import { api, ApiError } from '../lib/api'
import {
  DEFAULT_FEED_SETTINGS,
  EMPTY_FEED_SNAPSHOT,
  type FeedSettings,
  type FeedSnapshot,
} from '../lib/feedTypes'

// Threat-intel feed state. Push-driven, like techStore: it loads once and ws.ts folds in
// `feeds.updated` by re-fetching the authoritative snapshot (a map row is a server-side
// aggregate, so the client reloads rather than merging). It never joins the 5s dashboard
// poll loop — feeds refresh every 15 min server-side.
//
// `available` is false when the instance returns 404 (started with --no-feeds, or feeds.json
// could not be read): the ticker and feed widgets then render nothing rather than an error.

interface FeedsState {
  available: boolean
  loaded: boolean
  loading: boolean
  saving: boolean
  refreshing: boolean
  settings: FeedSettings
  snapshot: FeedSnapshot

  /** Loads settings + snapshot once (no-op if already loaded/loading). */
  ensureLoaded: () => Promise<void>
  /** Re-fetches the authoritative snapshot + settings (on ws feeds.updated). */
  reload: () => Promise<void>
  setEnabled: (enabled: boolean) => Promise<void>
  saveSettings: (settings: FeedSettings) => Promise<void>
  refreshNow: () => Promise<void>
}

export const useFeedsStore = create<FeedsState>((set, get) => ({
  available: true,
  loaded: false,
  loading: false,
  saving: false,
  refreshing: false,
  settings: DEFAULT_FEED_SETTINGS,
  snapshot: EMPTY_FEED_SNAPSHOT,

  ensureLoaded: async () => {
    const st = get()
    if (st.loaded || st.loading) return
    set({ loading: true })
    try {
      const res = await api.getFeeds()
      set({ available: true, settings: res.settings, snapshot: res.snapshot, loaded: true })
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        set({ available: false, loaded: true })
      } else {
        // Transient failure (e.g. outside proxy mode): leave defaults, mark loaded so
        // the UI stops showing a spinner. A ws event or a manual retry can refill it.
        set({ loaded: true })
      }
    } finally {
      set({ loading: false })
    }
  },

  reload: async () => {
    if (!get().available) return
    try {
      const res = await api.getFeeds()
      set({ settings: res.settings, snapshot: res.snapshot })
    } catch {
      // keep prior state on a transient failure
    }
  },

  setEnabled: async (enabled) => {
    await get().saveSettings({ ...get().settings, enabled })
  },

  saveSettings: async (settings) => {
    const prev = get().settings
    set({ saving: true, settings }) // optimistic
    try {
      const saved = await api.setFeedsSettings(settings)
      set({ settings: saved })
    } catch {
      set({ settings: prev }) // roll back
    } finally {
      set({ saving: false })
    }
  },

  refreshNow: async () => {
    if (get().refreshing) return
    set({ refreshing: true })
    try {
      await api.refreshFeeds()
      // The server broadcasts feeds.updated when the refresh completes; ws.ts reloads.
    } catch {
      // ignore (debounced or disabled)
    } finally {
      set({ refreshing: false })
    }
  },
}))
