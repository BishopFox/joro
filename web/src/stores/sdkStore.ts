import { create } from 'zustand'
import { api, type SdkMethod } from '../lib/api'

/**
 * The SDK surface: every joro.* method, joined with the capability behind it.
 *
 * Held here because three surfaces read it — the reference beside the code editor, the
 * canvas palette, and every call node's argument ports, which are generated from each
 * method's JSON Schema rather than listed in the frontend. That generation is the reason
 * this is fetched at all: a capability that gains an argument gains a port with no change
 * here, the same way the trigger canvas builds its field selects from trigger.Fields().
 *
 * Thin on purpose, following triggerStore: the payload plus a refetch. The bundle is a
 * constant of the binary, so there is nothing to invalidate within a session.
 */
interface SdkState {
  methods: SdkMethod[]
  storage: { js: string; description: string }[]
  globals: { js: string; description: string }[]
  bundle: string
  loaded: boolean
  /** Why the surface is empty: null when it loaded, otherwise the server's explanation.
   *  Absent scripting is the usual reason, and the message names the flag. */
  unavailable: string | null

  refresh: () => Promise<void>
}

export const useSdkStore = create<SdkState>((set, get) => ({
  methods: [],
  storage: [],
  globals: [],
  bundle: '',
  loaded: false,
  unavailable: null,

  refresh: async () => {
    // Fetched once. Re-reading it on every canvas mount would cost a request per selection
    // in the rail for a payload that cannot change while Joro is running.
    if (get().loaded) return
    try {
      const d = await api.getScriptSdk()
      set({
        methods: d.methods ?? [],
        storage: d.storage ?? [],
        globals: d.globals ?? [],
        bundle: d.bundle ?? '',
        loaded: true,
        unavailable: null,
      })
    } catch (e) {
      set({ methods: [], loaded: true, unavailable: String(e instanceof Error ? e.message : e) })
    }
  },
}))
