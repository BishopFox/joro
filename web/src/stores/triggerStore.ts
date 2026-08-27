import { create } from 'zustand'
import { api, type Trigger, type TriggerFieldSpec } from '../lib/api'

/**
 * The trigger catalog: Joro's own events plus the operator's custom triggers.
 *
 * Held here rather than in the panel that lists them because two surfaces read it — the
 * Triggers tab, and the automation editor's sidebar, which offers both kinds as things to
 * point an automation at.
 *
 * Thin on purpose, following detectStore: the list plus a refetch, with create, update and
 * delete called on `api` directly and followed by a reload. A trigger is edited rarely and
 * read by the dispatcher, so an optimistic local copy would buy nothing and could disagree
 * with what the server actually compiled.
 */
interface TriggerState {
  triggers: Trigger[]
  /** Which fields each event carries. An event absent from the map carries nothing to
   *  test, which is every event the operator starts by hand. */
  fields: Record<string, TriggerFieldSpec[]>
  events: string[]
  valueLen: number
  loaded: boolean
  /** Why the list is empty: null when it loaded, otherwise the server's explanation. */
  unavailable: string | null

  refresh: () => Promise<void>
  /** Drop the cache so the next read reloads. For a project switch, which does not change
   *  triggers but does change everything they are tested against. */
  invalidate: () => void
}

export const useTriggerStore = create<TriggerState>((set) => ({
  triggers: [],
  fields: {},
  events: [],
  valueLen: 512,
  loaded: false,
  unavailable: null,

  refresh: async () => {
    try {
      const d = await api.listTriggers()
      set({
        triggers: d.triggers ?? [],
        fields: d.fields ?? {},
        events: d.events ?? [],
        valueLen: d.limits?.valueLen ?? 512,
        loaded: true,
        unavailable: null,
      })
    } catch (e) {
      set({
        triggers: [],
        loaded: true,
        unavailable: String(e instanceof Error ? e.message : e),
      })
    }
  },

  invalidate: () => set({ loaded: false }),
}))
