import { create } from 'zustand'

export type InterceptKind = 'request' | 'response'

export interface PendingItem {
  id: string
  kind: InterceptKind
  method: string
  url: string
  host: string
  protocol?: string
  status?: number
  pausedAt?: string
  reqRaw: string // base64, set for both kinds
  respRaw?: string // base64, response pauses only
}

// Alias kept so existing call sites need no churn.
export type PendingRequest = PendingItem

// Both phases of one transaction share the request's id, so rows are keyed on
// kind + id. They cannot legitimately coexist, but a dropped intercept.resolved
// WS frame would otherwise leave two rows sharing a React key.
const keyOf = (i: PendingItem) => `${i.kind}:${i.id}`

// withSelection keeps the detail pane loaded: while the queue is non-empty something
// is selected, so resolving an item advances to the next rather than emptying the pane
// and sending the operator back to the list on every single one.
//
// A post-condition of setItems / addItem / removeItem, not an invariant of the store:
// setSelected stays unnormalized, so an explicit click outranks the default and
// setSelected(null) sticks.
//
// Element zero is the oldest pause, because InterceptQueue.List sorts by PausedAt and
// addItem appends — a new pause always being the newest. Both have to stay true
// together and nothing fails a build if one stops being. Sorting here instead is not
// the fix: an item off the event stream arrives before the server's listing does, and
// its pausedAt is a different clock's reading. Oldest-first does put response pauses
// behind every waiting request, which is the accepted cost of FIFO and not free — a
// paused response holds a client connection open against the browser's per-host cap.
//
// A surviving selection keeps its original object, the opposite of detectStore's
// upsert. Downstream state is keyed on kind:id rather than identity, so re-pointing
// would corrupt nothing — it would just churn every consumer on each reconcile poll.
function withSelection(items: PendingItem[], prev: PendingItem | null) {
  if (prev && items.some((i) => keyOf(i) === keyOf(prev))) return { items, selected: prev }
  return { items, selected: items[0] ?? null }
}

interface InterceptState {
  enabled: boolean
  responsesEnabled: boolean
  items: PendingItem[]
  selected: PendingItem | null
  setEnabled: (v: boolean) => void
  setResponsesEnabled: (v: boolean) => void
  setItems: (items: PendingItem[]) => void
  addItem: (item: PendingItem) => void
  removeItem: (id: string) => void
  setSelected: (item: PendingItem | null) => void
}

export const useInterceptStore = create<InterceptState>((set) => ({
  enabled: false,
  responsesEnabled: false,
  items: [],
  selected: null,

  setEnabled: (enabled) => set({ enabled }),
  setResponsesEnabled: (responsesEnabled) => set({ responsesEnabled }),

  // A selection the server no longer knows about (timed out, drained) gives way to
  // the oldest item still queued.
  setItems: (items) => set((s) => withSelection(items, s.selected)),

  // Upsert rather than append, so a reconcile poll or a replayed event cannot
  // duplicate a row. The first arrival into an empty queue selects itself; a later
  // one never steals the pane from the item the operator is reading.
  addItem: (item) =>
    set((s) => {
      const idx = s.items.findIndex((i) => keyOf(i) === keyOf(item))
      if (idx === -1) return withSelection([...s.items, item], s.selected)
      const items = [...s.items]
      items[idx] = item
      return withSelection(items, s.selected)
    }),

  // Clears both phases for the id. Idempotent. Filtering on the bare id is what
  // clears both; withSelection compares on kind:id, which agrees here because the
  // filter has already removed every row carrying the id.
  removeItem: (id) =>
    set((s) => withSelection(s.items.filter((i) => i.id !== id), s.selected)),

  setSelected: (selected) => set({ selected }),
}))
