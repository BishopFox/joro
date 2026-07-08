import { create } from 'zustand'

// A request staged for a Dead Drop export. Raw bytes are base64, sourced from
// a RequestDetail (GET /requests/:id) so the record is self-contained — the
// exported .jord file carries these bytes verbatim into the viewer.
export interface StagedRequest {
  id: string // source request id; also the stable staging key
  host: string
  method: string
  url: string
  status: number
  reqRaw: string // base64
  respRaw: string // base64
  truncated: boolean
  note: string // per-item, editable
}

interface DeadDropState {
  staged: StagedRequest[]
  add: (r: StagedRequest) => void // dedupes by id (ignores if already staged)
  remove: (id: string) => void
  reorder: (from: number, to: number) => void
  setNote: (id: string, note: string) => void
  clear: () => void
}

export const useDeadDropStore = create<DeadDropState>((set) => ({
  staged: [],

  add: (r) =>
    set((s) => (s.staged.some((x) => x.id === r.id) ? s : { staged: [...s.staged, r] })),
  remove: (id) => set((s) => ({ staged: s.staged.filter((x) => x.id !== id) })),
  reorder: (from, to) =>
    set((s) => {
      if (
        from === to ||
        from < 0 ||
        to < 0 ||
        from >= s.staged.length ||
        to >= s.staged.length
      ) {
        return s
      }
      const next = [...s.staged]
      const [moved] = next.splice(from, 1)
      next.splice(to, 0, moved)
      return { staged: next }
    }),
  setNote: (id, note) =>
    set((s) => ({ staged: s.staged.map((x) => (x.id === id ? { ...x, note } : x)) })),
  clear: () => set({ staged: [] }),
}))
