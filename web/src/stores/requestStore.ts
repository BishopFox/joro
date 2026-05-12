import { create } from 'zustand'
import { api } from '../lib/api'

export interface RequestSummary {
  id: string
  seq: number
  timestamp: string
  method: string
  url: string
  host: string
  protocol?: string
  statusCode: number
  contentType: string
  durationMs: number
  responseSize: number
}

interface RequestState {
  items: RequestSummary[]
  total: number
  loading: boolean
  selected: RequestSummary | null
  selectedDetail: RequestDetail | null
  filter: RequestFilter
  highlights: Record<string, string>
  reloadCounter: number
  sortColumn: SortColumn
  sortDir: SortDir
  addItem: (item: RequestSummary) => void
  addItems: (items: RequestSummary[]) => void
  setItems: (items: RequestSummary[], total: number) => void
  setSelected: (item: RequestSummary | null) => void
  setSelectedDetail: (detail: RequestDetail | null) => void
  setFilter: (f: Partial<RequestFilter>) => void
  setSort: (column: SortColumn, dir: SortDir) => void
  setLoading: (v: boolean) => void
  clear: () => void
  invalidate: () => void
  loadHighlights: () => Promise<void>
  setHighlight: (id: string, color: string) => void
  removeHighlight: (id: string) => void
}

export interface RequestDetail extends RequestSummary {
  reqRaw: string   // base64
  respRaw: string  // base64
}

export interface RequestFilter {
  host: string
  method: string
  search: string
  status: string
  exclude: string
  extMode: 'exclude' | 'include' | ''
  contentTypes: string[]
  scopeOnly: boolean
  offset: number
  limit: number
}

export type SortColumn = 'seq' | 'method' | 'statusCode' | 'contentType' | 'url' | 'timestamp' | 'responseSize'
export type SortDir = 'asc' | 'desc'

const DEFAULT_EXCLUDE = '.css,.png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.woff,.woff2'

const SORT_STORAGE_KEY = 'joro-history-sort'
const VALID_SORT_COLUMNS: SortColumn[] = ['seq', 'method', 'statusCode', 'contentType', 'url', 'timestamp', 'responseSize']

function loadSort(): { column: SortColumn; dir: SortDir } {
  try {
    const raw = localStorage.getItem(SORT_STORAGE_KEY)
    if (!raw) return { column: 'seq', dir: 'desc' }
    const parsed = JSON.parse(raw)
    const column = VALID_SORT_COLUMNS.includes(parsed?.column) ? parsed.column as SortColumn : 'seq'
    const dir: SortDir = parsed?.dir === 'asc' || parsed?.dir === 'desc' ? parsed.dir : 'desc'
    return { column, dir }
  } catch {
    return { column: 'seq', dir: 'desc' }
  }
}

function persistSort(column: SortColumn, dir: SortDir) {
  try {
    localStorage.setItem(SORT_STORAGE_KEY, JSON.stringify({ column, dir }))
  } catch { /* ignore quota / privacy-mode failures */ }
}

const initialSort = loadSort()

// sortRequestItems sorts items in place by the given column/direction. Mirrors
// the comparator in History.tsx; kept in the store so mutations land sorted and
// the rendered order can never desync from the user's chosen sort.
function sortRequestItems(items: RequestSummary[], column: SortColumn, dir: SortDir): RequestSummary[] {
  const mul = dir === 'asc' ? 1 : -1
  items.sort((a, b) => {
    let cmp = 0
    switch (column) {
      case 'seq': cmp = a.seq - b.seq; break
      case 'statusCode': cmp = a.statusCode - b.statusCode; break
      case 'method': cmp = a.method.localeCompare(b.method); break
      case 'contentType': cmp = (a.contentType || '').localeCompare(b.contentType || ''); break
      case 'url': cmp = a.url.localeCompare(b.url); break
      case 'timestamp': cmp = (a.timestamp || '').localeCompare(b.timestamp || ''); break
      case 'responseSize': cmp = a.responseSize - b.responseSize; break
    }
    return cmp * mul
  })
  return items
}

export const useRequestStore = create<RequestState>((set) => ({
  items: [],
  total: 0,
  loading: false,
  selected: null,
  selectedDetail: null,
  highlights: {},
  reloadCounter: 0,
  sortColumn: initialSort.column,
  sortDir: initialSort.dir,
  filter: { host: '', method: '', search: '', status: '', exclude: localStorage.getItem('joro-history-exclude') ?? DEFAULT_EXCLUDE, extMode: (localStorage.getItem('joro-history-extMode') as 'exclude' | 'include' | '') ?? 'exclude', contentTypes: [], scopeOnly: false, offset: 0, limit: 0 },

  addItem: (item) =>
    set((s) => {
      const { exclude, extMode } = s.filter
      if (exclude && extMode) {
        const exts = new Set(exclude.split(',').map(e => e.trim().toLowerCase()))
        try {
          const dotIdx = new URL(item.url).pathname.lastIndexOf('.')
          if (dotIdx >= 0) {
            const ext = new URL(item.url).pathname.substring(dotIdx).toLowerCase()
            const found = exts.has(ext)
            if (extMode === 'exclude' && found) return s
            if (extMode === 'include' && !found) return s
          } else if (extMode === 'include') {
            return s
          }
        } catch { /* allow through */ }
      }
      const merged = sortRequestItems([...s.items, item], s.sortColumn, s.sortDir)
      return { items: merged, total: s.total + 1 }
    }),

  addItems: (newItems) =>
    set((s) => {
      const { exclude, extMode } = s.filter
      let filtered = newItems
      if (exclude && extMode) {
        const exts = new Set(exclude.split(',').map(e => e.trim().toLowerCase()))
        filtered = newItems.filter((item) => {
          try {
            const dotIdx = new URL(item.url).pathname.lastIndexOf('.')
            if (dotIdx >= 0) {
              const ext = new URL(item.url).pathname.substring(dotIdx).toLowerCase()
              const found = exts.has(ext)
              if (extMode === 'exclude' && found) return false
              if (extMode === 'include' && !found) return false
            } else if (extMode === 'include') {
              return false
            }
          } catch { /* allow through */ }
          return true
        })
      }
      if (filtered.length === 0) return s
      const merged = sortRequestItems([...s.items, ...filtered], s.sortColumn, s.sortDir)
      // Dev-mode invariant: if we're sorting by seq, the merged array must be
      // monotonic. A warning here means the merge actually saw out-of-order
      // arrivals (likely the backend Add/emit race in handler.go) — silence in
      // prod; loud in dev so the bug becomes diagnosable in the wild.
      if (import.meta.env.DEV && s.sortColumn === 'seq') {
        const asc = s.sortDir === 'asc'
        for (let i = 1; i < merged.length; i++) {
          const prev = merged[i - 1].seq
          const curr = merged[i].seq
          if (asc ? curr < prev : curr > prev) {
            console.warn('[requestStore] seq order violated after addItems', { i, prev, curr, dir: s.sortDir })
            break
          }
        }
      }
      return { items: merged, total: s.total + filtered.length }
    }),

  setItems: (items, total) => set((s) => ({
    items: sortRequestItems([...items], s.sortColumn, s.sortDir),
    total,
  })),
  setSelected: (selected) => set({ selected }),
  setSelectedDetail: (selectedDetail) => set({ selectedDetail }),
  setSort: (sortColumn, sortDir) => set((s) => {
    persistSort(sortColumn, sortDir)
    return {
      sortColumn,
      sortDir,
      items: sortRequestItems([...s.items], sortColumn, sortDir),
    }
  }),
  setFilter: (f) => set((s) => ({ filter: { ...s.filter, ...f, offset: 0 } })),
  setLoading: (loading) => set({ loading }),
  clear: () => set({ items: [], total: 0, selected: null, selectedDetail: null }),
  invalidate: () => set((s) => ({ items: [], total: 0, selected: null, selectedDetail: null, reloadCounter: s.reloadCounter + 1 })),

  loadHighlights: async () => {
    try {
      const data = await api.getHighlights()
      set({ highlights: data.highlights })
    } catch { /* ignore */ }
  },
  setHighlight: (id, color) => {
    set((s) => ({ highlights: { ...s.highlights, [id]: color } }))
    api.setHighlight(id, color).catch(() => {})
  },
  removeHighlight: (id) => {
    set((s) => {
      const { [id]: _, ...rest } = s.highlights
      return { highlights: rest }
    })
    api.setHighlight(id, '').catch(() => {})
  },
}))
