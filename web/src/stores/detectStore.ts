import { create } from 'zustand'
import { api } from '../lib/api'
import { SEVERITY_RANK, type Severity, type Confidence } from '../lib/severity'
import { matchesFindingFilter } from '../lib/detectFilters'

export interface Finding {
  // id is the server's deterministic group hash. Re-emission for a known group
  // arrives with the same id and a bumped count, so the live merge below is a
  // plain map upsert.
  id: string
  ruleId: string
  ruleName: string
  category: string
  severity: Severity
  confidence: Confidence
  target: string
  host: string
  method: string
  url: string
  requestId: string
  detail?: string
  evidence: string
  // Present only for rules that redact. The real value travels with the finding,
  // so revealing it is a local toggle rather than a fetch.
  rawEvidence?: string
  evidenceOffset: number
  evidenceLength: number
  evidencePart?: string
  count: number
  firstSeen: string
  lastSeen: string
  falsePositive: boolean
  hasNotes: boolean
  truncated?: boolean
}

export interface FindingOccurrence {
  requestId: string
  seq: number
  method: string
  url: string
  statusCode: number
  timestamp: string
  offset: number
  part: string
  requestPresent: boolean
}

export interface DetectRule {
  id: string
  name: string
  description?: string
  remediation?: string
  kind: 'regex' | 'analyzer'
  category: string
  severity: Severity
  confidence: Confidence
  target: string
  pattern?: string
  literal?: string
  captureGroup?: number
  postFilters?: string[]
  analyzer?: string
  groupBy?: string
  contentTypes?: string[]
  statusCodes?: string
  scheme?: string
  minLength?: number
  minEntropy?: number
  maxPerResponse?: number
  redactEvidence?: boolean
  builtin: boolean
  enabled: boolean
  findingCount?: number
}

export interface DetectConfig {
  scopeOnly: boolean
  scanRequests: boolean
  persistFindings: boolean
  clearFindingsWithHistory: boolean
  maxBodyScanBytes: number
  maxRequestBodyScanBytes: number
  skipContentTypes: string[]
  skipExtensions: string[]
  excludeHosts: string[]
}

export interface DetectSummary {
  total: number
  bySeverity: Record<string, number>
  byCategory: Record<string, number>
  falsePositives: number
  hiddenByDisabledRule: number
  skippedEncoded: number
  skippedBinary: number
  scanned: number
}

export interface ScanState {
  running: boolean
  jobId: string
  kind?: string
  scanned: number
  total: number
  findingsNew: number
  startedAt?: string
  finishedAt?: string
  status?: string
}

export interface DetectFilter {
  severities: Severity[]
  categories: string[]
  confidence: string
  rule: string
  host: string
  search: string
  showFalsePositives: boolean
  includeDisabled: boolean
  offset: number
  limit: number
}

export const emptyDetectFilter: DetectFilter = {
  // severities is the set of bands the table shows. An EMPTY array means no
  // severity filter at all, matching MultiSelectDropdown's "Any"/Clear and the
  // server's absent severity param.
  //
  // The default lists the four non-Info bands. Info rules still run and their
  // findings are stored, counted, and persisted; only the view narrows. Not
  // persisted, so every session starts here.
  severities: ['critical', 'high', 'medium', 'low'],
  categories: [],
  confidence: '',
  rule: '',
  host: '',
  search: '',
  showFalsePositives: false,
  includeDisabled: false,
  offset: 0,
  limit: 200,
}

export type FindingSortColumn =
  | 'severity'
  | 'rule'
  | 'category'
  | 'host'
  | 'url'
  | 'count'
  | 'lastSeen'
export type SortDir = 'asc' | 'desc'

// MAX_ITEMS caps the rendered list. The table is not virtualized and limit=0
// ("All") is reachable from the UI.
const MAX_ITEMS = 5000

const SORT_KEY = 'joro-detect-sort'

function loadSort(): { column: FindingSortColumn; dir: SortDir } {
  try {
    const raw = localStorage.getItem(SORT_KEY)
    if (raw) {
      const parsed = JSON.parse(raw) as { column: FindingSortColumn; dir: SortDir }
      if (parsed.column && parsed.dir) return parsed
    }
  } catch {
    // Ignore malformed storage and fall through to the default.
  }
  return { column: 'severity', dir: 'desc' }
}

function persistSort(column: FindingSortColumn, dir: SortDir) {
  try {
    localStorage.setItem(SORT_KEY, JSON.stringify({ column, dir }))
  } catch {
    // Storage is best-effort.
  }
}

// sortFindings orders the list in place. Every mutation calls it, so render
// order cannot drift from the sort state. See requestStore's sort helper.
function sortFindings(items: Finding[], col: FindingSortColumn, dir: SortDir): Finding[] {
  const mul = dir === 'asc' ? 1 : -1
  items.sort((a, b) => {
    let cmp = 0
    switch (col) {
      case 'severity':
        cmp = (SEVERITY_RANK[a.severity] ?? 0) - (SEVERITY_RANK[b.severity] ?? 0)
        break
      case 'count':
        cmp = a.count - b.count
        break
      case 'lastSeen':
        cmp = (a.lastSeen || '').localeCompare(b.lastSeen || '')
        break
      case 'rule':
        cmp = a.ruleName.localeCompare(b.ruleName)
        break
      default:
        cmp = String(a[col] ?? '').localeCompare(String(b[col] ?? ''))
    }
    if (cmp === 0) {
      // Deterministic tiebreak, so equal rows never reorder between renders.
      cmp =
        (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
        a.id.localeCompare(b.id)
      return cmp
    }
    return cmp * mul
  })
  return items
}

const emptySummary: DetectSummary = {
  total: 0,
  bySeverity: {},
  byCategory: {},
  falsePositives: 0,
  hiddenByDisabledRule: 0,
  skippedEncoded: 0,
  skippedBinary: 0,
  scanned: 0,
}

const emptyScan: ScanState = {
  running: false,
  jobId: '',
  scanned: 0,
  total: 0,
  findingsNew: 0,
}

interface DetectState {
  enabled: boolean
  items: Finding[]
  total: number
  truncated: boolean
  loading: boolean
  selected: Finding | null
  occurrences: FindingOccurrence[]
  selectedRule: DetectRule | null
  selectedNotes: string
  filter: DetectFilter
  sortColumn: FindingSortColumn
  sortDir: SortDir
  reloadCounter: number
  livePaused: boolean
  pending: Finding[]
  summary: DetectSummary
  scan: ScanState
  rules: DetectRule[]
  rulesLoaded: boolean
  config: DetectConfig | null

  setEnabled: (v: boolean) => void
  setItems: (items: Finding[], total: number) => void
  upsertFindings: (batch: Finding[]) => void
  setSelected: (f: Finding | null) => void
  setSelectedDetail: (
    occurrences: FindingOccurrence[],
    rule: DetectRule | null,
    notes: string
  ) => void
  setFilter: (patch: Partial<DetectFilter>) => void
  setSort: (col: FindingSortColumn) => void
  setLoading: (v: boolean) => void
  setSummary: (s: DetectSummary) => void
  setScan: (patch: Partial<ScanState>) => void
  invalidate: () => void
  clearAll: () => void
  togglePaused: () => void
  flushPending: () => void
  markFalsePositive: (id: string, v: boolean) => void
  setNotes: (id: string, notes: string) => void
  overrideSeverity: (id: string, sev: Severity) => void
  removeFinding: (id: string) => void
  setRules: (rules: DetectRule[]) => void
  setRuleEnabled: (id: string, enabled: boolean) => void
  setConfig: (c: DetectConfig) => void
}

const initialSort = loadSort()

export const useDetectStore = create<DetectState>((set, get) => ({
  enabled: true,
  items: [],
  total: 0,
  truncated: false,
  loading: false,
  selected: null,
  occurrences: [],
  selectedRule: null,
  selectedNotes: '',
  filter: { ...emptyDetectFilter },
  sortColumn: initialSort.column,
  sortDir: initialSort.dir,
  reloadCounter: 0,
  livePaused: false,
  pending: [],
  summary: emptySummary,
  scan: { ...emptyScan },
  rules: [],
  rulesLoaded: false,
  config: null,

  setEnabled: (v) => set({ enabled: v }),

  setItems: (items, total) =>
    set((s) => ({
      items: sortFindings([...items], s.sortColumn, s.sortDir).slice(0, MAX_ITEMS),
      total,
      truncated: items.length > MAX_ITEMS,
    })),

  // upsertFindings merges live findings. The server's finding id is a
  // deterministic group hash, so `total` increments only for new ids; an
  // occurrence bump changes `count`, never `total`.
  upsertFindings: (batch) =>
    set((s) => {
      if (s.livePaused) {
        return { pending: [...s.pending, ...batch] }
      }
      const idx = new Map(s.items.map((f, i) => [f.id, i]))
      const next = [...s.items]
      let total = s.total
      let changed = false
      let selected = s.selected

      for (const f of batch) {
        const i = idx.get(f.id)
        if (i !== undefined) {
          // Known group: bump only the volatile fields. Never replace wholesale,
          // since the row may carry an optimistic local false-positive mark.
          //
          // The evidence location is one value spread over five fields and they
          // must be updated together, as Store.Upsert does on the server: a
          // host-grouped rule merges two different matches.
          next[i] = {
            ...next[i],
            count: f.count,
            lastSeen: f.lastSeen,
            evidence: f.evidence || next[i].evidence,
            rawEvidence: f.rawEvidence ?? next[i].rawEvidence,
            requestId: f.requestId || next[i].requestId,
            url: f.url || next[i].url,
            evidenceOffset: f.evidenceOffset,
            evidenceLength: f.evidenceLength,
            evidencePart: f.evidencePart,
          }
          if (selected?.id === f.id) selected = next[i]
          changed = true
          continue
        }
        if (!matchesFindingFilter(f, s.filter)) continue
        idx.set(f.id, next.length)
        next.push(f)
        total += 1
        changed = true
      }
      if (!changed) return s

      sortFindings(next, s.sortColumn, s.sortDir)
      const truncated = next.length > MAX_ITEMS
      return {
        items: truncated ? next.slice(0, MAX_ITEMS) : next,
        total,
        selected,
        truncated: s.truncated || truncated,
      }
    }),

  setSelected: (f) =>
    set({ selected: f, occurrences: [], selectedRule: null, selectedNotes: '' }),

  setSelectedDetail: (occurrences, rule, notes) =>
    set({ occurrences, selectedRule: rule, selectedNotes: notes }),

  setFilter: (patch) =>
    set((s) => ({
      // Any filter change resets pagination; a narrower filter could otherwise
      // land on an empty page.
      filter: { ...s.filter, ...patch, ...(patch.offset === undefined && { offset: 0 }) },
    })),

  setSort: (col) =>
    set((s) => {
      const dir: SortDir = s.sortColumn === col && s.sortDir === 'desc' ? 'asc' : 'desc'
      persistSort(col, dir)
      return {
        sortColumn: col,
        sortDir: dir,
        items: sortFindings([...s.items], col, dir),
      }
    }),

  setLoading: (v) => set({ loading: v }),
  setSummary: (summary) => set({ summary }),
  setScan: (patch) => set((s) => ({ scan: { ...s.scan, ...patch } })),

  invalidate: () =>
    set((s) => ({
      reloadCounter: s.reloadCounter + 1,
      selected: null,
      occurrences: [],
      selectedRule: null,
      pending: [],
      rulesLoaded: false,
    })),

  clearAll: () =>
    set({
      items: [],
      total: 0,
      selected: null,
      occurrences: [],
      selectedRule: null,
      pending: [],
      truncated: false,
      summary: emptySummary,
    }),

  togglePaused: () => set((s) => ({ livePaused: !s.livePaused })),

  flushPending: () => {
    const pending = get().pending
    if (pending.length === 0) return
    set({ pending: [] })
    get().upsertFindings(pending)
  },

  // Optimistic update, then fire-and-forget. See requestStore.setHighlight.
  markFalsePositive: (id, v) => {
    set((s) => ({
      items: s.items.map((f) => (f.id === id ? { ...f, falsePositive: v } : f)),
      selected: s.selected?.id === id ? { ...s.selected, falsePositive: v } : s.selected,
    }))
    api.updateFinding(id, { falsePositive: v }).catch(() => {})
  },

  setNotes: (id, notes) => {
    set((s) => ({
      items: s.items.map((f) => (f.id === id ? { ...f, hasNotes: notes !== '' } : f)),
      selectedNotes: s.selected?.id === id ? notes : s.selectedNotes,
    }))
    api.updateFinding(id, { notes }).catch(() => {})
  },

  overrideSeverity: (id, sev) => {
    set((s) => ({
      items: sortFindings(
        s.items.map((f) => (f.id === id ? { ...f, severity: sev } : f)),
        s.sortColumn,
        s.sortDir
      ),
      selected: s.selected?.id === id ? { ...s.selected, severity: sev } : s.selected,
    }))
    api.updateFinding(id, { severity: sev }).catch(() => {})
  },

  removeFinding: (id) => {
    set((s) => ({
      items: s.items.filter((f) => f.id !== id),
      total: Math.max(0, s.total - 1),
      selected: s.selected?.id === id ? null : s.selected,
    }))
    api.deleteFinding(id).catch(() => {})
  },

  setRules: (rules) => set({ rules, rulesLoaded: true }),

  setRuleEnabled: (id, enabled) => {
    set((s) => ({
      rules: s.rules.map((r) => (r.id === id ? { ...r, enabled } : r)),
    }))
    api.setDetectRuleEnabled(id, enabled).catch(() => {})
  },

  setConfig: (config) => set({ config }),
}))
