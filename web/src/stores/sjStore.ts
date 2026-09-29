import { create } from 'zustand'
import { api } from '../lib/api'
import type {
  SJSpec, SJOperation, SJResult, SJRunKind, SJRunStatus, SJMatrixView, SJProfileInput, SJTriage,
  SJFoundSpec,
} from '../lib/sjTypes'

const MAX_TABS = 8

export type SJSubTab = 'operations' | 'automate' | 'matrix' | 'brute'
export type SJRunSlot = 'scanRun' | 'matrixRun' | 'discoverRun'

/** One operation's editing state. Kept per operation id so switching away and
 *  back restores exactly what was typed, including hand-edited bytes. */
export interface SJDraft {
  values: Record<string, string>
  /** Parameters the operator explicitly unticked, by `${in}:${name}`.
   *
   *  Stored rather than derived. "Omitted" has no representation in `values` —
   *  absent there already means "use the generated default" — so deriving the
   *  checkbox from it made unticking a no-op: the key was deleted and the
   *  expression immediately read back true from the parameter's own default. */
  omit: Record<string, true>
  contentType: string
  /** Per-content-type body drafts, so switching type and back is lossless. */
  bodyByContentType: Record<string, string>
  profileId: string

  // Raw preview and detach.
  rendered: string
  renderError: string
  rendering: boolean
  /** Monotonic; a reply older than this is dropped, so a slow render cannot
   *  overwrite a newer one. */
  renderSeq: number
  /** Once true the form stops driving the bytes. The send path changes with it:
   *  dirty bytes go out verbatim and the auth profile is NOT re-applied, because
   *  it was already baked into the render the operator then edited. */
  rawDirty: boolean
  rawEdited: string
  /** One-step undo for Revert to form. */
  rawRetained: string

  // Send.
  sending: boolean
  error: string
  response: string
  status: number | null
  durationMs: number | null
  seq: number | null
  requestId: string
  seqNote: string
  triage: SJTriage | null

  view: 'form' | 'raw'
}

export function makeDraft(partial?: Partial<SJDraft>): SJDraft {
  return {
    values: {},
    omit: {},
    contentType: '',
    bodyByContentType: {},
    profileId: '',
    rendered: '',
    renderError: '',
    rendering: false,
    renderSeq: 0,
    rawDirty: false,
    rawEdited: '',
    rawRetained: '',
    sending: false,
    error: '',
    response: '',
    status: null,
    durationMs: null,
    seq: null,
    requestId: '',
    seqNote: '',
    triage: null,
    view: 'form',
    ...partial,
  }
}

/** One scan, matrix or discovery run attached to a tab. */
export interface SJRun {
  id: string
  kind: SJRunKind
  status: SJRunStatus | 'idle'
  total: number
  completed: number
  errors: number
  skipped: number
  hits: number
  warnings: string[]
  /** Documents a discovery sweep parsed mid-run. Discovery only. */
  found: SJFoundSpec[]
  results: SJResult[]
  matrix: SJMatrixView | null
  selectedIndex: number | null
  triageFilter: SJTriage | null
}

function makeRun(id: string, kind: SJRunKind, total: number, warnings: string[]): SJRun {
  return {
    id, kind, total, warnings,
    status: 'running',
    completed: 0, errors: 0, skipped: 0, hits: 0,
    found: [],
    results: [],
    matrix: null,
    selectedIndex: null,
    triageFilter: null,
  }
}

export interface SJProfile extends SJProfileInput {
  enabled: boolean
}

/** What a run covers.
 *
 *  Replaces a per-operation checkbox set. That set was written in the operation
 *  tree and read only from two other sub-tabs, so the operator configured it in
 *  one place and saw its effect in another — and with no select-all, scoping a
 *  300-operation document meant 300 clicks. A scope names the intent instead,
 *  and sits in the toolbar beside the button that runs it. */
export type SJScope =
  | { kind: 'all' }
  | { kind: 'nonDestructive' }
  | { kind: 'tag'; tag: string }
  | { kind: 'custom'; ids: string[] }

/** resolveScope turns a scope into the operation ids a run should cover.
 *  Returns undefined for "everything", which is what the API treats as all. */
export function resolveScope(scope: SJScope, ops: SJOperation[]): string[] | undefined {
  switch (scope.kind) {
    case 'all':
      return undefined
    case 'nonDestructive':
      return ops.filter((o) => !o.destructive).map((o) => o.id)
    case 'tag':
      return ops.filter((o) => (o.tags ?? []).includes(scope.tag)).map((o) => o.id)
    case 'custom':
      return scope.ids
  }
}

/** scopeCount is how many operations a scope covers, for a label. */
export function scopeCount(scope: SJScope, ops: SJOperation[]): number {
  return resolveScope(scope, ops)?.length ?? ops.length
}

export interface SJTab {
  id: string
  name: string

  spec: SJSpec | null
  loading: boolean
  loadError: string
  /** Set when a load returned "that was the UI page, not a document". Carries
   *  the paths Discover should be pre-filled with. */
  htmlHint: { message: string; candidates: string[]; sourceUrl: string } | null

  subTab: SJSubTab

  // Target. Always editable: a document may declare no server, several, or one
  // that is wrong.
  serverIndex: number
  scheme: string
  host: string
  basePath: string

  // Operation browser.
  groupBy: 'tag' | 'path'
  opFilter: string
  methodFilter: string[]
  collapsed: Record<string, true>
  selectedOpId: string | null

  /** What Automate and the Auth Matrix cover. */
  scope: SJScope

  drafts: Record<string, SJDraft>

  profiles: SJProfile[]
  activeProfileId: string

  scanRun: SJRun | null
  matrixRun: SJRun | null
  discoverRun: SJRun | null

  discover: { scheme: string; host: string; basePath: string; full: boolean; stopOnFirst: boolean }

  concurrency: number
  ratePerSec: number
  /** Empty means the server's default, which is a browser value rather than no
   *  header — see apispec.DefaultUserAgent for the precedence ladder. Held per
   *  tab because it describes the document's target, not one sub-tab's run. */
  userAgent: string
  allowDestructive: boolean
  /** Brute runs hotter than Automate — unauthenticated GETs against one host —
   *  and it needs its own control rather than reaching for one that only exists
   *  on the Automate toolbar. */
  bruteThreads: number
}

function makeTab(id: string, name: string, partial?: Partial<SJTab>): SJTab {
  return {
    id,
    name,
    spec: null,
    loading: false,
    loadError: '',
    htmlHint: null,
    subTab: 'operations',
    serverIndex: 0,
    scheme: 'https',
    host: '',
    basePath: '',
    groupBy: 'tag',
    opFilter: '',
    methodFilter: [],
    collapsed: {},
    selectedOpId: null,
    scope: { kind: 'all' },
    drafts: {},
    profiles: [],
    activeProfileId: '',
    scanRun: null,
    matrixRun: null,
    discoverRun: null,
    discover: { scheme: 'https', host: '', basePath: '', full: false, stopOnFirst: false },
    concurrency: 5,
    ratePerSec: 0,
    userAgent: '',
    allowDestructive: false,
    bruteThreads: 10,
    ...partial,
  }
}

/** What unloading a tab would discard that the operator cannot get back.
 *
 *  Only these four count. A draft exists merely because an operation was opened
 *  — doRender writes one — so "has drafts" would fire almost every time and
 *  train the operator to click through the confirmation without reading it. */
export interface SJLosses {
  profiles: number
  drafts: number
  running: number
  results: number
}

export function tabLosses(tab: SJTab): SJLosses {
  const profiles = tab.profiles.filter(
    (p) =>
      (p.credentials ?? []).some((c) => c.value || c.password || c.username) ||
      (p.headers ?? []).some((h) => h.name || h.value)
  ).length

  const drafts = Object.values(tab.drafts).filter(
    (d) =>
      d.rawDirty ||
      Object.keys(d.values).length > 0 ||
      Object.keys(d.omit).length > 0 ||
      Object.keys(d.bodyByContentType).length > 0
  ).length

  const runs = [tab.scanRun, tab.matrixRun, tab.discoverRun].filter(Boolean) as SJRun[]
  return {
    profiles,
    drafts,
    running: runs.filter((r) => r.status === 'running').length,
    results: runs.filter((r) => r.status !== 'running' && r.results.some(Boolean)).length,
  }
}

/** anyLoss reports whether unloading would cost the operator anything. */
export function anyLoss(l: SJLosses): boolean {
  return l.profiles > 0 || l.drafts > 0 || l.running > 0 || l.results > 0
}

interface SJState {
  tabs: SJTab[]
  activeTabId: string
  nextNum: number

  addTab: (partial?: Partial<SJTab>) => string
  removeTab: (id: string) => void
  setActiveTab: (id: string) => void
  updateTab: (id: string, updates: Partial<SJTab>) => void

  setSpec: (tabId: string, spec: SJSpec) => void

  // A re-parse of the document a tab already holds, not a new one: it replaces
  // the spec and nothing else, where setSpec resets drafts, target and selection
  // because a *different* document has arrived. Keyed by spec id rather than tab
  // id for the reason addRunResults is keyed by run id — every tab showing that
  // document is looking at the one parse, and they have to agree about it.
  setSpecParse: (specId: string, spec: SJSpec) => void
  updateDraft: (tabId: string, opId: string, updates: Partial<SJDraft>) => void

  startRun: (tabId: string, slot: SJRunSlot, id: string, kind: SJRunKind, total: number, warnings: string[]) => void
  clearRun: (tabId: string, slot: SJRunSlot) => void
  updateRun: (runId: string, updates: Partial<SJRun>) => void

  // Run-id targeted, for WebSocket routing: results must land in the tab that
  // owns the run, not whichever tab happens to be active.
  addRunResults: (runId: string, results: SJResult[]) => void
  addRunFound: (runId: string, found: SJFoundSpec) => void
  addRunWarning: (runId: string, detail: string) => void
  setRunStarted: (runId: string, total: number) => void
  setRunStatus: (runId: string, status: SJRunStatus) => void

  clearAll: () => void
}

/** normalizeSpec coerces the collections the views iterate.
 *
 *  The server guarantees these are arrays (apispec.Spec.normalize), so this is
 *  defence in depth — but at one boundary rather than optional-chaining at a
 *  dozen call sites, which is what lets the types stay honest. A stored spec is
 *  the only spec the views ever see, so normalizing here covers all of them. */
function normalizeSpec(spec: SJSpec): SJSpec {
  return {
    ...spec,
    servers: spec.servers ?? [],
    auth: spec.auth ?? [],
    operations: (spec.operations ?? []).map((op) => ({ ...op, params: op.params ?? [] })),
    // Not a collection, but the same boundary and the same reason: the bar binds
    // inputs straight to these four, and an absent object would be four
    // uncontrolled inputs rather than a visible failure.
    placeholders: spec.placeholders ?? { string: '', date: '', url: '', email: '' },
  }
}

/** findRun locates the tab and slot owning a run id. */
function findRun(s: SJState, runId: string): { tabId: string; slot: SJRunSlot } | null {
  for (const t of s.tabs) {
    if (t.scanRun?.id === runId) return { tabId: t.id, slot: 'scanRun' }
    if (t.matrixRun?.id === runId) return { tabId: t.id, slot: 'matrixRun' }
    if (t.discoverRun?.id === runId) return { tabId: t.id, slot: 'discoverRun' }
  }
  return null
}

function patchTab(s: SJState, tabId: string, updates: Partial<SJTab>): Partial<SJState> {
  return { tabs: s.tabs.map((t) => (t.id === tabId ? { ...t, ...updates } : t)) }
}

function patchRun(s: SJState, runId: string, fn: (run: SJRun) => SJRun): Partial<SJState> {
  const found = findRun(s, runId)
  if (!found) return {}
  const { tabId, slot } = found
  return {
    tabs: s.tabs.map((t) => {
      if (t.id !== tabId) return t
      const run = t[slot]
      if (!run) return t
      return { ...t, [slot]: fn(run) }
    }),
  }
}

export const useSJStore = create<SJState>((set, get) => ({
  tabs: [makeTab('1', 'Untitled')],
  activeTabId: '1',
  nextNum: 2,

  addTab: (partial) => {
    const s = get()
    if (s.tabs.length >= MAX_TABS) {
      set({ activeTabId: s.tabs[s.tabs.length - 1].id })
      return s.tabs[s.tabs.length - 1].id
    }
    const id = String(s.nextNum)
    const tab = makeTab(id, partial?.name || `Doc ${id}`, partial)
    set({ tabs: [...s.tabs, tab], activeTabId: id, nextNum: s.nextNum + 1 })
    return id
  },

  removeTab: (id) =>
    set((s) => {
      const tab = s.tabs.find((t) => t.id === id)
      // Stop anything still running: a run outlives its tab otherwise, and keeps
      // sending requests nobody is watching.
      for (const slot of ['scanRun', 'matrixRun', 'discoverRun'] as SJRunSlot[]) {
        const run = tab?.[slot]
        if (run && run.status === 'running') api.sjStopRun(run.id).catch(() => {})
      }

      // The last one is emptied rather than refused. fuzzStore and
      // manipulateStore both hard-return here, and are right to: their tabs are
      // cheap and empty by default, so closing the last is meaningless. An SJ tab
      // holds a loaded document, which makes unloading the last one the single
      // most likely thing an operator wants.
      if (s.tabs.length <= 1) {
        return { tabs: [makeTab(id, 'Untitled')], activeTabId: id }
      }

      const idx = s.tabs.findIndex((t) => t.id === id)
      const tabs = s.tabs.filter((t) => t.id !== id)
      // Select the next one, matching fuzz and manipulate; SJ alone was
      // selecting the previous.
      const activeTabId =
        s.activeTabId === id ? tabs[Math.min(idx, tabs.length - 1)].id : s.activeTabId
      return { tabs, activeTabId }
    }),

  setActiveTab: (id) => set({ activeTabId: id }),
  updateTab: (id, updates) => set((s) => patchTab(s, id, updates)),

  setSpec: (tabId, spec) =>
    set((s) => {
      const normalized = normalizeSpec(spec)
      const srv = normalized.servers[0]
      return patchTab(s, tabId, {
        spec: normalized,
        loading: false,
        loadError: '',
        htmlHint: null,
        name: normalized.title || 'Untitled',
        serverIndex: 0,
        scheme: srv?.scheme || 'https',
        host: srv?.host || '',
        basePath: srv?.basePath ?? '',
        subTab: 'operations',
        selectedOpId: normalized.operations[0]?.id ?? null,
        drafts: {},
        scope: { kind: 'all' },
        discover: {
          ...(s.tabs.find((t) => t.id === tabId)?.discover ?? {
            scheme: 'https', host: '', basePath: '', full: false, stopOnFirst: false,
          }),
          scheme: srv?.scheme || 'https',
          host: srv?.host || '',
        },
      })
    }),

  setSpecParse: (specId, spec) =>
    set((s) => ({
      tabs: s.tabs.map((t) =>
        t.spec?.id === specId ? { ...t, spec: normalizeSpec(spec) } : t
      ),
    })),

  updateDraft: (tabId, opId, updates) =>
    set((s) =>
      patchTab(s, tabId, {
        drafts: {
          ...(s.tabs.find((t) => t.id === tabId)?.drafts ?? {}),
          [opId]: { ...(s.tabs.find((t) => t.id === tabId)?.drafts?.[opId] ?? makeDraft()), ...updates },
        },
      })
    ),

  startRun: (tabId, slot, id, kind, total, warnings) =>
    set((s) => patchTab(s, tabId, { [slot]: makeRun(id, kind, total, warnings) } as Partial<SJTab>)),

  clearRun: (tabId, slot) => set((s) => patchTab(s, tabId, { [slot]: null } as Partial<SJTab>)),

  updateRun: (runId, updates) => set((s) => patchRun(s, runId, (run) => ({ ...run, ...updates }))),

  addRunResults: (runId, results) =>
    set((s) =>
      patchRun(s, runId, (run) => {
        // Results arrive indexed for a scan or matrix and appended for
        // discovery, so place by index where the slot exists and append
        // otherwise. Either way one arrival never overwrites a different row.
        const next = run.results.slice()
        for (const r of results) {
          if (r.index < next.length) next[r.index] = r
          else {
            while (next.length < r.index) next.push(undefined as unknown as SJResult)
            next.push(r)
          }
        }
        // Every counter is derived from the array, never accumulated. A result
        // redelivered for an index already filled — a reconnect, or two RAF
        // batches overlapping — correctly overwrites its row, and an accumulated
        // counter would have counted it twice and shown errors > completed.
        let errors = 0
        let skipped = 0
        let hits = 0
        let completed = 0
        for (const r of next) {
          if (!r) continue
          completed++
          if (r.error) errors++
          else if (r.skipped) skipped++
          if (r.bodyKind === 'spec') hits++
        }
        return { ...run, results: next, completed, errors, skipped, hits }
      })
    ),

  // Both dedupe, because a reconnect can redeliver: the server fires each of
  // these once per run, so a second arrival is a replay, not a new one.
  addRunFound: (runId, found) =>
    set((s) =>
      patchRun(s, runId, (run) =>
        run.found.some((f) => f.specId === found.specId)
          ? run
          : { ...run, found: [...run.found, found] }
      )
    ),

  addRunWarning: (runId, detail) =>
    set((s) =>
      patchRun(s, runId, (run) =>
        run.warnings.includes(detail) ? run : { ...run, warnings: [...run.warnings, detail] }
      )
    ),

  setRunStarted: (runId, total) =>
    set((s) => patchRun(s, runId, (run) => ({ ...run, total, status: 'running' }))),

  setRunStatus: (runId, status) => set((s) => patchRun(s, runId, (run) => ({ ...run, status }))),

  clearAll: () => set({ tabs: [makeTab('1', 'Untitled')], activeTabId: '1', nextNum: 2 }),
}))
