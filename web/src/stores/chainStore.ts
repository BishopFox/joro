import { create } from 'zustand'
import type {
  Chain,
  ChainSummary,
  ChainResult,
  ChainRunStatus,
  ChainVariant,
  ChainVerdict,
  ChainStepHead,
  ChainGridView,
} from '../lib/chainTypes'

/** ChainRun is the client's view of one sweep in flight or finished. */
export interface ChainRun {
  id: string
  chainId: string
  chainName: string
  status: ChainRunStatus
  total: number
  stride: number
  completed: number
  errors: number
  unresolved: number
  bypassed: number
  warnings: string[]
  steps: ChainStepHead[]
  variants: ChainVariant[]
  verdicts: Record<string, ChainVerdict>
  /** Sparse: indexed by the server's slot, with holes where nothing has landed. */
  results: ChainResult[]
  grid?: ChainGridView
  selectedIndex: number | null
}

function makeRun(id: string, chainId: string, chainName: string, total: number, warnings: string[]): ChainRun {
  return {
    id,
    chainId,
    chainName,
    status: 'running',
    total,
    stride: 0,
    completed: 0,
    errors: 0,
    unresolved: 0,
    bypassed: 0,
    warnings,
    steps: [],
    variants: [],
    verdicts: {},
    results: [],
    selectedIndex: null,
  }
}

interface ChainState {
  chains: ChainSummary[]
  chainsLoaded: boolean
  /** The chain currently open in the map, fully hydrated. */
  active: Chain | null
  activeDirty: boolean
  selectedStepId: string | null
  selectedBindingId: string | null

  /** Runs by id. A sweep is addressed by run id from the WS handler, never by
   *  "the active one", so a result cannot land in the wrong run after the
   *  operator switches chains mid-sweep. */
  runs: Record<string, ChainRun>
  activeRunId: string | null

  setChains: (chains: ChainSummary[]) => void
  setActive: (chain: Chain | null) => void
  patchActive: (fn: (c: Chain) => Chain) => void
  markClean: () => void
  select: (stepId: string | null, bindingId?: string | null) => void

  startRun: (id: string, chainId: string, chainName: string, total: number, warnings: string[]) => void
  updateRun: (id: string, patch: Partial<ChainRun>) => void
  addRunResults: (id: string, results: ChainResult[]) => void
  setRunVerdict: (id: string, verdict: ChainVerdict) => void
  setRunStatus: (id: string, status: ChainRunStatus) => void
  clearRun: (id: string) => void
  clearAll: () => void
}

export const useChainStore = create<ChainState>((set) => ({
  chains: [],
  chainsLoaded: false,
  active: null,
  activeDirty: false,
  selectedStepId: null,
  selectedBindingId: null,
  runs: {},
  activeRunId: null,

  setChains: (chains) => set({ chains, chainsLoaded: true }),

  setActive: (active) =>
    set({ active, activeDirty: false, selectedStepId: null, selectedBindingId: null }),

  // Every map edit goes through here so `activeDirty` cannot disagree with what
  // is on screen — there is no second path that mutates the chain.
  patchActive: (fn) =>
    set((s) => (s.active ? { active: fn(s.active), activeDirty: true } : s)),

  markClean: () => set({ activeDirty: false }),

  select: (stepId, bindingId = null) =>
    set({ selectedStepId: stepId, selectedBindingId: bindingId }),

  startRun: (id, chainId, chainName, total, warnings) =>
    set((s) => ({
      runs: { ...s.runs, [id]: makeRun(id, chainId, chainName, total, warnings) },
      activeRunId: id,
    })),

  updateRun: (id, patch) =>
    set((s) => (s.runs[id] ? { runs: { ...s.runs, [id]: { ...s.runs[id], ...patch } } } : s)),

  addRunResults: (id, incoming) =>
    set((s) => {
      const run = s.runs[id]
      if (!run) return s
      const results = run.results.slice()
      for (const r of incoming) {
        results[r.index] = r
      }
      // Counters are derived from the array, never accumulated: a redelivered
      // result overwrites its slot, whereas an accumulated counter would
      // double-count it and show errors greater than completed.
      let completed = 0
      let errors = 0
      let unresolved = 0
      for (const r of results) {
        if (!r || !r.cell) continue
        if (r.cell === 'skipped') continue
        completed++
        if (r.cell === 'error') errors++
        if (r.cell === 'unresolved') unresolved++
      }
      return { runs: { ...s.runs, [id]: { ...run, results, completed, errors, unresolved } } }
    }),

  setRunVerdict: (id, verdict) =>
    set((s) => {
      const run = s.runs[id]
      if (!run) return s
      const verdicts = { ...run.verdicts, [verdict.variantId]: verdict }
      const bypassed = Object.values(verdicts).filter(
        (v) => v.verdict === 'bypassed' || v.verdict === 'amplified',
      ).length
      return { runs: { ...s.runs, [id]: { ...run, verdicts, bypassed } } }
    }),

  setRunStatus: (id, status) =>
    set((s) => (s.runs[id] ? { runs: { ...s.runs, [id]: { ...s.runs[id], status } } } : s)),

  clearRun: (id) =>
    set((s) => {
      const runs = { ...s.runs }
      delete runs[id]
      return { runs, activeRunId: s.activeRunId === id ? null : s.activeRunId }
    }),

  // Called from applyProject: a run's results reference History rows from the
  // previous engagement and its verdicts were computed against a baseline
  // measured there, so none of it survives a project switch. Chains do survive —
  // they travel in the project file — and are refetched when the page mounts.
  clearAll: () =>
    set({
      chains: [],
      chainsLoaded: false,
      active: null,
      activeDirty: false,
      selectedStepId: null,
      selectedBindingId: null,
      runs: {},
      activeRunId: null,
    }),
}))
