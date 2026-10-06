import { create } from 'zustand'
import type { ActiveScanRun } from '../lib/api'

// Active-scan run list, fed by the activescan.* WebSocket events plus an initial
// fetch in the Scans sub-tab. It is the single source of truth for both the Scans
// tab and the floating ActiveScanIndicator pill (which derives the running run).
// Findings themselves arrive through the shared detect.finding / detect.summary
// handlers and land in the Detect tab.
export interface ActiveScanState {
  runs: ActiveScanRun[] // newest first
  setRuns: (runs: ActiveScanRun[]) => void
  applyStarted: (p: {
    runId: string
    host: string
    origin: string
    scope: string
    rules: string[]
    total: number
  }) => void
  applyProgress: (p: { runId: string; scanned: number; total: number; findings: number }) => void
  applyComplete: (p: {
    runId: string
    status: string
    completed?: number
    errors?: number
    findings: number
  }) => void
  removeRun: (id: string) => void
  clear: () => void
}

export const useActiveScanStore = create<ActiveScanState>((set) => ({
  runs: [],
  setRuns: (runs) => set({ runs }),
  applyStarted: ({ runId, host, origin, scope, rules, total }) =>
    set((s) => {
      const row: ActiveScanRun = {
        id: runId,
        host,
        origin,
        scope,
        rules,
        status: 'running',
        total,
        completed: 0,
        errors: 0,
        findings: 0,
        createdAt: new Date().toISOString(),
      }
      const rest = s.runs.filter((r) => r.id !== runId)
      return { runs: [row, ...rest] }
    }),
  applyProgress: ({ runId, scanned, total, findings }) =>
    set((s) => ({
      runs: s.runs.map((r) =>
        r.id === runId ? { ...r, completed: scanned, total, findings } : r,
      ),
    })),
  applyComplete: ({ runId, status, completed, errors, findings }) =>
    set((s) => ({
      runs: s.runs.map((r) =>
        r.id === runId
          ? {
              ...r,
              status: (status === 'stopped' ? 'stopped' : 'complete') as ActiveScanRun['status'],
              completed: completed ?? r.completed,
              errors: errors ?? r.errors,
              findings,
            }
          : r,
      ),
    })),
  removeRun: (id) => set((s) => ({ runs: s.runs.filter((r) => r.id !== id) })),
  clear: () => set({ runs: [] }),
}))
