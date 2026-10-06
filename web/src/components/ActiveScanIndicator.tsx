import { Scan } from 'lucide-react'
import { useActiveScanStore } from '../stores/activeScanStore'

// A small fixed pill shown while an active scan runs. It derives the running run
// from the shared run list. Findings surface in the Detect tab; this only reports
// progress.
export default function ActiveScanIndicator() {
  const run = useActiveScanStore((s) => s.runs.find((r) => r.status === 'running'))
  if (!run) return null
  const pct = run.total > 0 ? Math.min(100, Math.round((run.completed / run.total) * 100)) : 0
  return (
    <div className="fixed bottom-3 right-3 z-50 w-64 rounded-md border border-border bg-surface-card shadow-lg">
      <div className="flex items-center gap-2 px-3 py-2">
        <Scan size={14} strokeWidth={1.8} className="text-accent-tertiary animate-pulse" />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[11px] font-semibold text-content-primary">Scanning {run.host}</div>
          <div className="text-[10px] text-content-muted">
            {run.completed} of {run.total} · {run.findings} finding{run.findings === 1 ? '' : 's'}
          </div>
        </div>
      </div>
      <div className="h-1 overflow-hidden rounded-b-md bg-surface-input">
        <div className="h-full bg-accent-tertiary transition-all" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}
