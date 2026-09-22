import { Flag, RotateCcw } from 'lucide-react'
import { cellPill, isFinding, variantKindLabel, verdictPill } from '../../lib/chainStatus'
import type { ChainRun } from '../../stores/chainStore'

interface Props {
  run: ChainRun
  onSelect: (index: number) => void
  selectedIndex: number | null
}

// The grid is variants down, steps across.
//
// Slots are addressed arithmetically — variantIndex*stride + stepIndex — which is
// the shape the server writes them in, so a cell that never ran is a hole rather
// than a missing row, and reads as "not run" instead of silently shifting every
// cell after it left.
export default function ChainGrid({ run, onSelect, selectedIndex }: Props) {
  if (run.steps.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center text-content-muted text-sm">
        Waiting for the run to start…
      </div>
    )
  }

  return (
    <div className="flex-1 min-h-0 overflow-auto">
      <table className="text-xs border-collapse">
        <thead className="sticky top-0 bg-surface-card z-10">
          <tr>
            <th className="text-left px-2 py-1.5 border-b border-border font-normal text-content-secondary sticky left-0 bg-surface-card min-w-56">
              Variant
            </th>
            {run.steps.map((s) => (
              <th
                key={s.id}
                className="px-2 py-1.5 border-b border-border font-normal text-content-secondary whitespace-nowrap"
                title={s.label}
              >
                <span className="flex items-center gap-1">
                  {s.setup && <RotateCcw size={10} className="text-semantic-info" />}
                  {s.goal && <Flag size={10} className="text-accent-secondary" />}
                  <span className="truncate max-w-32 inline-block">{s.label}</span>
                </span>
              </th>
            ))}
            <th className="text-left px-2 py-1.5 border-b border-border font-normal text-content-secondary">
              Verdict
            </th>
          </tr>
        </thead>
        <tbody>
          {run.variants.map((v, vi) => {
            const verdict = run.verdicts[v.id]
            return (
              <tr
                key={v.id}
                className={isFinding(verdict?.verdict) ? 'bg-semantic-error-bg/40' : ''}
              >
                <td className="px-2 py-1 border-b border-border-subtle sticky left-0 bg-surface-body">
                  <span className="text-content-muted mr-1.5">{variantKindLabel(v.kind)}</span>
                  <span className="text-content-primary">{v.label}</span>
                </td>
                {run.steps.map((s, si) => {
                  const idx = vi * (run.stride || run.steps.length) + si
                  const cell = run.results[idx]
                  return (
                    <td
                      key={s.id}
                      className={`px-2 py-1 border-b border-border-subtle text-center cursor-pointer hover:bg-surface-hover ${
                        selectedIndex === idx ? 'bg-surface-hover' : ''
                      }`}
                      onClick={() => cell?.cell && onSelect(idx)}
                    >
                      {cellPill(cell?.cell, cell?.status ?? 0, cell?.note)}
                    </td>
                  )
                })}
                <td className="px-2 py-1 border-b border-border-subtle whitespace-nowrap">
                  {verdictPill(verdict?.verdict, verdict?.detail)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
