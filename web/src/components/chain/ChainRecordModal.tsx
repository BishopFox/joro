import { useState } from 'react'
import { X } from 'lucide-react'
import { methodClass } from '../../lib/chainStatus'
import type { ChainRecordCandidate } from '../../lib/chainTypes'

interface Props {
  candidates: ChainRecordCandidate[]
  onClose: () => void
  onCreate: (seqs: number[], name: string) => void
}

// Recording hands back candidates to trim rather than building a chain outright.
//
// A workflow's traffic is mostly not the workflow: analytics beacons, fonts,
// polling. A chain built from an unreviewed window would be almost entirely
// noise, and the trimming is faster here than deleting steps from a map.
export default function ChainRecordModal({ candidates, onClose, onCreate }: Props) {
  const [picked, setPicked] = useState<Set<number>>(
    // Seed with the requests that plausibly are the workflow: anything that
    // changes state, plus documents and API responses. Everything else is one
    // click away.
    () => new Set(candidates.filter(isLikelyStep).map((c) => c.seq)),
  )
  const [name, setName] = useState('chain')

  const toggle = (seq: number) =>
    setPicked((p) => {
      const next = new Set(p)
      if (next.has(seq)) next.delete(seq)
      else next.add(seq)
      return next
    })

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="bg-surface-card border border-border rounded w-[46rem] max-h-[80vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-3 py-2 border-b border-border">
          <span className="text-sm text-content-primary">
            Pick the steps of this workflow
          </span>
          <button onClick={onClose} className="text-content-muted hover:text-content-primary">
            <X size={14} />
          </button>
        </div>

        <div className="px-3 py-2 border-b border-border flex items-center gap-2">
          <label className="text-xs text-content-secondary">Name</label>
          <input
            className="bg-surface-input border border-border rounded px-2 py-1 text-xs text-content-primary flex-1"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <span className="text-[11px] text-content-muted">{picked.size} selected</span>
          <button
            className="text-[11px] text-accent-secondary"
            onClick={() => setPicked(new Set(candidates.map((c) => c.seq)))}
          >
            all
          </button>
          <button className="text-[11px] text-accent-secondary" onClick={() => setPicked(new Set())}>
            none
          </button>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto">
          {candidates.length === 0 && (
            <div className="p-4 text-xs text-content-muted">
              Nothing was captured while recording.
            </div>
          )}
          {candidates.map((c) => (
            <label
              key={c.seq}
              className="flex items-center gap-2 px-3 py-1 hover:bg-surface-hover cursor-pointer border-b border-border-subtle"
            >
              <input type="checkbox" checked={picked.has(c.seq)} onChange={() => toggle(c.seq)} />
              <span className="text-content-muted font-mono text-[10px] w-10">{c.seq}</span>
              <span className={`font-mono text-[11px] font-bold w-14 ${methodClass(c.method)}`}>
                {c.method}
              </span>
              <span className="text-content-primary text-[11px] truncate flex-1">{c.url}</span>
              <span className="text-content-muted text-[10px] w-8 text-right">{c.status}</span>
            </label>
          ))}
        </div>

        <div className="px-3 py-2 border-t border-border flex justify-end gap-2">
          <button className="px-3 py-1 rounded text-xs bg-surface-input text-content-primary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="px-3 py-1 rounded text-xs bg-accent-secondary text-black disabled:opacity-40"
            disabled={picked.size === 0}
            onClick={() => onCreate([...picked].sort((a, b) => a - b), name)}
          >
            Create chain
          </button>
        </div>
      </div>
    </div>
  )
}

function isLikelyStep(c: ChainRecordCandidate): boolean {
  if (c.method !== 'GET') return true
  const ct = (c.contentType || '').toLowerCase()
  return ct.includes('json') || ct.includes('html')
}
