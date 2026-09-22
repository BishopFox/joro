import { useState } from 'react'
import { Circle, Link2, Save, Square, Trash2 } from 'lucide-react'
import { api } from '../../lib/api'
import { useChainStore } from '../../stores/chainStore'
import { useToastStore } from '../../stores/toastStore'
import type { Chain } from '../../lib/chainTypes'

interface Props {
  recording: number | null
  onStartRecord: () => void
  onStopRecord: () => void
  onSave: () => void
  onCorrelate: () => void
}

export default function ChainBar({
  recording, onStartRecord, onStopRecord, onSave, onCorrelate,
}: Props) {
  const store = useChainStore()
  const addToast = useToastStore((s) => s.addToast)
  const [renaming, setRenaming] = useState(false)

  const active = store.active

  async function open(id: string) {
    try {
      const chain = await api.chainGet(id)
      store.setActive(chain)
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  async function remove(chain: Chain) {
    try {
      await api.chainDelete(chain.id)
      store.setActive(null)
      const { chains } = await api.chainList()
      store.setChains(chains)
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  return (
    <div className="flex items-center gap-2 px-2 py-1.5 bg-surface-card border-b border-border shrink-0">
      <select
        className="bg-surface-input border border-border rounded px-2 py-1 text-xs text-content-primary max-w-56"
        value={active?.id ?? ''}
        onChange={(e) => (e.target.value ? open(e.target.value) : store.setActive(null))}
      >
        <option value="">Select a chain…</option>
        {store.chains.map((c) => (
          <option key={c.id} value={c.id}>
            {c.name} ({c.steps} steps)
          </option>
        ))}
      </select>

      {active && (
        <>
          {renaming ? (
            <input
              autoFocus
              className="bg-surface-input border border-border rounded px-2 py-1 text-xs text-content-primary"
              value={active.name}
              onChange={(e) => store.patchActive((c) => ({ ...c, name: e.target.value }))}
              onBlur={() => setRenaming(false)}
              onKeyDown={(e) => e.key === 'Enter' && setRenaming(false)}
            />
          ) : (
            <button
              className="text-xs text-content-primary hover:text-accent-secondary"
              onClick={() => setRenaming(true)}
              title="Rename"
            >
              {active.name}
            </button>
          )}
          <span className="text-[11px] text-content-muted">
            {active.steps.length} steps · {active.bindings.length} bindings
          </span>
        </>
      )}

      <div className="flex-1" />

      {active && (
        <>
          <button
            onClick={onCorrelate}
            className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-surface-input text-content-primary"
            title="Look for values a later step takes from an earlier response"
          >
            <Link2 size={12} /> Correlate
          </button>
          <button
            onClick={onSave}
            disabled={!store.activeDirty}
            className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-accent-secondary text-black disabled:opacity-40"
          >
            <Save size={12} /> {store.activeDirty ? 'Save' : 'Saved'}
          </button>
          <button
            onClick={() => remove(active)}
            className="text-content-muted hover:text-semantic-error"
            title="Delete this chain"
          >
            <Trash2 size={13} />
          </button>
        </>
      )}

      {recording === null ? (
        <button
          onClick={onStartRecord}
          className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-surface-input text-content-primary"
          title="Mark the capture buffer, browse the workflow, then stop to pick the steps"
        >
          <Circle size={12} className="text-semantic-error" /> Record
        </button>
      ) : (
        <button
          onClick={onStopRecord}
          className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-semantic-error-bg text-content-primary"
        >
          <Square size={12} /> Stop recording
        </button>
      )}
    </div>
  )
}
