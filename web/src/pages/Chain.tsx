import { useCallback, useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { api } from '../lib/api'
import { useResizable } from '../lib/useResizable'
import { useChainStore } from '../stores/chainStore'
import { useToastStore } from '../stores/toastStore'
import type { Chain, ChainNavState, ChainRecordCandidate } from '../lib/chainTypes'
import ChainBar from '../components/chain/ChainBar'
import ChainMap from '../components/chain/ChainMap'
import ChainStepInspector from '../components/chain/ChainStepInspector'
import ChainSweepView from '../components/chain/ChainSweepView'
import ChainRecordModal from '../components/chain/ChainRecordModal'

type SubTab = 'map' | 'sweep'

function SubTabButton({
  active, onClick, children,
}: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1 text-xs rounded ${
        active ? 'bg-surface-input text-accent' : 'text-content-secondary hover:text-content-primary'
      }`}
    >
      {children}
    </button>
  )
}

export default function Chain() {
  const store = useChainStore()
  const addToast = useToastStore((s) => s.addToast)
  const navigate = useNavigate()
  const location = useLocation()
  const split = useResizable('horizontal', 0.62)

  const [subTab, setSubTab] = useState<SubTab>('map')
  const [recording, setRecording] = useState<number | null>(null)
  const [candidates, setCandidates] = useState<ChainRecordCandidate[] | null>(null)

  const active = store.active

  const refreshChains = useCallback(async () => {
    try {
      const { chains } = await api.chainList()
      store.setChains(chains)
      return chains
    } catch {
      return []
    }
  }, [store])

  useEffect(() => {
    void refreshChains()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Inbound from History's "Add to Chain". Seqs, never bytes: the server still
  // has the captures and history.pushState would have to structured-clone them.
  useEffect(() => {
    const nav = location.state as ChainNavState | null
    if (!nav?.seqs?.length) return
    navigate('/chain', { replace: true })
    api
      .chainFromHistory(nav.seqs, nav.name)
      .then(async (chain) => {
        store.setActive(chain)
        if (chain.warning) addToast(chain.warning, 'info')
        await refreshChains()
      })
      .catch((e) => addToast(String((e as Error).message ?? e), 'error'))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.state])

  // Server-owned run state is re-synced on mount and on reconnect: events
  // emitted while the socket was down are gone for good, because the hub
  // broadcast is non-blocking and has no replay.
  const resyncRuns = useCallback(async () => {
    const ids = Object.keys(useChainStore.getState().runs)
    for (const id of ids) {
      const run = useChainStore.getState().runs[id]
      if (run.status !== 'running') continue
      try {
        const detail = await api.chainGetRun(id, { limit: 5000 })
        store.updateRun(id, {
          status: detail.status,
          total: detail.total,
          stride: detail.stride,
          steps: detail.steps,
          variants: detail.variants,
          results: detail.results.filter(Boolean),
          verdicts: Object.fromEntries(detail.verdicts.map((v) => [v.variantId, v])),
        })
      } catch {
        // Mark it stopped rather than blanking the grid: the rows already
        // collected still describe real requests.
        store.updateRun(id, { status: 'stopped' })
      }
    }
  }, [store])

  useEffect(() => {
    void resyncRuns()
    const onReconnect = () => void resyncRuns()
    window.addEventListener('joro:ws-reconnected', onReconnect)
    return () => window.removeEventListener('joro:ws-reconnected', onReconnect)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // A newly started run carries only its head; the step and variant headers come
  // from the server so the grid can draw its axes before the first cell lands.
  useEffect(() => {
    const id = store.activeRunId
    if (!id) return
    const run = store.runs[id]
    if (!run || run.steps.length > 0) return
    api
      .chainGetRun(id, { limit: 1 })
      .then((d) => store.updateRun(id, { steps: d.steps, variants: d.variants, stride: d.stride }))
      .catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [store.activeRunId, store.runs[store.activeRunId ?? '']?.steps.length])

  async function save() {
    if (!active) return
    try {
      const saved = await api.chainUpdate(active.id, {
        name: active.name,
        goalStepId: active.goalStepId,
        steps: active.steps.map((s) => ({
          id: s.id,
          label: s.label,
          scheme: s.scheme,
          host: s.host,
          reqRaw: s.reqRaw,
          respRaw: s.respRaw,
          originSeq: s.originSeq,
          setup: s.setup,
          edits: s.edits,
        })),
        bindings: active.bindings,
      })
      store.setActive(saved)
      await refreshChains()
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  async function correlate() {
    if (!active) return
    try {
      const { proposed } = await api.chainCorrelate(active.id)
      const additions = proposed.filter((p) => p.isNew).map((p) => p.binding)
      if (additions.length === 0) {
        addToast('No new dependencies found', 'info')
        return
      }
      // Appended, never replacing: a re-run must not discard a binding the
      // operator hand-wrote or whose onMissing they changed.
      store.patchActive((c) => ({ ...c, bindings: [...c.bindings, ...additions] }))
      addToast(`Added ${additions.length} binding${additions.length === 1 ? '' : 's'}`, 'info')
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  async function startRecord() {
    try {
      const { cursor } = await api.chainRecordStart()
      setRecording(cursor)
      addToast('Recording - browse the workflow, then stop', 'info')
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  async function stopRecord() {
    if (recording === null) return
    try {
      const { candidates: got } = await api.chainRecordStop(recording)
      setRecording(null)
      setCandidates(got)
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  async function createFromCandidates(seqs: number[], name: string) {
    try {
      const chain = await api.chainFromHistory(seqs, name)
      setCandidates(null)
      store.setActive(chain)
      if (chain.warning) addToast(chain.warning, 'info')
      await refreshChains()
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  const selectedStep = active?.steps.find((s) => s.id === store.selectedStepId)

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <ChainBar
        recording={recording}
        onStartRecord={startRecord}
        onStopRecord={stopRecord}
        onSave={save}
        onCorrelate={correlate}
      />

      {active && (
        <div className="flex items-center gap-0.5 px-2 py-1 bg-surface-card border-b border-border shrink-0">
          <SubTabButton active={subTab === 'map'} onClick={() => setSubTab('map')}>
            Map
          </SubTabButton>
          <SubTabButton active={subTab === 'sweep'} onClick={() => setSubTab('sweep')}>
            Sweep
          </SubTabButton>
        </div>
      )}

      {!active ? (
        <NoChain />
      ) : subTab === 'map' ? (
        <div ref={split.containerRef} className="flex flex-1 min-h-0">
          <div style={{ width: `${split.fraction * 100}%` }} className="flex flex-col min-h-0">
            <ChainMap
              chain={active}
              selectedStepId={store.selectedStepId}
              selectedBindingId={store.selectedBindingId}
              onSelect={(id, bindingId) => store.select(id, bindingId)}
              onChange={(c: Chain) => store.patchActive(() => c)}
              onCorrelate={correlate}
            />
          </div>
          <div className="drag-handle-h" {...split.handleProps} />
          <div className="flex-1 min-w-0 border-l border-border overflow-hidden">
            {selectedStep ? (
              <ChainStepInspector
                chain={active}
                step={selectedStep}
                selectedBindingId={store.selectedBindingId}
                onChange={(c) => store.patchActive(() => c)}
              />
            ) : (
              <div className="p-4 text-xs text-content-muted">
                Select a step to see what it needs, what it produces, and whether it is setup or
                the goal. Drag a step by its grip to reorder the chain, or move the focused one
                with Alt+Up / Alt+Down.
              </div>
            )}
          </div>
        </div>
      ) : (
        <ChainSweepView chain={active} />
      )}

      {candidates && (
        <ChainRecordModal
          candidates={candidates}
          onClose={() => setCandidates(null)}
          onCreate={createFromCandidates}
        />
      )}
    </div>
  )
}

function NoChain() {
  return (
    <div className="flex-1 flex items-center justify-center px-8">
      <div className="max-w-lg text-center">
        <div className="text-content-primary text-sm mb-2">No chain open</div>
        <div className="text-content-secondary text-xs leading-relaxed">
          A chain is an ordered workflow - a checkout, a password reset - plus the values each
          step takes from an earlier response. Once those are mapped, Joro can replay the
          workflow with a step skipped, repeated or moved, and say whether the application
          noticed.
        </div>
        <div className="text-content-muted text-xs mt-3 leading-relaxed">
          Press <em>Record</em>, walk the workflow in the browser, then pick the steps out of
          what was captured - the quickest way to build one. Or right-click a request in
          History and choose <em>Add to Chain</em>, once per step; each one is appended to the
          chain that is open here and re-correlated against the steps before it.
        </div>
      </div>
    </div>
  )
}
