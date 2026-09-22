import { useCallback, useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { FileJson, Search } from 'lucide-react'
import { api } from '../lib/api'
import { useSJStore, type SJSubTab, type SJProfile } from '../stores/sjStore'
import type { SJNavState } from '../lib/sjTypes'
import type { RequestDetail } from '../stores/requestStore'
import SJDocumentBar from '../components/sj/SJDocumentBar'
import SJDocumentModal, { type DocTab } from '../components/sj/SJDocumentModal'
import SJProfilesModal from '../components/sj/SJProfilesModal'
import SJOperationsView from '../components/sj/SJOperationsView'
import SJAutomateView from '../components/sj/SJAutomateView'
import SJMatrixPanel from '../components/sj/SJMatrixPanel'
import SJBruteView from '../components/sj/SJBruteView'

function SubTabButton({
  active, onClick, children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1.5 rounded-sm text-xs transition-colors ${
        active
          ? 'bg-accent text-content-primary'
          : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
      }`}
    >
      {children}
    </button>
  )
}

export default function SJ() {
  const location = useLocation()
  const navigate = useNavigate()
  const store = useSJStore()
  const { tabs, activeTabId } = store
  const tab = tabs.find((t) => t.id === activeTabId) ?? tabs[0]
  const [docModal, setDocModal] = useState<DocTab | null>(null)
  const [profilesOpen, setProfilesOpen] = useState(false)

  /** applyLoadFailure turns a rejection into either an error or, for the very
   *  common "that was the Swagger UI page" case, a pre-filled Brute tab. */
  const applyLoadFailure = useCallback((tabId: string, e: unknown) => {
    const err = e as { message?: string; body?: unknown }
    const body = (err as { body?: { kind?: string; candidates?: string[]; sourceUrl?: string } }).body
    if (body?.kind === 'html') {
      const t = useSJStore.getState().tabs.find((x) => x.id === tabId)
      store.updateTab(tabId, {
        loading: false,
        subTab: 'brute',
        htmlHint: {
          message:
            'That URL served the Swagger UI page, not a document. These are the paths it loads from.',
          candidates: body.candidates ?? [],
          sourceUrl: body.sourceUrl ?? '',
        },
        discover: {
          ...(t?.discover ?? { scheme: 'https', host: '', basePath: '', full: false, stopOnFirst: false }),
          ...hostFromURL(body.sourceUrl ?? ''),
        },
      })
      return
    }
    store.updateTab(tabId, { loading: false, loadError: String(err?.message ?? e) })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Inbound "Send to SJ" from History, Detect or Manipulate. A requestId is
  // preferred over inline bytes: a multi-megabyte document passed through
  // location.state would ride in history.pushState's structured clone on every
  // later navigation.
  useEffect(() => {
    const st = location.state as SJNavState | null
    if (!st || (!st.requestId && !st.respRaw)) return
    void loadFromNav(st)
    navigate('/sj', { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.state])

  // Rehydrate anything still marked running. Results arrive over the WebSocket,
  // so a reload or a dropped socket would otherwise lose a run the server is
  // still holding — and for a 200-request scan that is the whole thing.
  useEffect(() => {
    void resyncRuns()
    const handler = () => void resyncRuns()
    window.addEventListener('joro:ws-reconnected', handler)
    return () => window.removeEventListener('joro:ws-reconnected', handler)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function resyncRuns() {
    const s = useSJStore.getState()
    for (const t of s.tabs) {
      for (const run of [t.scanRun, t.matrixRun, t.discoverRun]) {
        if (!run || run.status !== 'running') continue
        try {
          const detail = await api.sjGetRun(run.id, { limit: 5000 })
          // filter(Boolean) is not enough: unfilled slots come back as
          // zero-valued objects, which are truthy. No triage, no error and no
          // status means it was never sent.
          s.addRunResults(
            run.id,
            detail.results.filter((r) => r && (r.triage || r.error || r.status)),
          )
          if (detail.status !== 'running') s.setRunStatus(run.id, detail.status)
        } catch {
          // The run is gone from the server (evicted, or the server restarted).
          // Leave what we have rather than blanking the table.
          s.setRunStatus(run.id, 'stopped')
        }
      }
    }
  }

  async function loadFromNav(st: SJNavState) {
    const id = targetTabForLoad()
    store.updateTab(id, { loading: true, name: st.name || 'Loading…' })
    try {
      let raw = st.respRaw
      let url = st.url
      if (st.requestId) {
        const detail = (await api.getRequest(st.requestId)) as RequestDetail
        raw = detail.respRaw
        url = url || detail.url
      }
      const res = await api.sjLoad({ raw, url })
      store.setSpec(id, res.spec)
    } catch (e) {
      applyLoadFailure(id, e)
    }
  }

  /** targetTabForLoad reuses an empty slot and otherwise opens a new one, so
   *  loading a second document never silently replaces the first. */
  function targetTabForLoad(): string {
    const current = useSJStore.getState().tabs.find((t) => t.id === useSJStore.getState().activeTabId)
    if (current && !current.spec) return current.id
    return store.addTab()
  }

  function setProfiles(next: SJProfile[]) {
    store.updateTab(tab.id, { profiles: next })
    if (!tab.spec) return
    void api
      .sjSetProfiles(tab.spec.id, next.map((p, i) => ({ ...p, rank: i })))
      .catch(() => {})
  }

  const hasSpec = !!tab.spec
  const go = (subTab: SJSubTab) => store.updateTab(tab.id, { subTab })

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <SJDocumentBar
        tab={tab}
        onOpenDoc={(d) => setDocModal(d)}
        onLoadNew={() => {
          const id = targetTabForLoad()
          store.setActiveTab(id)
          setDocModal('load')
        }}
        onOpenProfiles={() => setProfilesOpen(true)}
      />

      <div className="flex items-center gap-0.5 px-2 py-1 bg-surface-card border-b border-border shrink-0">
        <SubTabButton active={tab.subTab === 'operations'} onClick={() => go('operations')}>
          Operations
        </SubTabButton>
        <SubTabButton active={tab.subTab === 'automate'} onClick={() => go('automate')}>
          Automate
        </SubTabButton>
        <SubTabButton active={tab.subTab === 'matrix'} onClick={() => go('matrix')}>
          Auth Matrix
        </SubTabButton>
        {/* Brute needs no document — it is how you find one. */}
        <SubTabButton active={tab.subTab === 'brute'} onClick={() => go('brute')}>
          Brute
        </SubTabButton>
      </div>

      {tab.subTab === 'brute' ? (
        <SJBruteView tab={tab} onFailure={applyLoadFailure} />
      ) : !hasSpec ? (
        <NoDocument onLoad={() => setDocModal('load')} onBrute={() => go('brute')} />
      ) : tab.subTab === 'operations' ? (
        <SJOperationsView tab={tab} />
      ) : tab.subTab === 'automate' ? (
        <SJAutomateView tab={tab} />
      ) : (
        <SJMatrixPanel tab={tab} onOpenProfiles={() => setProfilesOpen(true)} />
      )}

      {docModal && (
        <SJDocumentModal
          tab={tab}
          initialTab={docModal}
          onFailure={applyLoadFailure}
          onClose={() => setDocModal(null)}
          onBrute={() => go('brute')}
        />
      )}

      {profilesOpen && (
        <SJProfilesModal
          profiles={tab.profiles}
          schemes={tab.spec?.auth ?? []}
          onChange={setProfiles}
          onClose={() => setProfilesOpen(false)}
        />
      )}
    </div>
  )
}

function NoDocument({ onLoad, onBrute }: { onLoad: () => void; onBrute: () => void }) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center px-6">
      <FileJson size={26} className="text-content-muted" strokeWidth={1.5} />
      <div className="text-sm text-content-secondary">No document loaded</div>
      <div className="text-xs text-content-muted max-w-md">
        Load a Swagger 2.0 or OpenAPI 3.x document to browse its operations, craft requests
        against them, and run them through Joro's proxy so they land in History and Detect.
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={onLoad}
          className="px-4 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
        >
          Load a document
        </button>
        <button
          onClick={onBrute}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs"
        >
          <Search size={12} /> Brute-force for one
        </button>
      </div>
    </div>
  )
}

function hostFromURL(raw: string): { scheme?: string; host?: string } {
  try {
    const u = new URL(raw)
    return { scheme: u.protocol.replace(':', ''), host: u.host }
  } catch {
    return {}
  }
}
