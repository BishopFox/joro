import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { FileJson, ChevronDown, Plus, X, AlertTriangle, Circle, SlidersHorizontal } from 'lucide-react'
import { api } from '../../lib/api'
import { useSJStore, tabLosses, anyLoss, type SJTab, type SJLosses } from '../../stores/sjStore'
import { useToastStore } from '../../stores/toastStore'
import ConfirmModal from '../ConfirmModal'
import type { SJSpec, SJPlaceholders } from '../../lib/sjTypes'
import type { DocTab } from './SJDocumentModal'

/** The document bar: what you are working on, where it points, and who you are.
 *
 *  These three were previously spread across a sub-tab, a toolbar that vanished
 *  on Discover, and a panel buried inside the Auth Matrix. They are all
 *  properties of the document, so they belong together and above the work. */
export default function SJDocumentBar({
  tab,
  onOpenDoc,
  onLoadNew,
  onOpenProfiles,
}: {
  tab: SJTab
  onOpenDoc: (docTab: DocTab) => void
  /** Opens the loader against a fresh document slot, so loading a second
   *  document does not silently replace the one in front of you. */
  onLoadNew: () => void
  onOpenProfiles: () => void
}) {
  const store = useSJStore()
  const { tabs } = store
  const spec = tab.spec
  const diagnostics = spec?.diagnostics?.length ?? 0
  const [confirming, setConfirming] = useState<{ id: string; name: string; losses: SJLosses } | null>(null)

  /** unloadDocument removes a document everywhere, not just from the list.
   *
   *  Order matters: stop the runs, delete them, then the document, then the tab.
   *  The server keeps a parsed document, its source bytes and its auth profile
   *  credentials until told otherwise, and nothing used to tell it. */
  async function unloadDocument(id: string) {
    const target = useSJStore.getState().tabs.find((t) => t.id === id)
    if (!target) return

    const runs = [target.scanRun, target.matrixRun, target.discoverRun].filter(Boolean)
    for (const r of runs) {
      if (r!.status === 'running') await api.sjStopRun(r!.id).catch(() => {})
      await api.sjDeleteRun(r!.id).catch(() => {})
    }

    // Only when nothing else holds it. A spec id is a hash of the document's
    // bytes, so the same document loaded twice is one server-side entry behind
    // two tabs — deleting unconditionally would 404 every render, send and scan
    // the survivor makes.
    const specID = target.spec?.id
    if (specID) {
      const stillReferenced = useSJStore
        .getState()
        .tabs.some((t) => t.id !== id && t.spec?.id === specID)
      if (!stillReferenced) await api.sjDeleteSpec(specID).catch(() => {})
    }

    store.removeTab(id)
  }

  /** requestUnload confirms only when something would actually be lost. */
  function requestUnload(id: string) {
    const target = useSJStore.getState().tabs.find((t) => t.id === id)
    if (!target) return
    const losses = tabLosses(target)
    if (!anyLoss(losses)) {
      void unloadDocument(id)
      return
    }
    setConfirming({ id, name: target.name, losses })
  }

  return (
    <div className="flex items-center gap-2 px-2 py-1.5 bg-surface-card border-b border-border shrink-0 flex-wrap">
      <DocumentPicker
        tab={tab}
        tabs={tabs}
        onOpenDoc={onOpenDoc}
        onLoadNew={onLoadNew}
        onUnload={requestUnload}
      />

      {spec ? (
        <>
          {spec.servers.length > 1 && (
            <select
              value={tab.serverIndex}
              onChange={(e) => {
                const i = Number(e.target.value)
                const srv = spec.servers[i]
                store.updateTab(tab.id, {
                  serverIndex: i,
                  scheme: srv.scheme || 'https',
                  host: srv.host || '',
                  basePath: srv.basePath ?? '',
                })
              }}
              className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              title="This document declares more than one server"
            >
              {spec.servers.map((s, i) => (
                // Labelled with the resolved address, not the raw url: a document
                // using server variables writes "{protocol}://{host}" there, and
                // picking between two of those says nothing about where the
                // request goes.
                <option key={i} value={i} title={s.url}>
                  {s.host ? `${s.scheme || 'https'}://${s.host}${s.basePath || ''}` : s.url}
                </option>
              ))}
            </select>
          )}

          <select
            value={tab.scheme}
            onChange={(e) => store.updateTab(tab.id, { scheme: e.target.value })}
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
          >
            <option value="https">https</option>
            <option value="http">http</option>
          </select>
          <input
            value={tab.host}
            onChange={(e) => store.updateTab(tab.id, { host: e.target.value })}
            placeholder="host"
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border flex-1 min-w-40 max-w-xs"
          />
          <input
            value={tab.basePath}
            onChange={(e) => store.updateTab(tab.id, { basePath: e.target.value })}
            placeholder="/base"
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-28"
          />
          {/* Reaches every sub-tab from here, so a run and a single send agree.
              A User-Agent set on an auth profile outranks it. */}
          <input
            value={tab.userAgent}
            onChange={(e) => store.updateTab(tab.id, { userAgent: e.target.value })}
            placeholder="User-Agent (default: Chrome)"
            title="Sent with every request from this document. Empty sends a browser default."
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-64"
          />

          <PlaceholderControl spec={spec} />

          {/* The profile a single send and an Automate run authenticate as. The
              Auth Matrix picks its own set, since it runs several at once. */}
          <label className="flex items-center gap-1.5 text-xs text-content-muted ml-auto">
            Auth
            <select
              value={tab.activeProfileId}
              onChange={(e) => {
                if (e.target.value === '__manage') {
                  onOpenProfiles()
                  return
                }
                store.updateTab(tab.id, { activeProfileId: e.target.value })
              }}
              className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
            >
              <option value="">none</option>
              {tab.profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label || p.id}
                </option>
              ))}
              <option value="__manage">Manage profiles…</option>
            </select>
          </label>

          {diagnostics > 0 && (
            <button
              onClick={() => onOpenDoc('diagnostics')}
              className="flex items-center gap-1 px-2 py-1.5 rounded-sm text-xs text-semantic-warning hover:bg-surface-input"
              title="Some of this document could not be resolved"
            >
              <AlertTriangle size={13} /> {diagnostics}
            </button>
          )}
        </>
      ) : (
        <span className="text-xs text-content-muted">
          No document loaded - load one, or use Brute to find one.
        </span>
      )}

      {/* Rendered from the bar, not the dropdown: the panel closes on any
          outside mousedown, so a modal inside it would dismiss itself. */}
      {confirming && (
        <ConfirmModal
          title={`Unload ${confirming.name}?`}
          message="Its auth profiles, edited requests and run results are discarded. The document itself can be loaded again - the fetch that retrieved it is in History."
          body={<LossList losses={confirming.losses} />}
          confirmLabel="Unload"
          deliberate
          onConfirm={() => {
            const id = confirming.id
            setConfirming(null)
            void unloadDocument(id)
          }}
          onClose={() => setConfirming(null)}
        />
      )}
    </div>
  )
}

/** LossList names what unloading costs. Credentials are the reason this
 *  confirmation exists at all: the API returns whether a profile holds a value
 *  and never the value, so a token typed ten minutes ago is unrecoverable. */
function LossList({ losses }: { losses: SJLosses }) {
  const items: string[] = []
  if (losses.profiles > 0) {
    items.push(`${losses.profiles} auth profile${losses.profiles === 1 ? '' : 's'} (credentials)`)
  }
  if (losses.drafts > 0) {
    items.push(`${losses.drafts} edited request${losses.drafts === 1 ? '' : 's'}`)
  }
  if (losses.running > 0) {
    items.push(`${losses.running} run${losses.running === 1 ? '' : 's'} still in flight`)
  }
  if (losses.results > 0) {
    items.push(`results from ${losses.results} finished run${losses.results === 1 ? '' : 's'}`)
  }
  return (
    <ul className="text-xs text-content-muted list-disc pl-4 space-y-0.5">
      {items.map((t) => (
        <li key={t}>{t}</li>
      ))}
    </ul>
  )
}

/** The document chip and its dropdown.
 *
 *  Fixed-position panel, for the reason ProjectSwitcher documents: an absolutely
 *  positioned one is clipped by a header that scrolls horizontally. */
/** PlaceholderControl sets the values this document's requests are generated
 *  from: the test string in the bar, the date, URL and email behind the gear.
 *
 *  Committing re-parses the document server-side, because a placeholder is baked
 *  into every generated default and body at parse time rather than substituted
 *  per request — which is why this commits on blur and Enter and never on
 *  change. Values the operator has typed into a parameter or body outrank a
 *  generated one and survive the re-parse.
 *
 *  The fields show the *effective* values, so clearing one and committing brings
 *  the server's default back visibly. */
function PlaceholderControl({ spec }: { spec: SJSpec }) {
  const store = useSJStore()
  const addToast = useToastStore((s) => s.addToast)
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState({ top: 0, left: 0 })
  const [saving, setSaving] = useState(false)
  const [draft, setDraft] = useState<SJPlaceholders>(spec.placeholders)
  const btnRef = useRef<HTMLButtonElement>(null)

  // Re-seeded from the parse, so a change made against this document in another
  // tab is reflected here rather than overwritten by a stale draft.
  useEffect(() => setDraft(spec.placeholders), [spec.placeholders])

  useLayoutEffect(() => {
    if (!open || !btnRef.current) return
    const r = btnRef.current.getBoundingClientRect()
    setPos({ top: r.bottom + 4, left: r.left })
  }, [open])

  useEffect(() => {
    if (!open) return
    // Clicking away commits, exactly as blurring the string input does. Reverting
    // instead would race that blur — both fire for one click — and would make the
    // two halves of one control disagree about what dismissing it means.
    function onDown(e: MouseEvent) {
      const t = e.target as HTMLElement
      if (!t.closest('[data-sj-phmenu]')) {
        setOpen(false)
        void commit(draft)
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setDraft(spec.placeholders)
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', onDown, true)
    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('mousedown', onDown, true)
      document.removeEventListener('keydown', onKey, true)
    }
  }, [open, draft, spec.placeholders])

  async function commit(next: SJPlaceholders) {
    const cur = spec.placeholders
    // Also the guard against the two dismiss paths firing for one click: a blur
    // and an outside-mousedown both land before the first reply does.
    if (
      saving ||
      (next.string === cur.string && next.date === cur.date &&
        next.url === cur.url && next.email === cur.email)
    ) {
      return
    }
    setSaving(true)
    try {
      const res = await api.sjSetPlaceholders(spec.id, next)
      store.setSpecParse(spec.id, res.spec)
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
      setDraft(spec.placeholders)
    } finally {
      setSaving(false)
    }
  }

  const field = 'bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border'

  return (
    <div className="flex items-center gap-1.5 text-xs text-content-muted" data-sj-phmenu>
      <label className="flex items-center gap-1.5">
        Placeholder
        <input
          value={draft.string}
          disabled={saving}
          onChange={(e) => setDraft({ ...draft, string: e.target.value })}
          onBlur={() => void commit(draft)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') e.currentTarget.blur()
            if (e.key === 'Escape') setDraft(spec.placeholders)
          }}
          title="Generated for every string a schema gives no example for. Changes what this document's requests contain; values you have edited are kept."
          className={`${field} w-28 text-content-primary`}
        />
      </label>
      <button
        ref={btnRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="Date, URL and email placeholders"
        className="p-1.5 rounded-sm border border-border bg-surface-input hover:text-content-primary hover:border-accent-secondary transition-colors"
      >
        <SlidersHorizontal size={13} strokeWidth={1.8} aria-hidden="true" />
      </button>

      {open && (
        <div
          data-sj-phmenu
          style={{ top: pos.top, left: pos.left }}
          className="fixed z-50 w-72 p-2 rounded-sm bg-surface-card border border-border shadow-lg flex flex-col gap-2"
        >
          {([
            ['date', 'Date', '1990-01-01'],
            ['url', 'URL', 'https://bishopfox.com'],
            ['email', 'Email', 'noreply@localhost.localdomain'],
          ] as const).map(([key, label, hint]) => (
            <label key={key} className="flex flex-col gap-1 text-[11px] text-content-muted">
              {label}
              <input
                value={draft[key]}
                disabled={saving}
                placeholder={hint}
                onChange={(e) => setDraft({ ...draft, [key]: e.target.value })}
                className={`${field} w-full text-content-primary`}
              />
            </label>
          ))}
          <p className="text-[10px] text-content-muted">
            Used where a property name or schema format asks for that shape. Empty restores
            the default.
          </p>
          <button
            type="button"
            disabled={saving}
            onClick={() => {
              setOpen(false)
              void commit(draft)
            }}
            className="self-end px-2 py-1 rounded-sm text-[11px] bg-accent-secondary text-black hover:bg-accent-secondary-hover transition-colors"
          >
            Apply
          </button>
        </div>
      )}
    </div>
  )
}

function DocumentPicker({
  tab,
  tabs,
  onOpenDoc,
  onLoadNew,
  onUnload,
}: {
  tab: SJTab
  tabs: SJTab[]
  onOpenDoc: (docTab: DocTab) => void
  onLoadNew: () => void
  onUnload: (tabId: string) => void
}) {
  const store = useSJStore()
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState({ top: 0, left: 0 })
  const btnRef = useRef<HTMLButtonElement>(null)

  useLayoutEffect(() => {
    if (!open || !btnRef.current) return
    const r = btnRef.current.getBoundingClientRect()
    setPos({ top: r.bottom + 4, left: r.left })
  }, [open])

  useEffect(() => {
    if (!open) return
    function onDown(e: MouseEvent) {
      const t = e.target as HTMLElement
      if (!t.closest('[data-sj-docmenu]')) setOpen(false)
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDown, true)
    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('mousedown', onDown, true)
      document.removeEventListener('keydown', onKey, true)
    }
  }, [open])

  const spec = tab.spec
  const label = spec ? spec.title : tab.loading ? 'Loading…' : 'No document'

  return (
    <>
      <button
        ref={btnRef}
        data-sj-docmenu
        onClick={() => setOpen((v) => !v)}
        title="Choose or load a document"
        className="flex items-center gap-1.5 max-w-xs px-2 py-1.5 rounded-sm text-xs bg-surface-input border border-border text-content-secondary hover:text-content-primary hover:border-accent-secondary transition-colors"
      >
        <FileJson size={14} strokeWidth={1.8} className="shrink-0" aria-hidden="true" />
        <span className={`truncate ${spec ? 'text-content-primary' : 'italic text-content-muted'}`}>
          {label}
        </span>
        {spec && (
          <span className="text-content-muted shrink-0">
            {spec.version} · {spec.operations.length} ops
          </span>
        )}
        <ChevronDown size={12} className="shrink-0" aria-hidden="true" />
      </button>

      {open && (
        <div
          data-sj-docmenu
          style={{ position: 'fixed', top: pos.top, left: pos.left }}
          className="w-72 z-50 bg-surface-card border border-border rounded shadow-lg py-1 text-xs"
        >
          <div className="px-2 py-1 text-[10px] uppercase tracking-wide text-content-muted">
            Documents
          </div>
          <div className="max-h-64 overflow-y-auto">
            {tabs.map((t) => {
              const running = [t.scanRun, t.matrixRun, t.discoverRun].some(
                (r) => r?.status === 'running'
              )
              return (
                // Two sibling buttons in a div, not one nested in the other. The
                // close control used to be a span[role=button] inside the row
                // button: interactive content inside a <button>, which is invalid
                // and left it mouse-only and fragile to hit.
                <div key={t.id} className="w-full flex items-center hover:bg-surface-hover">
                  <button
                    onClick={() => {
                      store.setActiveTab(t.id)
                      setOpen(false)
                    }}
                    className="flex items-center gap-2 flex-1 min-w-0 px-3 py-1.5 text-left"
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                        t.id === tab.id ? 'bg-accent-secondary' : 'bg-transparent'
                      }`}
                    />
                    <span className="truncate flex-1 text-content-secondary">{t.name}</span>
                    {running && (
                      <Circle size={7} className="text-semantic-success fill-current shrink-0" />
                    )}
                  </button>
                  {/* Always rendered. Gating this on more than one document meant
                      the usual case — one loaded — had no way to remove it. */}
                  <button
                    onClick={() => {
                      setOpen(false)
                      onUnload(t.id)
                    }}
                    className="px-2 py-1.5 text-content-muted hover:text-semantic-error shrink-0"
                    title={`Unload ${t.name}`}
                    aria-label={`Unload ${t.name}`}
                  >
                    <X size={11} />
                  </button>
                </div>
              )
            })}
          </div>
          <div className="border-t border-border-subtle mt-1 pt-1">
            <button
              onClick={() => {
                setOpen(false)
                onLoadNew()
              }}
              className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-surface-hover text-left text-content-secondary"
            >
              <Plus size={12} /> Load a document…
            </button>
            {tab.spec && (
              <>
                <button
                  onClick={() => {
                    setOpen(false)
                    onOpenDoc('info')
                  }}
                  className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-surface-hover text-left text-content-secondary"
                >
                  <FileJson size={12} /> About this document
                </button>
                <button
                  onClick={() => {
                    setOpen(false)
                    onUnload(tab.id)
                  }}
                  className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-surface-hover text-left text-content-secondary hover:text-semantic-error"
                >
                  <X size={12} /> Unload this document
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </>
  )
}
