import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useProjectStore } from '../stores/projectStore'
import { useToastStore } from '../stores/toastStore'
import NewProjectModal from './NewProjectModal'

// ProjectSwitcher is the header dropdown (left of the Dead Drop spider) for quick
// project switching. Switching respects the outgoing project's autoSave pref:
// auto-save on → save silently; off (or an unnamed scratch session) → prompt.
export default function ProjectSwitcher() {
  const navigate = useNavigate()
  const projects = useProjectStore((s) => s.projects)
  const active = useProjectStore((s) => s.active)
  const refresh = useProjectStore((s) => s.refresh)
  const switchTo = useProjectStore((s) => s.switchTo)
  const createFromCurrent = useProjectStore((s) => s.createFromCurrent)
  const createEmpty = useProjectStore((s) => s.createEmpty)
  const saveActive = useProjectStore((s) => s.saveActive)
  const addToast = useToastStore((s) => s.addToast)

  const [open, setOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  // pending holds a switch awaiting a save/discard decision (autoSave off or scratch).
  const [pending, setPending] = useState<{ name: string; scratch: boolean } | null>(null)
  const [scratchName, setScratchName] = useState('')
  const [err, setErr] = useState('')
  const rootRef = useRef<HTMLDivElement>(null)
  const btnRef = useRef<HTMLButtonElement>(null)
  // Viewport-relative position for the dropdown panel: a fixed panel escapes the
  // header's `overflow-x-auto`, which would clip an absolutely-positioned one.
  const [pos, setPos] = useState<{ top: number; right: number }>({ top: 0, right: 0 })

  useEffect(() => { refresh() }, [refresh])

  useLayoutEffect(() => {
    if (!open) return
    const place = () => {
      const r = btnRef.current?.getBoundingClientRect()
      if (r) setPos({ top: r.bottom + 4, right: Math.max(8, window.innerWidth - r.right) })
    }
    place()
    window.addEventListener('resize', place)
    return () => window.removeEventListener('resize', place)
  }, [open])

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const activeMeta = projects.find((p) => p.name === active)

  async function doSwitch(name: string, opts?: { action?: 'save' | 'discard'; saveScratchAs?: string }) {
    try {
      await switchTo(name, opts)
      addToast(opts?.action === 'save' || opts?.saveScratchAs ? `Saved, switched to ${name}` : `Switched to ${name}`, 'info')
    } catch (e) {
      addToast(`Failed to switch: ${String(e)}`, 'error')
    }
    setPending(null)
    setScratchName('')
    setErr('')
    setOpen(false)
  }

  function selectProject(name: string) {
    if (name === active) { setOpen(false); return }
    if (active === '') {
      // Unnamed scratch session — force a save/discard decision.
      setPending({ name, scratch: true })
      return
    }
    if (activeMeta && activeMeta.autoSave) {
      doSwitch(name, { action: 'save' })
      return
    }
    // Active project has auto-save off — confirm.
    setPending({ name, scratch: false })
  }

  async function handleSave() {
    try {
      await saveActive()
      addToast(`Saved ${active}`, 'info')
    } catch (e) {
      addToast(`Failed to save: ${String(e)}`, 'error')
    }
    setOpen(false)
  }

  async function handleCreateCurrent(name: string) {
    try {
      await createFromCurrent(name)
      addToast(`Created project ${name}`, 'info')
    } catch (e) {
      addToast(`Failed to create: ${String(e)}`, 'error')
    }
    setCreating(false)
    setOpen(false)
  }

  async function handleCreateEmpty(name: string, opts?: { action?: 'save' | 'discard'; saveScratchAs?: string }) {
    try {
      await createEmpty(name, opts)
      addToast(`Created empty project ${name}`, 'info')
    } catch (e) {
      addToast(`Failed to create: ${String(e)}`, 'error')
    }
    setCreating(false)
    setOpen(false)
  }

  const label = active || 'Scratch session'

  return (
    <div className="relative" ref={rootRef}>
      <button
        ref={btnRef}
        onClick={() => setOpen((v) => !v)}
        title="Switch project"
        className="flex items-center gap-1.5 max-w-[180px] px-2 py-1 rounded-sm text-xs bg-surface-input border border-border text-content-secondary hover:text-content-primary hover:border-accent-secondary transition-colors"
      >
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="shrink-0">
          <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
        </svg>
        <span className={`truncate ${active ? 'text-content-primary' : 'italic text-content-muted'}`}>{label}</span>
        <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="shrink-0">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div
          style={{ position: 'fixed', top: pos.top, right: pos.right }}
          className="w-64 z-50 bg-surface-card border border-border rounded shadow-lg py-1 text-xs"
        >
          <div className="px-2 py-1 text-[10px] uppercase tracking-wide text-content-muted">Projects</div>
          <div className="max-h-64 overflow-y-auto">
            {projects.length === 0 ? (
              <div className="px-3 py-2 text-content-muted italic">No saved projects</div>
            ) : (
              projects.map((p) => (
                <button
                  key={p.name}
                  onClick={() => selectProject(p.name)}
                  className="w-full flex items-center gap-2 px-3 py-1.5 hover:bg-surface-hover text-left"
                >
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${p.active ? 'bg-accent' : 'bg-transparent'}`} />
                  <span className={`flex-1 truncate ${p.active ? 'text-accent' : 'text-content-primary'}`}>{p.name}</span>
                  {!p.autoSave && <span className="text-[9px] text-content-muted" title="Auto-save off">manual</span>}
                </button>
              ))
            )}
          </div>

          <div className="border-t border-border-subtle mt-1 pt-1">
            {active !== '' && (
              <button onClick={handleSave} className="w-full text-left px-3 py-1.5 hover:bg-surface-hover text-accent-tertiary">
                💾 Save project
              </button>
            )}
            <button onClick={() => setCreating(true)} className="w-full text-left px-3 py-1.5 hover:bg-surface-hover text-accent-secondary">
              ＋ New project…
            </button>
            <button onClick={() => { setOpen(false); navigate('/settings', { state: { category: 'project' } }) }} className="w-full text-left px-3 py-1.5 hover:bg-surface-hover text-content-secondary">
              Manage…
            </button>
          </div>
        </div>
      )}

      {creating && (
        <NewProjectModal
          active={active}
          activeAutoSave={activeMeta?.autoSave ?? true}
          onClose={() => setCreating(false)}
          onCreateCurrent={handleCreateCurrent}
          onCreateEmpty={handleCreateEmpty}
        />
      )}

      {pending && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50" onClick={() => setPending(null)}>
          <div className="bg-surface-card border border-border rounded p-4 w-80 space-y-3" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-content-primary">
              Switch to {pending.name}
            </h3>
            {pending.scratch ? (
              <>
                <p className="text-xs text-content-secondary">
                  Your current session isn't saved to a project. Name it to keep it, or discard it.
                </p>
                <input
                  autoFocus
                  type="text"
                  value={scratchName}
                  onChange={(e) => setScratchName(e.target.value)}
                  placeholder="Save current session as…"
                  className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                />
                {err && <p className="text-semantic-error text-xs">{err}</p>}
                <div className="flex justify-end gap-2 pt-1">
                  <button onClick={() => setPending(null)} className="px-3 py-1.5 rounded-sm text-xs text-content-secondary hover:text-content-primary">Cancel</button>
                  <button onClick={() => doSwitch(pending.name)} className="px-3 py-1.5 rounded-sm text-xs bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold">Discard &amp; switch</button>
                  <button
                    onClick={() => {
                      if (!scratchName.trim()) { setErr('Enter a name or choose Discard'); return }
                      doSwitch(pending.name, { saveScratchAs: scratchName.trim() })
                    }}
                    className="px-3 py-1.5 rounded-sm text-xs bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold"
                  >
                    Save &amp; switch
                  </button>
                </div>
              </>
            ) : (
              <>
                <p className="text-xs text-content-secondary">
                  Auto-save is off for <span className="text-content-primary">{active}</span>. Save
                  your changes before switching?
                </p>
                <div className="flex justify-end gap-2 pt-1">
                  <button onClick={() => setPending(null)} className="px-3 py-1.5 rounded-sm text-xs text-content-secondary hover:text-content-primary">Cancel</button>
                  <button onClick={() => doSwitch(pending.name, { action: 'discard' })} className="px-3 py-1.5 rounded-sm text-xs bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold">Discard &amp; switch</button>
                  <button onClick={() => doSwitch(pending.name, { action: 'save' })} className="px-3 py-1.5 rounded-sm text-xs bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold">Save &amp; switch</button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
