import { useEffect, useRef, useState } from 'react'
import { useProjectStore } from '../stores/projectStore'
import { useToastStore } from '../stores/toastStore'
import { api, type ProjectMeta } from '../lib/api'
import NewProjectModal from './NewProjectModal'
import ProjectSettings from './ProjectSettings'

function formatBytes(n: number): string {
  if (n <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)))
  return `${(n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function formatWhen(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return '—'
  return d.toLocaleString()
}

// ProjectBrowser is the project list + management UI, embedded in the Settings
// page under the "Project" category. Per-project settings render inline below
// the table (Team Server / Team Configs / Filtering, via ProjectSettings).
export default function ProjectBrowser() {
  const projects = useProjectStore((s) => s.projects)
  const active = useProjectStore((s) => s.active)
  const loading = useProjectStore((s) => s.loading)
  const refresh = useProjectStore((s) => s.refresh)
  const switchTo = useProjectStore((s) => s.switchTo)
  const createFromCurrent = useProjectStore((s) => s.createFromCurrent)
  const createEmpty = useProjectStore((s) => s.createEmpty)
  const setPrefs = useProjectStore((s) => s.setPrefs)
  const saveActive = useProjectStore((s) => s.saveActive)
  const addToast = useToastStore((s) => s.addToast)

  const [creating, setCreating] = useState(false)
  const [pending, setPending] = useState<{ name: string; scratch: boolean } | null>(null)
  const [scratchName, setScratchName] = useState('')
  const [err, setErr] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  useEffect(() => { refresh() }, [refresh])

  const activeMeta = projects.find((p) => p.name === active)

  async function doSwitch(name: string, opts?: { action?: 'save' | 'discard'; saveScratchAs?: string }) {
    try {
      await switchTo(name, opts)
      addToast(`Switched to ${name}`, 'info')
    } catch (e) {
      addToast(`Failed to switch: ${String(e)}`, 'error')
    }
    setPending(null)
    setScratchName('')
    setErr('')
  }

  function selectProject(name: string) {
    if (name === active) return
    if (active === '') { setPending({ name, scratch: true }); return }
    if (activeMeta && activeMeta.autoSave) { doSwitch(name, { action: 'save' }); return }
    setPending({ name, scratch: false })
  }

  async function handleSave() {
    try {
      await saveActive()
      addToast(`Saved ${active}`, 'info')
    } catch (e) {
      addToast(`Failed to save: ${String(e)}`, 'error')
    }
  }

  async function handleCreateCurrent(name: string) {
    try {
      await createFromCurrent(name)
      addToast(`Created project ${name}`, 'info')
    } catch (e) {
      addToast(`Failed to create: ${String(e)}`, 'error')
    }
    setCreating(false)
  }

  async function handleCreateEmpty(name: string, opts?: { action?: 'save' | 'discard'; saveScratchAs?: string }) {
    try {
      await createEmpty(name, opts)
      addToast(`Created empty project ${name}`, 'info')
    } catch (e) {
      addToast(`Failed to create: ${String(e)}`, 'error')
    }
    setCreating(false)
  }

  async function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) { void importFile(file) }
    if (fileRef.current) fileRef.current.value = ''
  }

  async function importFile(file: File) {
    try {
      const buf = new Uint8Array(await file.arrayBuffer())
      let binary = ''
      for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i])
      const b64 = btoa(binary)
      const name = file.name.replace(/\.(joro|json)$/i, '').replace(/[^a-zA-Z0-9_-]/g, '-')
      await api.importProjectConfig(name, b64)
      addToast(`Imported ${name}`, 'info')
      await refresh()
      window.dispatchEvent(new CustomEvent('joro:project-changed'))
    } catch (er) {
      addToast(`Import failed: ${String(er)}`, 'error')
    }
  }

  async function togglePref(p: ProjectMeta, key: 'autoSave' | 'saveHistory', value: boolean) {
    try {
      await setPrefs(p.name, { [key]: value })
    } catch (er) {
      addToast(`Failed to update: ${String(er)}`, 'error')
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide">Projects</h2>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSave}
            disabled={active === ''}
            title={active === '' ? 'No active project to save' : `Save ${active}`}
            className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-40"
          >
            Save
          </button>
          <button
            onClick={() => setCreating(true)}
            className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold"
          >
            New project…
          </button>
          <button
            onClick={() => fileRef.current?.click()}
            className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
          >
            Import…
          </button>
          <input ref={fileRef} type="file" accept=".joro,.json" onChange={handleImport} className="hidden" />
        </div>
      </div>

      <p className="text-xs text-content-muted">
        Auto-save periodically writes the active project in the background; turn off Save history to
        keep a project small (its sitemap won't persist).
      </p>

      {projects.length === 0 ? (
        <div className="text-content-muted text-sm italic py-8 text-center">
          {loading ? 'Loading…' : 'No saved projects yet. Create one above or from the header dropdown.'}
        </div>
      ) : (
        <div className="bg-surface-card border border-border rounded overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-content-muted text-[10px] uppercase tracking-wide border-b border-border">
                <th className="text-left font-medium px-3 py-2">Project</th>
                <th className="text-right font-medium px-3 py-2">Requests</th>
                <th className="text-right font-medium px-3 py-2">Notes</th>
                <th className="text-right font-medium px-3 py-2">Size</th>
                <th className="text-left font-medium px-3 py-2">Last saved</th>
                <th className="text-center font-medium px-3 py-2">Auto-save</th>
                <th className="text-center font-medium px-3 py-2">Save history</th>
                <th className="text-right font-medium px-3 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((p) => (
                <tr key={p.name} className="border-b border-border-subtle last:border-0 hover:bg-surface-hover">
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${p.active ? 'bg-accent' : 'bg-transparent'}`} />
                      <span className={`font-medium truncate ${p.active ? 'text-accent' : 'text-content-primary'}`}>{p.name}</span>
                      {p.active && <span className="text-[9px] uppercase tracking-wide text-accent">active</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-right text-content-secondary">{p.requestCount}</td>
                  <td className="px-3 py-2 text-right text-content-secondary">{p.noteCount}</td>
                  <td className="px-3 py-2 text-right text-content-secondary">{formatBytes(p.sizeBytes)}</td>
                  <td className="px-3 py-2 text-content-secondary whitespace-nowrap">{formatWhen(p.savedAt)}</td>
                  <td className="px-3 py-2 text-center">
                    <input type="checkbox" checked={p.autoSave} onChange={(e) => togglePref(p, 'autoSave', e.target.checked)} />
                  </td>
                  <td className="px-3 py-2 text-center">
                    <input type="checkbox" checked={p.saveHistory} onChange={(e) => togglePref(p, 'saveHistory', e.target.checked)} />
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex justify-end gap-3">
                      <button
                        onClick={() => selectProject(p.name)}
                        disabled={p.active}
                        className="text-accent-secondary hover:underline font-medium disabled:opacity-40 disabled:no-underline"
                      >
                        {p.active ? 'Loaded' : 'Switch'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Per-project settings, formerly a modal opened from this page. */}
      <div className="border-t border-border pt-4">
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-muted mb-3">Project Settings</h3>
        <ProjectSettings />
      </div>

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
            <h3 className="text-sm font-semibold text-content-primary">Switch to {pending.name}</h3>
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
