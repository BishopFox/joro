import { useState } from 'react'

type Props = {
  active: string
  activeAutoSave: boolean
  onClose: () => void
  onCreateCurrent: (name: string) => void
  onCreateEmpty: (name: string, opts?: { action?: 'save' | 'discard'; saveScratchAs?: string }) => void
}

// NewProjectModal asks whether a new project should snapshot the current session
// or start empty. For an empty project it also decides what happens to the
// outgoing session (auto-saved projects need no prompt; an auto-save-off project
// or an unnamed scratch session offers save/discard).
export default function NewProjectModal({ active, activeAutoSave, onClose, onCreateCurrent, onCreateEmpty }: Props) {
  const [name, setName] = useState('')
  const [mode, setMode] = useState<'current' | 'empty'>('current')
  const [outgoing, setOutgoing] = useState<'save' | 'discard'>('save')
  const [scratchName, setScratchName] = useState('')
  const [err, setErr] = useState('')

  // Whether starting empty risks losing unsaved work in the outgoing session.
  const scratchActive = active === ''
  const outgoingAtRisk = mode === 'empty' && (scratchActive || !activeAutoSave)

  function submit() {
    const n = name.trim()
    if (!n) { setErr('Enter a project name'); return }
    if (mode === 'current') {
      onCreateCurrent(n)
      return
    }
    const opts: { action?: 'save' | 'discard'; saveScratchAs?: string } = {}
    if (scratchActive) {
      if (outgoing === 'save') {
        if (!scratchName.trim()) { setErr('Name the current session to save it, or choose Discard'); return }
        opts.saveScratchAs = scratchName.trim()
      }
    } else if (!activeAutoSave) {
      opts.action = outgoing
    }
    onCreateEmpty(n, opts)
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-surface-card border border-border rounded p-4 w-96 space-y-3" onClick={(e) => e.stopPropagation()}>
        <h3 className="text-sm font-semibold text-content-primary">New project</h3>

        <input
          autoFocus
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') submit() }}
          placeholder="Project name"
          className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
        />

        <div className="space-y-1.5">
          <label className="flex items-start gap-2 text-xs cursor-pointer">
            <input type="radio" className="mt-0.5" checked={mode === 'current'} onChange={() => setMode('current')} />
            <span>
              <span className="text-content-primary font-medium">Save current session</span>
              <span className="block text-[10px] text-content-muted">Save the current session under the new name.</span>
            </span>
          </label>
          <label className="flex items-start gap-2 text-xs cursor-pointer">
            <input type="radio" className="mt-0.5" checked={mode === 'empty'} onChange={() => setMode('empty')} />
            <span>
              <span className="text-content-primary font-medium">Start empty</span>
              <span className="block text-[10px] text-content-muted">Begin a fresh project.</span>
            </span>
          </label>
        </div>

        {outgoingAtRisk && (
          <div className="border-t border-border-subtle pt-2 space-y-1.5">
            <p className="text-[10px] text-content-muted">
              {scratchActive
                ? 'Your current session isn\'t saved to a project.'
                : `Auto-save is off for "${active}".`}
            </p>
            <div className="flex gap-3 text-xs">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="radio" checked={outgoing === 'save'} onChange={() => setOutgoing('save')} />
                {scratchActive ? 'Save current session' : `Save "${active}"`}
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="radio" checked={outgoing === 'discard'} onChange={() => setOutgoing('discard')} />
                Discard changes
              </label>
            </div>
            {scratchActive && outgoing === 'save' && (
              <input
                type="text"
                value={scratchName}
                onChange={(e) => setScratchName(e.target.value)}
                placeholder="Save current session as…"
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              />
            )}
          </div>
        )}

        {err && <p className="text-semantic-error text-xs">{err}</p>}

        <div className="flex justify-end gap-2 pt-1">
          <button onClick={onClose} className="px-3 py-1.5 rounded-sm text-xs text-content-secondary hover:text-content-primary">Cancel</button>
          <button onClick={submit} className="px-3 py-1.5 rounded-sm text-xs bg-accent-tertiary hover:bg-accent-tertiary-hover text-black font-semibold">Create</button>
        </div>
      </div>
    </div>
  )
}
