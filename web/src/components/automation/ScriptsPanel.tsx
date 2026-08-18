import { useCallback, useEffect, useState } from 'react'
import { Download, Pause, Play, Plus, Trash2, Upload } from 'lucide-react'
import { api, type AutomationSummary } from '../../lib/api'
import { downloadPackage, pickPackage } from '../../lib/automationPackage'
import { useToastStore } from '../../stores/toastStore'
import ConfirmModal from '../ConfirmModal'
import ScriptEditor, { type EditorDraft } from './ScriptEditor'

/**
 * Installed automations: the list, and the editor it opens.
 *
 * Two levels of availability, and they mean different things to whoever is looking:
 * automation can be off entirely (--no-automation) or on with scripting off (no
 * --automation-scripting). Saying which is missing is the difference between a fixable
 * situation and a mystery.
 */
export default function ScriptsPanel() {
  const addToast = useToastStore((s) => s.addToast)
  const [scripts, setScripts] = useState<AutomationSummary[]>([])
  const [triggers, setTriggers] = useState<string[]>([])
  const [unavailable, setUnavailable] = useState<string | null>(null)
  const [editing, setEditing] = useState<{ id?: string; draft?: EditorDraft } | null>(null)
  const [confirm, setConfirm] = useState<{ id: string } | null>(null)

  const load = useCallback(async () => {
    try {
      const d = await api.listScripts()
      setScripts(d.scripts ?? [])
      setTriggers(d.triggers ?? [])
      setUnavailable(null)
    } catch (e) {
      setUnavailable(String(e instanceof Error ? e.message : e))
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const guard = async (fn: () => Promise<unknown>, ok?: string) => {
    try {
      await fn()
      if (ok) addToast(ok, 'info')
      await load()
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    }
  }

  const importFile = async () => {
    try {
      const bundle = await pickPackage()
      if (!bundle) return
      // Opened in the editor rather than installed straight away: importing someone
      // else's automation is exactly when reading it first matters.
      setEditing({ draft: { manifest: bundle.manifest, source: bundle.source } })
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    }
  }

  const exportOne = async (id: string) => {
    try {
      const pkg = await api.getScript(id)
      await downloadPackage(pkg.manifest, pkg.source ?? '')
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    }
  }

  if (editing) {
    return (
      <ScriptEditor
        id={editing.id}
        draft={editing.draft}
        triggers={triggers}
        onClose={() => {
          setEditing(null)
          load()
        }}
        onSaved={load}
      />
    )
  }

  if (unavailable) {
    return (
      <div className="flex-1 overflow-auto p-5">
        <h3 className="text-sm font-semibold text-content-primary mb-2">Automations</h3>
        <p className="text-[11px] text-content-secondary leading-relaxed max-w-xl">
          {unavailable.includes('--automation-scripting') ? (
            <>
              Script automation is off. Start Joro with{' '}
              <code className="font-mono text-content-primary">--automation-scripting</code> to install
              JavaScript automations and expose <code className="font-mono">script_run</code>,{' '}
              <code className="font-mono">script_list</code> and{' '}
              <code className="font-mono">script_invoke</code> to a granted token. Automations run in a
              sandboxed worker process against Joro&rsquo;s automation SDK.
            </>
          ) : (
            <>Automation is disabled on this instance ({unavailable}).</>
          )}
        </p>
      </div>
    )
  }

  return (
    <>
      <div className="flex-1 overflow-auto p-5 space-y-3">
        <div className="flex items-center gap-2">
          <div>
            <h3 className="text-sm font-semibold text-content-primary">Automations</h3>
            <p className="text-[11px] text-content-muted">
              Reviewed JavaScript that runs against the standard automation SDK — by hand, on an
              event, or when an agent asks for it by id.
            </p>
          </div>
          <div className="ml-auto flex items-center gap-1.5">
            <button
              onClick={importFile}
              className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
            >
              <Upload size={11} strokeWidth={2} aria-hidden="true" />
              Import
            </button>
            <button
              onClick={() => setEditing({})}
              className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold"
            >
              <Plus size={11} strokeWidth={2.4} aria-hidden="true" />
              New
            </button>
          </div>
        </div>

        {scripts.length === 0 ? (
          <p className="text-[11px] text-content-muted italic py-6 text-center">
            No automations installed. New writes one from a starter; Import reads a .jauto package.
          </p>
        ) : (
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-content-muted uppercase tracking-wide text-[10px] text-left">
                <th className="pb-1 font-semibold">Automation</th>
                <th className="pb-1 font-semibold">Armed for</th>
                <th className="pb-1 font-semibold">Last run</th>
                <th className="pb-1 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scripts.map((s) => (
                <tr key={s.id} className="border-t border-border-subtle align-top">
                  <td className="py-1.5 pr-2">
                    <button
                      onClick={() => setEditing({ id: s.id })}
                      className="text-content-primary hover:text-accent-secondary font-semibold text-left"
                    >
                      {s.name}
                    </button>
                    <div className="text-content-muted font-mono text-[10px]">
                      {s.id} v{s.version} · sha256:{s.sourceHash.slice(0, 12)}
                      {s.revisions > 1 ? ` · ${s.revisions} revisions` : ''}
                    </div>
                    {s.paused && (
                      <div className="text-semantic-warning text-[10px] mt-0.5 max-w-md leading-snug">
                        {s.pausedReason}
                      </div>
                    )}
                  </td>
                  <td className="py-1.5 pr-2 font-mono text-[10px] text-content-secondary">
                    {s.armed.length > 0 ? (
                      s.armed.join(', ')
                    ) : (
                      <span className="text-content-muted">
                        {s.enabled ? 'manual only' : 'disabled'}
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 pr-2 text-content-secondary">
                    {s.lastRun ? (
                      <>
                        <span className={s.lastRun.reason === 'success' ? '' : 'text-semantic-warning'}>
                          {s.lastRun.reason}
                        </span>
                        <div className="text-content-muted text-[10px]">
                          {new Date(s.lastRun.at).toLocaleString()}
                        </div>
                      </>
                    ) : (
                      <span className="text-content-muted">never</span>
                    )}
                  </td>
                  <td className="py-1.5 text-right whitespace-nowrap">
                    <button
                      onClick={() => guard(() => api.runScript({ scriptId: s.id }), `Ran ${s.id}`)}
                      className="text-content-muted hover:text-accent-tertiary px-1"
                      title="Run once now (allowed even when disabled)"
                    >
                      <Play size={13} strokeWidth={2} />
                    </button>
                    <button
                      onClick={() =>
                        guard(
                          () => api.setScriptEnabled(s.id, !s.enabled),
                          s.enabled ? `Disabled ${s.id}` : `Enabled ${s.id}`
                        )
                      }
                      className={`px-1 ${s.enabled ? 'text-semantic-success' : 'text-content-muted'} hover:text-accent`}
                      title={s.enabled ? 'Disable' : s.paused ? 'Enable (clears the pause)' : 'Enable'}
                    >
                      {s.enabled ? <Pause size={13} strokeWidth={2} /> : <Play size={13} strokeWidth={2} />}
                    </button>
                    <button
                      onClick={() => exportOne(s.id)}
                      className="text-content-muted hover:text-content-primary px-1"
                      title="Export as .jauto"
                    >
                      <Download size={13} strokeWidth={2} />
                    </button>
                    <button
                      onClick={() => setConfirm({ id: s.id })}
                      className="text-content-muted hover:text-semantic-error px-1"
                      title="Uninstall"
                    >
                      <Trash2 size={13} strokeWidth={2} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <p className="text-[10px] text-content-muted leading-relaxed max-w-2xl pt-1">
          An automation is installed disabled. Enabling it arms its event triggers and lets a token
          holding <code className="font-mono">script_invoke</code> run it; you can run a disabled one
          from here at any time. Code lives in{' '}
          <code className="font-mono">~/.joro/automations/</code> and never travels inside a project
          config — what an automation stores with{' '}
          <code className="font-mono">joro.storage</code> does, because that describes one engagement.
        </p>
      </div>

      {confirm && (
        <ConfirmModal
          title="Uninstall automation"
          message={`Remove ${confirm.id}? Its code and everything it has stored are deleted.`}
          confirmLabel="Uninstall"
          onConfirm={() => {
            const id = confirm.id
            setConfirm(null)
            guard(() => api.deleteScript(id), `Uninstalled ${id}`)
          }}
          onClose={() => setConfirm(null)}
        />
      )}
    </>
  )
}
