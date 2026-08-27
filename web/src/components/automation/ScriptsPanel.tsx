import { useEffect, useState } from 'react'
import { Bot, Download, Play, Plus, Power, PowerOff, Terminal, Trash2, Upload } from 'lucide-react'
import { api } from '../../lib/api'
import { downloadPackage, pickPackage } from '../../lib/automationPackage'
import { useAutomationStore } from '../../stores/automationStore'
import { useTriggerStore } from '../../stores/triggerStore'
import { useToastStore } from '../../stores/toastStore'
import ConfirmModal from '../ConfirmModal'
import ScriptEditor, { OPERATOR_STARTED, type EditorDraft } from './ScriptEditor'

/** The declared triggers the Dispatcher would watch — what enabling an automation arms. */
function declaredEvents(triggers: string[] | undefined): string[] {
  return (triggers ?? []).filter((t) => !OPERATOR_STARTED.includes(t))
}

/**
 * Installed automations: the list, and the editor it opens.
 *
 * Two levels of availability, and they mean different things to whoever is looking:
 * automation can be off entirely (--no-automation) or on with scripting off (no
 * --automation-scripting). Saying which is missing is the difference between a fixable
 * situation and a mystery.
 */
export default function ScriptsPanel({
  /** An automation another tab asked to open, e.g. Lenses. */
  openEditor,
  onEditorOpened,
}: {
  openEditor?: string
  onEditorOpened?: () => void
} = {}) {
  const addToast = useToastStore((s) => s.addToast)
  const { scripts, scriptsUnavailable: unavailable, refreshScripts: load } = useAutomationStore()
  // The trigger catalog, so an export can embed the definitions a manifest references and
  // an import can tell which of them this Joro is missing.
  const catalog = useTriggerStore((st) => st.triggers)
  const refreshTriggers = useTriggerStore((st) => st.refresh)
  const [editing, setEditing] = useState<{ id?: string; draft?: EditorDraft } | null>(null)
  const [confirm, setConfirm] = useState<{ id: string } | null>(null)

  useEffect(() => {
    load()
    refreshTriggers()
  }, [load, refreshTriggers])

  useEffect(() => {
    if (!openEditor) return
    setEditing({ id: openEditor })
    onEditorOpened?.()
  }, [openEditor, onEditorOpened])

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

      // Trigger definitions the package brought that this Joro does not have. Installed
      // before the editor opens, because the automation is about to reference them by id
      // and a reference to nothing is an automation that silently never fires.
      const missing = (bundle.triggers ?? []).filter((t) => !catalog.some((c) => c.id === t.id))
      for (const t of missing) {
        try {
          await api.createTrigger(t)
        } catch (e) {
          addToast(`Trigger ${t.id}: ${e instanceof Error ? e.message : e}`, 'error')
        }
      }
      if (missing.length > 0) {
        await refreshTriggers()
        addToast(
          `Installed ${missing.length} trigger${missing.length === 1 ? '' : 's'} this package needs: ` +
            missing.map((t) => t.name).join(', '),
          'info'
        )
      }

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
      await downloadPackage(pkg.manifest, pkg.source ?? '', catalog)
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    }
  }

  if (editing) {
    return (
      <ScriptEditor
        id={editing.id}
        draft={editing.draft}
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
                    {s.kind === 'command' && (
                      /* Worth a badge rather than left to the argv line below: what
                         enabling this arms is a program on the operator's own machine,
                         which is a different decision from arming a sandboxed script. */
                      <span
                        className="inline-flex items-center gap-1 ml-1.5 px-1 py-px rounded-sm bg-surface-input text-semantic-warning text-[10px] align-middle"
                        title="Runs a local command on this machine, not sandboxed JavaScript."
                      >
                        <Terminal size={9} strokeWidth={2} aria-hidden="true" />
                        command
                      </span>
                    )}
                    {s.author && (
                      <span
                        className="inline-flex items-center gap-1 ml-1.5 px-1 py-px rounded-sm bg-surface-input text-content-secondary text-[10px] align-middle"
                        title={`Stored by ${s.author}. Read the code before enabling it.`}
                      >
                        <Bot size={9} strokeWidth={2} aria-hidden="true" />
                        {s.author}
                      </span>
                    )}
                    <div className="text-content-muted font-mono text-[10px]">
                      {s.id} v{s.version} · sha256:{s.sourceHash.slice(0, 12)}
                      {s.revisions > 1 ? ` · ${s.revisions} revisions` : ''}
                    </div>
                    {s.command && (
                      <div className="text-content-secondary font-mono text-[10px] mt-0.5 break-all">
                        $ {s.command}
                      </div>
                    )}
                    {s.paused && (
                      <div className="text-semantic-warning text-[10px] mt-0.5 max-w-md leading-snug">
                        {s.pausedReason}
                      </div>
                    )}
                  </td>
                  <td className="py-1.5 pr-2 font-mono text-[10px] text-content-secondary">
                    {s.armed?.length ? (
                      s.armed.join(', ')
                    ) : (
                      <span className="text-content-muted">
                        {s.enabled ? 'manual only' : 'disabled'}
                        {/* What Enable would arm. An absent triggersDisabled key means
                            armed, so enabling arms every event the manifest declares at
                            once — and until then this column is the only place the
                            operator can see which ones those are. */}
                        {!s.enabled && declaredEvents(s.triggers).length > 0 && (
                          <> · declares {declaredEvents(s.triggers).join(', ')}</>
                        )}
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 pr-2 text-content-secondary">
                    {s.lastRun ? (
                      <>
                        {/* Styled off the stable code, labelled with the prose. */}
                        <span className={s.lastRun.outcome === 'success' ? '' : 'text-semantic-warning'}>
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
                      {/* Not Play: it sits beside Run, which is a Play triangle. */}
                      {s.enabled ? <Power size={13} strokeWidth={2} /> : <PowerOff size={13} strokeWidth={2} />}
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
        <p className="text-[10px] text-content-muted leading-relaxed max-w-2xl">
          An automation a token stored with <code className="font-mono">script_install</code> arrives
          disabled and labelled with that token. A token holding{' '}
          <code className="font-mono">script_replace</code> can rewrite any automation you do not
          currently have enabled, including one you wrote — enabling an automation is what puts its
          code beyond their reach.
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
