import { useCallback, useEffect, useMemo, useState } from 'react'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { javascript } from '@codemirror/lang-javascript'
import { oneDark } from '@codemirror/theme-one-dark'
import { Bot, Download, Play, Save, X } from 'lucide-react'
import {
  api,
  LENS_PARTS,
  type AutomationLimits,
  type AutomationManifest,
  type LensPart,
  type ScriptRun,
} from '../../lib/api'
import { downloadPackage } from '../../lib/automationPackage'
import { useAutomationStore } from '../../stores/automationStore'
import { useToastStore } from '../../stores/toastStore'
import RunOutput from './RunOutput'
import SdkReference from './SdkReference'

const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border w-full'

// The two triggers the operator starts, so the Dispatcher never watches them and a lens may
// still declare them. Mirrors dispatched() in internal/jsautomation/manifest.go, which drops
// the rest from a manifest that declares a lens.
//
// Exported because ScriptsPanel needs the same split to say what enabling an automation
// would arm, and a second copy of this list would be one to keep in step.
export const OPERATOR_STARTED = ['manual', 'request.selected']

const STARTER = `async function run(ctx) {
  // ctx.trigger tells you why this ran; ctx.input carries anything passed in.
  // joro.* is the whole SDK — see the reference on the right.
  const recent = await joro.history.list({ limit: 10 });
  console.log(recent);
  return { looked: true };
}
`

export interface EditorDraft {
  manifest: AutomationManifest
  source: string
}

function blankManifest(): AutomationManifest {
  return { id: '', name: '', version: '1.0.0', sdkVersion: '1', triggers: ['manual'] }
}

/**
 * The authoring surface for one automation.
 *
 * Inline in the sub-tab rather than in a modal: a code editor wants the full pane height,
 * and index.css sets `.cm-editor { height: 100% !important }` globally, so an editor only
 * works inside a parent whose height actually resolves.
 */
export default function ScriptEditor({
  id,
  draft,
  triggers,
  onClose,
  onSaved,
}: {
  /** Editing an installed automation, or undefined for a new one. */
  id?: string
  /** Seed for a new automation, or one imported from a file. */
  draft?: EditorDraft
  triggers: string[]
  onClose: () => void
  onSaved: () => void
}) {
  const addToast = useToastStore((s) => s.addToast)
  // The global run budget, so the boxes below show what a run actually gets today rather
  // than an empty field. Settings -> Automation -> Settings is where it is set.
  const globalBudget = useAutomationStore((st) => st.budget)
  const refreshBudget = useAutomationStore((st) => st.refreshBudget)

  const [manifest, setManifest] = useState<AutomationManifest>(draft?.manifest ?? blankManifest())
  const [source, setSource] = useState(draft?.source ?? STARTER)
  // The operator's half of the budget, and what the two halves resolve to under the
  // global. Kept apart from the manifest because they are saved through a different
  // endpoint: updating the code must never revert a limit the operator lowered.
  const [override, setOverride] = useState<AutomationLimits>({})
  const [effective, setEffective] = useState<AutomationLimits | null>(null)
  // The hash the source was loaded at. Sent back on update so replacing the code of an
  // armed automation cannot silently clobber a concurrent edit.
  const [baseHash, setBaseHash] = useState('')
  const [busy, setBusy] = useState(false)
  const [run, setRun] = useState<ScriptRun | null>(null)
  const [input, setInput] = useState('{}')
  // Which token last wrote this code, shown beside the hash. Saving here clears it on the
  // server, so it is cleared locally on save too rather than lingering until a reload.
  const [author, setAuthor] = useState('')

  useEffect(() => {
    if (!id) return
    let cancelled = false
    api
      .getScript(id)
      .then((pkg) => {
        if (cancelled) return
        setManifest(pkg.manifest)
        setSource(pkg.source ?? '')
        setBaseHash(pkg.sourceHash)
        setAuthor(pkg.state.author ?? '')
        setOverride(pkg.state.limits ?? {})
        setEffective(pkg.effectiveLimits ?? null)
      })
      .catch((e) => addToast(String(e instanceof Error ? e.message : e), 'error'))
    return () => {
      cancelled = true
    }
  }, [id, addToast])

  useEffect(() => {
    refreshBudget()
  }, [refreshBudget])

  const extensions = useMemo(() => [javascript(), EditorView.lineWrapping], [])

  const patch = (p: Partial<AutomationManifest>) => setManifest((m) => ({ ...m, ...p }))
  const patchLimits = (p: Partial<AutomationLimits>) =>
    setManifest((m) => ({ ...m, limits: { ...m.limits, ...p } }))

  /** What a run gets right now for one field, for use as a placeholder. */
  const globalOf = (k: keyof AutomationLimits) => globalBudget?.effective[k]

  const guard = useCallback(
    async (fn: () => Promise<unknown>, ok?: string) => {
      setBusy(true)
      try {
        await fn()
        if (ok) addToast(ok, 'info')
        return true
      } catch (e) {
        addToast(String(e instanceof Error ? e.message : e), 'error')
        return false
      } finally {
        setBusy(false)
      }
    },
    [addToast]
  )

  const save = async () => {
    const ok = await guard(async () => {
      if (id) {
        const pkg = await api.updateScript(id, manifest, source, baseHash)
        setBaseHash(pkg.sourceHash)
      } else {
        const pkg = await api.installScript(manifest, source)
        setBaseHash(pkg.sourceHash)
      }
      // Saving from here is the operator writing the code, whoever wrote it before.
      setAuthor('')
    }, id ? 'Saved' : 'Installed (disabled until you enable it)')
    if (ok) onSaved()
  }

  const runNow = async () => {
    let parsed: unknown = {}
    if (input.trim()) {
      try {
        parsed = JSON.parse(input)
      } catch {
        addToast('Test input is not valid JSON', 'error')
        return
      }
    }
    await guard(async () => {
      // Runs the buffer, not what is on disk: reviewing means running a draft before
      // committing to it.
      setRun(await api.runScript({ source, input: parsed }))
    })
  }

  // Saved through the prefs endpoint, not with the manifest: author intent and operator
  // intent live in different files precisely so one cannot overwrite the other.
  const saveOverride = async () => {
    if (!id) return
    await guard(async () => {
      await api.setScriptPrefs(id, { limits: override })
      // Re-read only the resolved budget. Reloading the package wholesale would throw
      // away whatever is in the editor.
      const pkg = await api.getScript(id)
      setEffective(pkg.effectiveLimits ?? null)
    }, 'Operator limits saved')
  }

  const toggleTrigger = (t: string) => {
    const cur = manifest.triggers ?? []
    patch({ triggers: cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t] })
  }

  const canSave = manifest.id.trim() !== '' && source.trim() !== ''

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border">
        <div className="min-w-0">
          <h3 className="text-xs font-semibold text-content-primary truncate">
            {id ? manifest.name || id : 'New automation'}
          </h3>
          {baseHash && (
            <p className="text-[10px] text-content-muted font-mono">
              sha256:{baseHash.slice(0, 16)}
              {author && (
                <span
                  className="inline-flex items-center gap-1 ml-1.5 px-1 py-px rounded-sm bg-surface-input text-content-secondary font-sans"
                  title={`Stored by ${author}. Saving here makes the code yours.`}
                >
                  <Bot size={9} strokeWidth={2} aria-hidden="true" />
                  {author}
                </span>
              )}
            </p>
          )}
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          <button
            onClick={runNow}
            disabled={busy || !source.trim()}
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black font-semibold disabled:opacity-40"
          >
            <Play size={11} strokeWidth={2.2} aria-hidden="true" />
            Run
          </button>
          <button
            onClick={save}
            disabled={busy || !canSave}
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-40"
          >
            <Save size={11} strokeWidth={2.2} aria-hidden="true" />
            {id ? 'Save' : 'Install'}
          </button>
          <button
            onClick={() => downloadPackage(manifest, source)}
            disabled={!canSave}
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-40"
            title="Export as a .jauto package"
          >
            <Download size={11} strokeWidth={2} aria-hidden="true" />
            Export
          </button>
          <button
            onClick={onClose}
            className="text-content-muted hover:text-content-primary"
            aria-label="Close editor"
          >
            <X size={15} strokeWidth={2} />
          </button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0">
        {/* Editor. The height chain is load-bearing: flex-1 relative min-h-0, then an
            absolutely positioned child, because .cm-editor is height:100% !important. */}
        <div className="flex-1 relative min-h-0">
          <div className="absolute inset-0 overflow-hidden">
            <CodeMirror
              value={source}
              theme={oneDark}
              height="100%"
              onChange={setSource}
              extensions={extensions}
              basicSetup={{ lineNumbers: true, foldGutter: true }}
            />
          </div>
        </div>

        <div className="w-72 shrink-0 border-l border-border overflow-y-auto p-3 space-y-3">
          <Field label="Id">
            <input
              className={inputCls}
              value={manifest.id}
              disabled={!!id}
              placeholder="idor-check"
              onChange={(e) => patch({ id: e.target.value })}
            />
            {!id && (
              <p className="text-[10px] text-content-muted mt-0.5">
                Lowercase letters, digits, hyphen, underscore. Permanent.
              </p>
            )}
          </Field>
          <Field label="Name">
            <input className={inputCls} value={manifest.name} onChange={(e) => patch({ name: e.target.value })} />
          </Field>
          <Field label="Version">
            <input
              className={inputCls}
              value={manifest.version}
              onChange={(e) => patch({ version: e.target.value })}
            />
          </Field>
          <Field label="Description">
            <textarea
              className={`${inputCls} h-14 resize-none`}
              value={manifest.description ?? ''}
              onChange={(e) => patch({ description: e.target.value })}
            />
          </Field>

          <Field label="Triggers">
            <div className="space-y-0.5">
              {triggers.map((t) => {
                const off = !!manifest.lens && !OPERATOR_STARTED.includes(t)
                return (
                  <label
                    key={t}
                    className={`flex items-center gap-1.5 text-[11px] text-content-secondary ${
                      off ? 'opacity-40 cursor-not-allowed' : ''
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={(manifest.triggers ?? []).includes(t)}
                      disabled={off}
                      onChange={() => toggleTrigger(t)}
                    />
                    <code className="font-mono">{t}</code>
                  </label>
                )
              })}
            </div>
            {manifest.lens && (
              <p className="text-[10px] text-content-muted mt-1 leading-snug">
                A lens is started by the viewer, so it subscribes to no event. Only the triggers you
                start yourself apply.
              </p>
            )}
            {(manifest.triggers ?? []).includes('request.captured') && (
              <p className="text-[10px] text-semantic-warning mt-1 leading-snug">
                A traffic-triggered automation that sends requests skips the traffic its own run
                produced, so it cannot trigger itself — but it will also miss whatever else was
                captured during that run.
              </p>
            )}
          </Field>

          <Field label="Lens">
            <label className="flex items-center gap-1.5 text-[11px] text-content-secondary mb-1">
              {/* Ticking this clears the event triggers in state rather than merely hiding
                  them, so what the form shows is what gets stored: Normalize drops them
                  server-side anyway, and un-ticking must not offer back something the server
                  will not keep. */}
              <input
                type="checkbox"
                checked={!!manifest.lens}
                onChange={(e) =>
                  patch(
                    e.target.checked
                      ? {
                          lens: { label: '', part: 'response' },
                          triggers: (manifest.triggers ?? []).filter((t) =>
                            OPERATOR_STARTED.includes(t)
                          ),
                        }
                      : { lens: undefined }
                  )
                }
              />
              Render a viewer tab
            </label>
            {manifest.lens && (
              <div className="space-y-1.5">
                <input
                  className={inputCls}
                  value={manifest.lens.label}
                  placeholder="Tab label"
                  maxLength={24}
                  onChange={(e) => patch({ lens: { ...manifest.lens!, label: e.target.value } })}
                />
                <select
                  className={inputCls}
                  value={manifest.lens.part}
                  onChange={(e) => patch({ lens: { ...manifest.lens!, part: e.target.value as LensPart } })}
                >
                  {LENS_PARTS.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
                <p className="text-[10px] text-content-muted leading-snug">
                  Receives <code className="font-mono">ctx.input.raw</code> (base64) and returns{' '}
                  <code className="font-mono">{'{ text }'}</code>. Runs with sends disabled.
                </p>
              </div>
            )}
          </Field>

          <Field label="Minimum interval (ms)">
            {/* A LimitBox with no label of its own: same blank-means-inherit box, so it
                gets the same stepper behaviour rather than a second copy of it. */}
            <LimitBox
              label=""
              value={manifest.minIntervalMs}
              hint={1000}
              onChange={(v) => patch({ minIntervalMs: v })}
            />
          </Field>

          <Field label="Limits (author)">
            <div className="grid grid-cols-2 gap-1.5">
              <LimitBox label="timeout ms" value={manifest.limits?.timeoutMs} hint={globalOf('timeoutMs')} onChange={(v) => patchLimits({ timeoutMs: v })} />
              <LimitBox label="memory MB" value={manifest.limits?.memoryMb} hint={globalOf('memoryMb')} onChange={(v) => patchLimits({ memoryMb: v })} />
              <LimitBox label="max calls" value={manifest.limits?.maxCalls} hint={globalOf('maxCalls')} onChange={(v) => patchLimits({ maxCalls: v })} />
              <LimitBox label="max sends" value={manifest.limits?.maxSendCalls} hint={globalOf('maxSendCalls')} onChange={(v) => patchLimits({ maxSendCalls: v })} />
            </div>
            <p className="text-[10px] text-content-muted mt-0.5">
              What this automation asks for. Blank takes the run budget, shown greyed. Nothing
              here can raise a limit.
            </p>
          </Field>

          {id && (
            <Field label="Limits (operator)">
              <div className="grid grid-cols-2 gap-1.5">
                <LimitBox label="timeout ms" value={override.timeoutMs} hint={globalOf('timeoutMs')} onChange={(v) => setOverride({ ...override, timeoutMs: v })} />
                <LimitBox label="memory MB" value={override.memoryMb} hint={globalOf('memoryMb')} onChange={(v) => setOverride({ ...override, memoryMb: v })} />
                <LimitBox label="max calls" value={override.maxCalls} hint={globalOf('maxCalls')} onChange={(v) => setOverride({ ...override, maxCalls: v })} />
                <LimitBox label="max sends" value={override.maxSendCalls} hint={globalOf('maxSendCalls')} onChange={(v) => setOverride({ ...override, maxSendCalls: v })} />
              </div>
              <button
                onClick={saveOverride}
                disabled={busy}
                className="mt-1.5 w-full text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-40"
              >
                Save operator limits
              </button>
              <p className="text-[10px] text-content-muted mt-1 leading-snug">
                Your own ceiling for this automation, saved separately so updating the code cannot
                revert it.
                {effective && (
                  <>
                    {' '}
                    Effective: {effective.timeoutMs} ms &middot; {effective.memoryMb} MB &middot;{' '}
                    {effective.maxCalls} calls &middot; {effective.maxSendCalls} sending.
                  </>
                )}
              </p>
            </Field>
          )}

          <Field label="Test input (JSON)">
            <textarea
              className={`${inputCls} h-14 resize-none font-mono`}
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
          </Field>

          <SdkReference />
        </div>
      </div>

      {run && <RunOutput run={run} onClose={() => setRun(null)} />}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-[10px] font-semibold text-content-muted uppercase tracking-wide mb-1">
        {label}
      </label>
      {children}
    </div>
  )
}

/**
 * One numeric limit. hint is what a run gets while the box is empty.
 *
 * A text box rather than type=number, for the reason BudgetPanel's cell gives: a stepper on
 * a box that is empty by design steps from 1 rather than from the figure being inherited.
 */
function LimitBox({
  label,
  value,
  hint,
  onChange,
}: {
  label: string
  value?: number
  hint?: number
  onChange: (v: number | undefined) => void
}) {
  return (
    <label className="block">
      {label && <span className="block text-[10px] text-content-muted">{label}</span>}
      <input
        type="text"
        inputMode="numeric"
        autoComplete="off"
        className={inputCls}
        value={value ?? ''}
        placeholder={hint !== undefined ? String(hint) : ''}
        onChange={(e) => {
          const digits = e.target.value.replace(/[^0-9]/g, '')
          onChange(digits !== '' && Number(digits) > 0 ? Number(digits) : undefined)
        }}
      />
    </label>
  )
}

