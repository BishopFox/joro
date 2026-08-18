import { useCallback, useEffect, useMemo, useState } from 'react'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { javascript } from '@codemirror/lang-javascript'
import { oneDark } from '@codemirror/theme-one-dark'
import { Download, Play, Save, X } from 'lucide-react'
import { api, type AutomationLimits, type AutomationManifest, type ScriptRun } from '../../lib/api'
import { downloadPackage } from '../../lib/automationPackage'
import { useToastStore } from '../../stores/toastStore'
import SdkReference from './SdkReference'

const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border w-full'

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

  const [manifest, setManifest] = useState<AutomationManifest>(draft?.manifest ?? blankManifest())
  const [source, setSource] = useState(draft?.source ?? STARTER)
  // The hash the source was loaded at. Sent back on update so replacing the code of an
  // armed automation cannot silently clobber a concurrent edit.
  const [baseHash, setBaseHash] = useState('')
  const [busy, setBusy] = useState(false)
  const [run, setRun] = useState<ScriptRun | null>(null)
  const [input, setInput] = useState('{}')

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
      })
      .catch((e) => addToast(String(e instanceof Error ? e.message : e), 'error'))
    return () => {
      cancelled = true
    }
  }, [id, addToast])

  const extensions = useMemo(() => [javascript(), EditorView.lineWrapping], [])

  const patch = (p: Partial<AutomationManifest>) => setManifest((m) => ({ ...m, ...p }))
  const patchLimits = (p: Partial<AutomationLimits>) =>
    setManifest((m) => ({ ...m, limits: { ...m.limits, ...p } }))

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
            <p className="text-[10px] text-content-muted font-mono">sha256:{baseHash.slice(0, 16)}</p>
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
              {triggers.map((t) => (
                <label key={t} className="flex items-center gap-1.5 text-[11px] text-content-secondary">
                  <input
                    type="checkbox"
                    checked={(manifest.triggers ?? []).includes(t)}
                    onChange={() => toggleTrigger(t)}
                  />
                  <code className="font-mono">{t}</code>
                </label>
              ))}
            </div>
            {(manifest.triggers ?? []).includes('request.captured') && (
              <p className="text-[10px] text-semantic-warning mt-1 leading-snug">
                A traffic-triggered automation that sends requests skips the traffic its own run
                produced, so it cannot trigger itself — but it will also miss whatever else was
                captured during that run.
              </p>
            )}
          </Field>

          <Field label="Minimum interval (ms)">
            <input
              type="number"
              className={inputCls}
              value={manifest.minIntervalMs ?? ''}
              placeholder="1000"
              onChange={(e) => patch({ minIntervalMs: Number(e.target.value) || undefined })}
            />
          </Field>

          <Field label="Limits">
            <div className="grid grid-cols-2 gap-1.5">
              <LimitBox label="timeout ms" value={manifest.limits?.timeoutMs} onChange={(v) => patchLimits({ timeoutMs: v })} />
              <LimitBox label="memory MB" value={manifest.limits?.memoryMb} onChange={(v) => patchLimits({ memoryMb: v })} />
              <LimitBox label="max calls" value={manifest.limits?.maxCalls} onChange={(v) => patchLimits({ maxCalls: v })} />
              <LimitBox label="max sends" value={manifest.limits?.maxSendCalls} onChange={(v) => patchLimits({ maxSendCalls: v })} />
            </div>
            <p className="text-[10px] text-content-muted mt-0.5">
              Blank takes the default. The operator can lower these further; nothing here can
              raise a limit.
            </p>
          </Field>

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

function LimitBox({
  label,
  value,
  onChange,
}: {
  label: string
  value?: number
  onChange: (v: number | undefined) => void
}) {
  return (
    <label className="block">
      <span className="block text-[10px] text-content-muted">{label}</span>
      <input
        type="number"
        className={inputCls}
        value={value ?? ''}
        onChange={(e) => onChange(Number(e.target.value) || undefined)}
      />
    </label>
  )
}

/** The run report: how it ended, what it logged, what it returned. */
function RunOutput({ run, onClose }: { run: ScriptRun; onClose: () => void }) {
  const r = run.result
  const bad = r.reason !== 'success'
  return (
    <div className="shrink-0 border-t border-border max-h-56 overflow-y-auto">
      <div className="flex items-center gap-2 px-3 py-1.5 sticky top-0 bg-surface-card border-b border-border-subtle">
        <span className={`text-[11px] font-semibold ${bad ? 'text-semantic-warning' : 'text-semantic-success'}`}>
          {r.reason}
        </span>
        <span className="text-[10px] text-content-muted font-mono">
          {run.durationMs}ms · {r.calls} call{r.calls === 1 ? '' : 's'}
          {r.sendCalls > 0 ? ` (${r.sendCalls} sending)` : ''}
          {r.storageOps ? ` · ${r.storageOps} storage` : ''}
        </span>
        <button onClick={onClose} className="ml-auto text-content-muted hover:text-content-primary" aria-label="Dismiss">
          <X size={13} strokeWidth={2} />
        </button>
      </div>
      <div className="p-3 space-y-2 text-[11px]">
        {r.err && <pre className="font-mono whitespace-pre-wrap text-semantic-error">{r.err}</pre>}
        {r.logs && r.logs.length > 0 && (
          <div className="font-mono bg-surface-input rounded p-2">
            {r.logs.map((l, i) => (
              <div
                key={i}
                className={
                  l.level === 'error'
                    ? 'text-semantic-error'
                    : l.level === 'warn'
                      ? 'text-semantic-warning'
                      : 'text-content-secondary'
                }
              >
                {l.text}
              </div>
            ))}
            {r.logsTruncated && <div className="text-content-muted">… log budget reached</div>}
          </div>
        )}
        {r.value !== undefined && r.value !== null && (
          <pre className="font-mono whitespace-pre-wrap bg-surface-input rounded p-2 overflow-x-auto">
            {JSON.stringify(r.value, null, 2)}
          </pre>
        )}
      </div>
    </div>
  )
}
