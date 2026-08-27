import { AlertTriangle, Bot, Download, Play, Power, PowerOff, Save, Trash2, X } from 'lucide-react'
import {
  LENS_PARTS,
  type AutomationKind,
  type AutomationLimits,
  type AutomationManifest,
  type CommandMeta,
  type LensPart,
} from '../../lib/api'
import TabButton from '../TabButton'

const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border w-full'

// The two triggers the operator starts, so the Dispatcher never watches them and a lens may
// still declare them. Mirrors dispatched() in internal/jsautomation/manifest.go, which drops
// the rest from a manifest that declares a lens.
//
// Defined here rather than in the editor because this is the file that decides which
// checkboxes a lens may keep; ScriptEditor re-exports it for ScriptingPanel, which needs the
// same split to say what enabling an automation would arm.
export const OPERATOR_STARTED = ['manual', 'request.selected']

/**
 * What this automation is called, what you can do to it, and which half of it you are
 * looking at. Nothing else.
 *
 * Its settings are not here. They live in the rail beside the body, permanently, because
 * they are edited while looking at the thing they describe — a trigger list read against the
 * canvas showing those triggers, a lens label read against the box that renders it. A header
 * that folded open to show them covered the canvas to do it.
 */
export default function AutomationHeader({
  id,
  manifest,
  baseHash,
  author,
  busy,
  canSave,
  canRun,
  dirty,
  enabled,
  paused,
  pausedReason,
  onRun,
  onSave,
  onToggleEnabled,
  onExport,
  onDelete,
  onClose,
  view,
  onView,
  hasGraph,
  graphStale,
  problems = [],
  toolbar,
}: {
  id?: string
  manifest: AutomationManifest
  baseHash: string
  author: string
  busy: boolean
  canSave: boolean
  canRun: boolean
  dirty: boolean
  enabled?: boolean
  paused?: boolean
  pausedReason?: string
  onRun: () => void
  onSave: () => void
  onToggleEnabled?: () => void
  onExport?: () => void
  onDelete?: () => void
  onClose: () => void
  view: 'graph' | 'code'
  onView: (v: 'graph' | 'code') => void
  /** Whether a canvas owns the body, which is what makes the code half a generated view
   *  rather than the thing being edited. */
  hasGraph: boolean
  graphStale?: boolean
  /** What the canvas cannot compile, one message per fault. Non-empty is what disables
   *  Save, so the reason has to be reachable from here — a bare count is a dead end. */
  problems?: string[]
  /** The canvas palette, when the canvas is what is on screen. */
  toolbar?: React.ReactNode
}) {
  const isCommand = manifest.kind === 'command'
  return (
    <div className="shrink-0 border-b border-border">
      <div className="flex items-center gap-2 px-3 py-2">
        <div className="min-w-0">
          <h3 className="text-xs font-semibold text-content-primary truncate">
            {id ? manifest.name || id : 'New automation'}
            {dirty && (
              <span className="ml-1.5 text-accent-tertiary" title="Unsaved changes">
                &bull;
              </span>
            )}
          </h3>
          {baseHash && (
            <p className="text-[10px] text-content-muted font-mono">
              sha256:{baseHash.slice(0, 16)}
              {paused && (
                /* A badge, not the sentence. The breaker's explanation is three lines of
                   prose about self-triggering and intervals — worth reading once, and worth
                   staying out of the way every other time the operator opens this. */
                <span
                  className="inline-flex items-center gap-1 ml-1.5 px-1 py-px rounded-sm bg-surface-input text-semantic-warning font-sans cursor-help"
                  title={pausedReason}
                >
                  <AlertTriangle size={9} strokeWidth={2.4} aria-hidden="true" />
                  paused automatically
                </span>
              )}
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
            onClick={onRun}
            disabled={busy || !canRun}
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black font-semibold disabled:opacity-40"
            title={canRun ? 'Run once now (allowed even when disabled)' : 'A command has to be installed before it can run'}
          >
            <Play size={11} strokeWidth={2.2} aria-hidden="true" />
            Run
          </button>
          <button
            onClick={onSave}
            disabled={busy || !canSave}
            title={
              problems.length > 0
                ? `A canvas that does not compile does not write a file:\n\n${problems.join('\n')}`
                : undefined
            }
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-40"
          >
            <Save size={11} strokeWidth={2.2} aria-hidden="true" />
            {id ? 'Save' : 'Install'}
          </button>
          {id && onToggleEnabled && (
            <button
              onClick={onToggleEnabled}
              disabled={busy}
              className={`inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover disabled:opacity-40 ${
                enabled ? 'text-semantic-success' : 'text-content-secondary'
              }`}
              title={
                manifest.lens
                  ? enabled
                    ? 'Hide this viewer tab'
                    : 'Show this viewer tab'
                  : enabled
                    ? 'Disable'
                    : paused
                      ? 'Enable (clears the pause)'
                      : 'Enable — arms every trigger below'
              }
            >
              {enabled ? <Power size={11} strokeWidth={2.2} /> : <PowerOff size={11} strokeWidth={2.2} />}
              {manifest.lens ? (enabled ? 'Shown' : 'Hidden') : enabled ? 'Enabled' : 'Disabled'}
            </button>
          )}
          {onExport && (
            <button
              onClick={onExport}
              disabled={!canSave}
              className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-40"
              title="Export as a .jauto package"
            >
              <Download size={11} strokeWidth={2} aria-hidden="true" />
            </button>
          )}
          {id && onDelete && (
            <button
              onClick={onDelete}
              disabled={busy}
              className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-muted hover:text-semantic-error disabled:opacity-40"
              title="Uninstall"
            >
              <Trash2 size={11} strokeWidth={2} aria-hidden="true" />
            </button>
          )}
          <button onClick={onClose} className="text-content-muted hover:text-content-primary" aria-label="Close editor">
            <X size={15} strokeWidth={2} />
          </button>
        </div>
      </div>


      {/* Tabs on the left, the canvas palette on the right under the action buttons it
          lines up with. The palette wraps rather than running on, so a row of fifteen
          buttons becomes two short ones and the header stays the same height whatever is
          in it.

          Graph is first because it is what the automation does; the code half is what that
          compiles to. A hand-written automation gets the same pair, where the graph shows
          the wiring it does have — what wakes it and what it produces. */}
      <div className="flex items-start gap-3 px-3 pb-2">
        <div className="flex items-center gap-0.5 shrink-0">
          <TabButton active={view === 'graph'} onClick={() => onView('graph')}>
            Graph
          </TabButton>
          <TabButton active={view === 'code'} onClick={() => onView('code')}>
            {isCommand ? 'Command' : 'Code'}
          </TabButton>
          {problems.length > 0 && (
            <span className="ml-2 text-[10px] text-semantic-error cursor-help" title={problems.join('\n')}>
              {problems.length} problem{problems.length === 1 ? '' : 's'}
            </span>
          )}
          {hasGraph && problems.length === 0 && (
            <span
              className={`ml-2 text-[10px] ${graphStale ? 'text-semantic-warning' : 'text-content-muted'}`}
              title={
                graphStale
                  ? 'The stored code was edited outside Joro and no longer matches this canvas.'
                  : 'The code is generated from the canvas.'
              }
            >
              {graphStale ? 'canvas out of step with the code' : 'code generated from the canvas'}
            </span>
          )}
        </div>

        {toolbar && <div className="ml-auto flex flex-wrap justify-end gap-1">{toolbar}</div>}
      </div>
    </div>
  )
}

/**
 * Everything about an automation that is not its body: what it is called, what wakes it,
 * whether it renders a viewer tab, and what a run of it is held to.
 *
 * A column in the rail, always present, beside whichever view is open. These are read
 * against the thing they describe — the trigger list against the canvas showing those
 * triggers — so putting them anywhere that covers the body to be read is the wrong place.
 */
export function AutomationOptions({
  id,
  manifest,
  patch,
  patchLimits,
  kind,
  isCommand,
  kinds,
  scriptingEnabled,
  commandMeta,
  onKindChange,
  override,
  setOverride,
  effective,
  saveOverride,
  lensOrder,
  onLensOrder,
  busy,
  globalOf,
  commandOr,
  input,
  setInput,
}: {
  id?: string
  manifest: AutomationManifest
  patch: (p: Partial<AutomationManifest>) => void
  patchLimits: (p: Partial<AutomationLimits>) => void
  kind: AutomationKind
  isCommand: boolean
  kinds: AutomationKind[]
  scriptingEnabled: boolean
  commandMeta: CommandMeta | null
  onKindChange: (k: AutomationKind) => void
  override: AutomationLimits
  setOverride: (l: AutomationLimits) => void
  effective: AutomationLimits | null
  saveOverride: () => void
  lensOrder: string
  onLensOrder: (v: string, commit: boolean) => void
  busy: boolean
  globalOf: (k: keyof AutomationLimits) => number | undefined
  commandOr: (k: 'timeoutMs') => number | undefined
  input: string
  setInput: (v: string) => void
}) {
  const hasTrigger = (t: string) => (manifest.triggers ?? []).includes(t)

  return (
    <div className="space-y-3">
      {/* Identity */}
      <div className="space-y-2">
        <div className="space-y-2">
          <Field label="Id">
            <input
              className={inputCls}
              value={manifest.id}
              disabled={!!id}
              placeholder="idor-check"
              onChange={(e) => patch({ id: e.target.value })}
            />
          </Field>
          <Field label="Version">
            <input className={inputCls} value={manifest.version} onChange={(e) => patch({ version: e.target.value })} />
          </Field>
        </div>
        <Field label="Name">
          <input className={inputCls} value={manifest.name} onChange={(e) => patch({ name: e.target.value })} />
        </Field>
        <Field label="Description">
          <textarea
            className={`${inputCls} h-12 resize-none`}
            value={manifest.description ?? ''}
            onChange={(e) => patch({ description: e.target.value })}
          />
        </Field>
        <Field label="Kind">
          <select className={inputCls} value={kind} disabled={!!id} onChange={(e) => onKindChange(e.target.value as AutomationKind)}>
            {kinds.map((k) => (
              <option key={k} value={k} disabled={k === 'js' && !scriptingEnabled}>
                {k === 'command' ? 'Local command' : 'Sandboxed script'}
              </option>
            ))}
          </select>
          {!id && (
            <p className="text-[10px] text-content-muted mt-0.5 leading-snug">
              Permanent, like the id. A script runs in a sandboxed worker against the SDK; a command runs a
              program on this machine.
            </p>
          )}
          {isCommand && commandMeta && !commandMeta.enabled && (
            <p className="text-[10px] text-semantic-warning mt-1 leading-snug">
              Command automations are not enabled on this instance, so this will install and list but never
              run. Restart Joro with <code className="font-mono">--automation-commands</code>.
            </p>
          )}
        </Field>
        <Field label="Test input (JSON)">
          <textarea
            className={`${inputCls} h-12 resize-none font-mono`}
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
        </Field>
      </div>

      {/* Pacing, and what the declared triggers imply.

          There is no trigger list here. The graph shows one box per trigger and the canvas
          rail adds and removes them, so a checkbox list beside it would be a second control
          over one thing — and the one further from the boxes it governs. What survives is
          what the boxes cannot say: the consequences of a choice already made. */}
      <div className="space-y-2 border-t border-border-subtle pt-3">
        <Field label="Minimum interval (ms)">
          {/* A LimitBox with no label of its own: same blank-means-inherit box, so it gets the
              same stepper behaviour rather than a second copy of it. */}
          <LimitBox label="" value={manifest.minIntervalMs} hint={1000} onChange={(v) => patch({ minIntervalMs: v })} />
        </Field>

        {manifest.lens && (
          <p className="text-[10px] text-content-muted leading-snug">
            A lens is started by the viewer, so it subscribes to no event. Only the triggers you start
            yourself apply.
          </p>
        )}
        {hasTrigger('request.captured') &&
          (isCommand ? (
            /* A command is handed one event, not a batch, and its cursor always jumps to the
               newest capture — Joro cannot count a subprocess's requests, so it has to assume
               it made some. The result is sampling, and an operator expecting every request to
               be examined would otherwise read an empty result as nothing having been found. */
            <p className="text-[10px] text-semantic-warning leading-snug">
              A command sees the most recent request, at most once per interval, and skips whatever
              arrived in between — it samples traffic rather than examining all of it. Joro cannot tell
              whether a program sent anything, so it always assumes it did and moves past its own window.
            </p>
          ) : (
            <p className="text-[10px] text-semantic-warning leading-snug">
              A traffic-triggered automation that sends requests skips the traffic its own run produced,
              so it cannot trigger itself — but it will also miss whatever else was captured during that
              run.
            </p>
          ))}
      </div>

      {/* Lens + limits */}
      <div className="space-y-2 border-t border-border-subtle pt-3">
        <Field label="Lens">
          <label className="flex items-center gap-1.5 text-[11px] text-content-secondary mb-1">
            {/* Ticking this clears the event triggers in state rather than merely hiding them,
                so what the form shows is what gets stored: Normalize drops them server-side
                anyway, and un-ticking must not offer back something the server will not keep. */}
            <input
              type="checkbox"
              checked={!!manifest.lens}
              onChange={(e) =>
                patch(
                  e.target.checked
                    ? {
                        lens: { label: '', part: 'response' },
                        triggers: (manifest.triggers ?? []).filter((t) => OPERATOR_STARTED.includes(t)),
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
              {id && (
                <label className="block">
                  <span className="block text-[10px] text-content-muted">
                    Order in the strip — lower sits left
                  </span>
                  {/* An operator preference, not the author's: written to the sidecar through
                      the prefs endpoint, so updating the code cannot revert it. Hence the
                      separate commit on blur rather than riding along with Save. */}
                  <input
                    type="number"
                    className={inputCls}
                    value={lensOrder}
                    onChange={(e) => onLensOrder(e.target.value, false)}
                    onBlur={(e) => onLensOrder(e.target.value, true)}
                  />
                </label>
              )}
              {isCommand ? (
                /* A script lens is provably send-free: its grants are stripped. A command lens
                   has no grants to strip, so the same sentence would claim containment that
                   does not exist here. */
                <p className="text-[10px] text-semantic-warning leading-snug">
                  Receives the bytes on screen on its standard input and its output becomes the tab. Unlike
                  a script lens, this is not prevented from reaching the network — there are no
                  capabilities to withhold from a program — so it runs every time you open a matching
                  request.
                </p>
              ) : (
                <p className="text-[10px] text-content-muted leading-snug">
                  Receives <code className="font-mono">ctx.input.raw</code> (base64) and returns{' '}
                  <code className="font-mono">{'{ text }'}</code>. Runs with sends disabled.
                </p>
              )}
            </div>
          )}
        </Field>

        <Field label="Limits (author)">
          <div className="grid grid-cols-2 gap-1.5">
            <LimitBox label="timeout ms" value={manifest.limits?.timeoutMs} hint={commandOr('timeoutMs')} onChange={(v) => patchLimits({ timeoutMs: v })} />
            {/* SDK calls, sends and a memory ceiling mean nothing to a subprocess: it makes no
                SDK calls, and it is already its own process, so the rest of its budget is what
                Joro keeps of its output. Those live in the run budget rather than per
                automation, so there is nothing to show here. */}
            {!isCommand && (
              <>
                <LimitBox label="memory MB" value={manifest.limits?.memoryMb} hint={globalOf('memoryMb')} onChange={(v) => patchLimits({ memoryMb: v })} />
                <LimitBox label="max calls" value={manifest.limits?.maxCalls} hint={globalOf('maxCalls')} onChange={(v) => patchLimits({ maxCalls: v })} />
                <LimitBox label="max sends" value={manifest.limits?.maxSendCalls} hint={globalOf('maxSendCalls')} onChange={(v) => patchLimits({ maxSendCalls: v })} />
              </>
            )}
          </div>
          <p className="text-[10px] text-content-muted mt-0.5">
            What this automation asks for. Blank takes the run budget, shown greyed. Nothing here can raise
            a limit.
          </p>
        </Field>

        {id && (
          <Field label="Limits (operator)">
            <div className="grid grid-cols-2 gap-1.5">
              <LimitBox label="timeout ms" value={override.timeoutMs} hint={commandOr('timeoutMs')} onChange={(v) => setOverride({ ...override, timeoutMs: v })} />
              {!isCommand && (
                <>
                  <LimitBox label="memory MB" value={override.memoryMb} hint={globalOf('memoryMb')} onChange={(v) => setOverride({ ...override, memoryMb: v })} />
                  <LimitBox label="max calls" value={override.maxCalls} hint={globalOf('maxCalls')} onChange={(v) => setOverride({ ...override, maxCalls: v })} />
                  <LimitBox label="max sends" value={override.maxSendCalls} hint={globalOf('maxSendCalls')} onChange={(v) => setOverride({ ...override, maxSendCalls: v })} />
                </>
              )}
            </div>
            <button
              onClick={saveOverride}
              disabled={busy}
              className="mt-1.5 w-full text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-40"
            >
              Save operator limits
            </button>
            <p className="text-[10px] text-content-muted mt-1 leading-snug">
              Your own ceiling for this automation, saved separately so updating the code cannot revert it.
              {effective && (
                <>
                  {' '}
                  Effective: {effective.timeoutMs} ms
                  {!isCommand && (
                    <>
                      {' '}
                      &middot; {effective.memoryMb} MB &middot; {effective.maxCalls} calls &middot;{' '}
                      {effective.maxSendCalls} sending
                    </>
                  )}
                  .
                </>
              )}
            </p>
          </Field>
        )}
      </div>
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
 * A text box rather than type=number, for the reason BudgetPanel's cell gives: a stepper on a
 * box that is empty by design steps from 1 rather than from the figure being inherited.
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
