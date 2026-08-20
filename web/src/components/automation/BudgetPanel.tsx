import { useEffect, useState } from 'react'
import { RotateCcw, Save } from 'lucide-react'
import type {
  AutomationBudget,
  AutomationHostLimits,
  AutomationLimits,
  BudgetSpec,
} from '../../lib/api'
import { useAutomationStore } from '../../stores/automationStore'
import { useToastStore } from '../../stores/toastStore'

const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border w-24 text-right'

/** A draft as this panel holds it: every row is driven by a spec key the server sent, so
 *  indexing by string is what the panel actually does. Cast once at the API boundary. */
type Fields = Record<string, number | undefined>

/**
 * The ceiling on a row, printed under its numbers — for the few fields that really do stop
 * somewhere. A field with no cap renders nothing, and that absence is the statement: the
 * operator's number is final there, so printing a bound would be the same illusion as
 * refusing the value they typed.
 */
function CapLine({ spec }: { spec: BudgetSpec }) {
  if (!spec.cap) return null
  return (
    <div className="text-[10px] text-semantic-warning text-right mt-1">
      &le; {spec.cap} {spec.unit}
    </div>
  )
}

/** Why that ceiling is where it is, in the row's own words. */
function CapReason({ spec }: { spec: BudgetSpec }) {
  if (!spec.cap) return null
  return (
    <p className="text-[10px] text-content-muted leading-snug mt-0.5 max-w-xl italic">
      {spec.cap} {spec.unit} is the ceiling: {spec.capReason}.
    </p>
  )
}

/** The greyed figure in the Max column: what the maximum currently resolves to, which is
 *  Joro's own number unless the operator's default has raised it past that. */
function maxPlaceholder(budget: AutomationBudget, sp: BudgetSpec): number {
  const resolved = (budget.effectiveMax as Record<string, number | undefined>)[sp.key]
  return resolved !== undefined ? resolved / sp.factor : (sp.defaultMax ?? 0)
}

function shown(stored: number | undefined, sp: BudgetSpec): string {
  if (!stored) return ''
  return String(stored / sp.factor)
}

/**
 * The run budget: what one sandboxed automation may do, and how many may run at once.
 *
 * Two halves, because they answer different questions. Per run the operator sets a
 * default (what a run that asks for nothing gets) and a maximum (the most a run may ask
 * for). The host limits are properties of this Joro rather than of one run, so they are a
 * single number each.
 *
 * Every figure and every sentence comes from GET /automation/limits, which builds them
 * from the constants the runtime enforces. Nothing about the budget is written twice.
 */
export default function BudgetPanel() {
  const { budget, scriptsUnavailable, refreshBudget, setBudget } = useAutomationStore()
  const addToast = useToastStore((s) => s.addToast)

  const [defaults, setDefaults] = useState<Fields>({})
  const [maxima, setMaxima] = useState<Fields>({})
  const [host, setHost] = useState<Fields>({})
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    refreshBudget()
  }, [refreshBudget])

  // Re-seeded whenever the server's copy changes, which is on load and after a save.
  useEffect(() => {
    if (!budget) return
    setDefaults({ ...budget.policy.defaults })
    setMaxima({ ...budget.policy.maxima })
    setHost({ ...budget.policy.host })
  }, [budget])

  if (!budget) {
    return (
      <div className="flex-1 overflow-auto p-5">
        <h3 className="text-sm font-semibold text-content-primary mb-2">Run budget</h3>
        <p className="text-[11px] text-content-secondary leading-relaxed max-w-xl">
          {scriptsUnavailable?.includes('--automation-scripting') ? (
            <>
              Script automation is off, so there is no run budget to set. Start Joro with{' '}
              <code className="font-mono text-content-primary">--automation-scripting</code> to install
              JavaScript automations.
            </>
          ) : (
            <>{scriptsUnavailable ?? 'Loading…'}</>
          )}
        </p>
      </div>
    )
  }

  const stored = budget.policy
  const same = (a: Fields, b: Fields, keys: string[]) =>
    keys.every((k) => (a[k] ?? 0) === (b[k] ?? 0))
  const runKeys = budget.specs.map((sp) => sp.key)
  const hostKeys = budget.hostSpecs.map((sp) => sp.key)
  const dirty =
    !same(defaults, { ...stored.defaults }, runKeys) ||
    !same(maxima, { ...stored.maxima }, runKeys) ||
    !same(host, { ...stored.host }, hostKeys)

  const clear = () => {
    setDefaults({})
    setMaxima({})
    setHost({})
  }

  const save = async () => {
    setBusy(true)
    try {
      await setBudget({
        defaults: defaults as AutomationLimits,
        maxima: maxima as AutomationLimits,
        host: host as AutomationHostLimits,
      })
      addToast('Run budget saved', 'info')
    } catch (e) {
      // The server names the field it refused and the limit it broke rather than
      // clamping silently, so this message is the whole explanation.
      addToast(String(e instanceof Error ? e.message : e), 'error')
    } finally {
      setBusy(false)
    }
  }

  /**
   * One figure, in the operator's unit, stored in the field's.
   *
   * A text box rather than type=number, deliberately. A number input's stepper starts from
   * its minimum when the box is empty — and an unset field here *is* empty, showing what it
   * inherits as a placeholder — so the first press produced 1 and the next 2, which reads as
   * the field resetting and refusing to climb. Seeding the box to fix that then ran into a
   * number input supporting no selection API, so typing over the seed appended to it. None
   * of that exists for a text box: it holds what you type, an empty one still means "inherit
   * Joro's figure", and no browser-side max, min or step implies a bound the field does not
   * have. Where a bound does exist the row prints it, and the server refuses a value past it
   * naming what it is fixed against.
   *
   * Non-digits are dropped as they arrive, so the box cannot hold something that is not a
   * number and every value here parses.
   */
  const cell = (
    sp: BudgetSpec,
    value: number | undefined,
    placeholder: number,
    onChange: (v: number | undefined) => void
  ) => (
    <input
      type="text"
      inputMode="numeric"
      autoComplete="off"
      aria-label={`${sp.label} (${sp.unit})`}
      className={inputCls}
      placeholder={String(placeholder)}
      value={shown(value, sp)}
      onChange={(e) => {
        const digits = e.target.value.replace(/[^0-9]/g, '')
        const n = Number(digits)
        onChange(digits !== '' && n > 0 ? Math.round(n * sp.factor) : undefined)
      }}
    />
  )

  return (
    <div className="flex-1 overflow-auto p-5 space-y-5">
      <div className="flex items-start gap-2">
        <div className="max-w-2xl space-y-1.5">
          <h3 className="text-sm font-semibold text-content-primary">Run budget</h3>
          <p className="text-[11px] text-content-muted leading-relaxed">
            An automation is code Joro executes on your behalf, and some of it is written by an
            agent rather than by you. The budget is what keeps the cost of running it bounded and
            knowable: a script that loops forever, allocates without end, or calls the SDK ten
            thousand times stops at a number you chose, and a runaway costs a worker process
            rather than the proxy holding your captured traffic. It is also the leash on an agent
            — without it, one <code className="font-mono">script_run</code> call could turn into an
            open-ended sweep of a client&rsquo;s systems.
          </p>
          <p className="text-[11px] text-content-muted leading-relaxed">
            Raise these when the defaults are too small for the work — a wider sweep, a longer
            comparison — and lower them when an agent should be kept on a shorter leash than you
            are.
          </p>
        </div>
        <div className="ml-auto flex items-center gap-1.5 shrink-0">
          <button
            onClick={clear}
            disabled={busy}
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary disabled:opacity-40"
            title="Clear every field back to Joro's own numbers"
          >
            <RotateCcw size={11} strokeWidth={2} aria-hidden="true" />
            Defaults
          </button>
          <button
            onClick={save}
            disabled={busy || !dirty}
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-40"
          >
            <Save size={11} strokeWidth={2.2} aria-hidden="true" />
            Save
          </button>
        </div>
      </div>

      {/* Per run: a default and a maximum. */}
      <div>
        <div className="flex items-end gap-3 mb-1.5">
          <h4 className="text-xs font-semibold text-content-muted uppercase tracking-wide">Per run</h4>
          <div className="ml-auto flex gap-3 text-[10px] text-content-muted uppercase tracking-wide">
            <span className="w-24 text-right">Default</span>
            <span className="w-24 text-right">Max</span>
          </div>
        </div>
        <div className="bg-surface-card border border-border rounded divide-y divide-border-subtle">
          {budget.specs.map((sp) => (
            <div key={sp.key} className="p-3 flex items-start gap-3">
              <div className="min-w-0">
                <div className="text-xs font-semibold text-content-primary">
                  {sp.label} <span className="text-content-muted font-normal">({sp.unit})</span>
                </div>
                <p className="text-[10px] text-content-muted leading-snug mt-0.5 max-w-xl">
                  {sp.description}
                </p>
                <CapReason spec={sp} />
              </div>
              <div className="ml-auto shrink-0">
                <div className="flex gap-3">
                  {cell(sp, defaults[sp.key], sp.default, (v) =>
                    setDefaults({ ...defaults, [sp.key]: v })
                  )}
                  {cell(sp, maxima[sp.key], maxPlaceholder(budget, sp), (v) =>
                    setMaxima({ ...maxima, [sp.key]: v })
                  )}
                </div>
                <CapLine spec={sp} />
              </div>
            </div>
          ))}
        </div>
        <p className="text-[10px] text-content-muted leading-relaxed mt-1.5 max-w-2xl">
          The <strong>default</strong> is what a run that asks for nothing gets. The{' '}
          <strong>max</strong> is the most a run may ask for — an agent calling{' '}
          <code className="font-mono">script_run</code> names its own figure, and anything above
          yours is trimmed to yours rather than refused. A blank box takes the greyed number
          beside it, which is Joro&rsquo;s own; type over it and your number stands, however much
          higher. A row showing <span className="font-mono">&le;</span> under its numbers has a
          ceiling neither figure may pass, and says what that ceiling is tied to; a row without
          one has no further limit.
        </p>
      </div>

      {/* Host limits: one number each. */}
      <div>
        <div className="flex items-end gap-3 mb-1.5">
          <h4 className="text-xs font-semibold text-content-muted uppercase tracking-wide">
            This Joro
          </h4>
          <div className="ml-auto flex gap-3 text-[10px] text-content-muted uppercase tracking-wide">
            <span className="w-24 text-right">Limit</span>
          </div>
        </div>
        <div className="bg-surface-card border border-border rounded divide-y divide-border-subtle">
          {budget.hostSpecs.map((sp) => (
            <div key={sp.key} className="p-3 flex items-start gap-3">
              <div className="min-w-0">
                <div className="text-xs font-semibold text-content-primary">
                  {sp.label} <span className="text-content-muted font-normal">({sp.unit})</span>
                </div>
                <p className="text-[10px] text-content-muted leading-snug mt-0.5 max-w-xl">
                  {sp.description}
                </p>
                <CapReason spec={sp} />
              </div>
              <div className="ml-auto shrink-0">
                {cell(sp, host[sp.key], sp.default, (v) =>
                  setHost({ ...host, [sp.key]: v })
                )}
                <CapLine spec={sp} />
              </div>
            </div>
          ))}
        </div>
        <p className="text-[10px] text-content-muted leading-relaxed mt-1.5 max-w-2xl">
          These belong to this Joro rather than to one run, so there is nothing for an automation
          or an agent to ask for: your number is the limit. The two agent figures are the
          exception — they share {Math.round(budget.agentOutputCap / 1024)} KB of tool result
          between them, so their sum is checked as well as each one.
        </p>
      </div>

      {/* What it applies to. */}
      <div className="max-w-2xl">
        <h4 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-1.5">
          Where this applies
        </h4>
        <ul className="text-[11px] text-content-muted leading-relaxed space-y-1 list-disc pl-4">
          <li>
            Every run, however it started: an agent&rsquo;s{' '}
            <code className="font-mono">script_run</code>, a run you start from the editor, an
            automation an agent invokes, a lens rendering a viewer tab, and a trigger firing.
          </li>
          <li>
            An automation can ask for less than this, never more. Joro takes the smallest of three
            numbers: what the author asked for in the manifest, the override you set on that
            automation, and the budget here.
          </li>
          <li>Changes take effect on the next run. Anything already running keeps its budget.</li>
        </ul>
      </div>
    </div>
  )
}
