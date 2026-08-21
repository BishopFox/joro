import { useEffect, useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { api, LENS_PARTS, type AutomationSummary } from '../../lib/api'
import { useAutomationStore } from '../../stores/automationStore'
import { useToastStore } from '../../stores/toastStore'

const inputCls = 'bg-surface-input text-[11px] px-1.5 py-0.5 rounded-sm border border-border'

/**
 * The lenses an operator has installed, and the three things they may change about one:
 * its tab title, which half of the transaction it renders, and where it sits in the strip.
 *
 * Overrides are written to the automation's sidecar, so updating its source never reverts
 * them. Showing a lens is the automation's own enable switch — a lens declares no
 * triggers, so enabling one arms nothing.
 */
export default function LensPanel({ onEdit }: { onEdit: (id: string) => void }) {
  const { scripts, scriptsUnavailable, refreshScripts } = useAutomationStore()
  const addToast = useToastStore((s) => s.addToast)

  useEffect(() => {
    refreshScripts()
  }, [refreshScripts])

  const lenses = scripts.filter((s) => s.lens)

  const guard = async (fn: () => Promise<unknown>, ok?: string) => {
    try {
      await fn()
      if (ok) addToast(ok, 'info')
      await refreshScripts()
    } catch (e) {
      addToast(String(e instanceof Error ? e.message : e), 'error')
    }
  }

  if (scriptsUnavailable) {
    return (
      <div className="flex-1 overflow-auto p-5">
        <h3 className="text-sm font-semibold text-content-primary mb-2">Lenses</h3>
        <p className="text-[11px] text-content-secondary leading-relaxed max-w-xl">
          {scriptsUnavailable.includes('--automation-scripting') ? (
            <>
              Script automation is off. Start Joro with{' '}
              <code className="font-mono text-content-primary">--automation-scripting</code> to install
              automations and add viewer tabs.
            </>
          ) : (
            <>Automation is disabled on this instance ({scriptsUnavailable}).</>
          )}
        </p>
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-auto p-5 space-y-3">
      <div>
        <h3 className="text-sm font-semibold text-content-primary">Lenses</h3>
        <p className="text-[11px] text-content-muted">
          Automations that add a tab beside Raw and Render, transforming the bytes on screen.
        </p>
      </div>

      {lenses.length === 0 ? (
        <p className="text-[11px] text-content-muted italic py-6 text-center">
          No lenses installed. Add a <code className="font-mono">lens</code> to an automation from the
          Automations tab to give it a viewer tab.
        </p>
      ) : (
        <table className="w-full text-[11px]">
          <thead>
            <tr className="text-content-muted uppercase tracking-wide text-[10px] text-left">
              <th className="pb-1 font-semibold">Automation</th>
              <th className="pb-1 font-semibold">Tab label</th>
              <th className="pb-1 font-semibold">Applies to</th>
              <th className="pb-1 font-semibold">Order</th>
              <th className="pb-1 font-semibold text-right">Shown</th>
            </tr>
          </thead>
          <tbody>
            {lenses.map((s) => (
              <LensRow key={s.id} lens={s} onEdit={onEdit} guard={guard} />
            ))}
          </tbody>
        </table>
      )}

      <p className="text-[10px] text-content-muted leading-relaxed max-w-2xl pt-1">
        A script lens runs with its send capabilities removed, so it can transform what is on screen
        but cannot reach a target. Its output is rendered and discarded — nothing is stored, and the
        run is recorded in Activity like any other.
      </p>
      {/* The asymmetry is real and worth stating here rather than only in the editor: this
          is the panel where an operator decides which lenses are live, and a command lens
          runs every time they open a matching request. */}
      {lenses.some((l) => l.kind === 'command') && (
        <p className="text-[10px] text-semantic-warning leading-relaxed max-w-2xl">
          A command lens is different. There are no capabilities to withhold from a program, so
          Joro cannot stop one reaching the network the way it stops a script — and a lens runs on
          every matching request you open. Keep these to filters that only read what they are
          given.
        </p>
      )}
    </div>
  )
}

/** One row. Edits are local until blur so typing does not fire a request per keystroke. */
function LensRow({
  lens,
  onEdit,
  guard,
}: {
  lens: AutomationSummary
  onEdit: (id: string) => void
  guard: (fn: () => Promise<unknown>, ok?: string) => Promise<void>
}) {
  const [label, setLabel] = useState(lens.lens?.label ?? '')
  const [order, setOrder] = useState(String(lens.lensOrder ?? 0))

  useEffect(() => {
    setLabel(lens.lens?.label ?? '')
    setOrder(String(lens.lensOrder ?? 0))
  }, [lens.lens?.label, lens.lensOrder])

  return (
    <tr className="border-t border-border-subtle align-top">
      <td className="py-1.5 pr-2">
        <button
          onClick={() => onEdit(lens.id)}
          className="text-content-primary hover:text-accent-secondary font-semibold text-left"
        >
          {lens.name}
        </button>
        <div className="text-content-muted font-mono text-[10px]">
          {lens.id} v{lens.version}
        </div>
      </td>
      <td className="py-1.5 pr-2">
        <input
          className={`${inputCls} w-28`}
          value={label}
          maxLength={24}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={() => label !== (lens.lens?.label ?? '') && guard(() => api.setScriptPrefs(lens.id, { lensLabel: label }))}
        />
      </td>
      <td className="py-1.5 pr-2">
        <select
          className={inputCls}
          value={lens.lens?.part ?? 'response'}
          onChange={(e) => guard(() => api.setScriptPrefs(lens.id, { lensPart: e.target.value }))}
        >
          {LENS_PARTS.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </td>
      <td className="py-1.5 pr-2">
        <input
          type="number"
          className={`${inputCls} w-14`}
          value={order}
          onChange={(e) => setOrder(e.target.value)}
          onBlur={() =>
            Number(order) !== (lens.lensOrder ?? 0) &&
            guard(() => api.setScriptPrefs(lens.id, { lensOrder: Number(order) || 0 }))
          }
        />
      </td>
      <td className="py-1.5 text-right">
        <button
          onClick={() =>
            guard(
              () => api.setScriptEnabled(lens.id, !lens.enabled),
              lens.enabled ? `Hid ${lens.lens?.label}` : `Showing ${lens.lens?.label}`
            )
          }
          className={`px-1 ${lens.enabled ? 'text-semantic-success' : 'text-content-muted'} hover:text-accent`}
          title={lens.enabled ? 'Hide this tab' : 'Show this tab'}
        >
          {lens.enabled ? <Eye size={13} strokeWidth={2} /> : <EyeOff size={13} strokeWidth={2} />}
        </button>
      </td>
    </tr>
  )
}
