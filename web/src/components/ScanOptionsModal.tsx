import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { initiateScan } from '../lib/scanMenu'
import { SEVERITY_OPTIONS } from '../lib/severity'
import { useScanOptionsStore } from '../stores/scanOptionsStore'
import MultiSelectDropdown from './MultiSelectDropdown'

interface RuleOpt {
  id: string
  name: string
  enabled: boolean
}

// ScanOptionsModal is the opt-in counterpart to the one-click "Initiate scan"
// context-menu action: it lets the operator pick rules and, for the template
// rule, narrow by severity/tag or bypass fingerprint gating before starting.
export default function ScanOptionsModal() {
  const open = useScanOptionsStore((s) => s.open)
  const target = useScanOptionsStore((s) => s.target)
  const close = useScanOptionsStore((s) => s.close)

  const [rules, setRules] = useState<RuleOpt[]>([])
  const [selectedRules, setSelectedRules] = useState<string[]>([])
  const [severities, setSeverities] = useState<string[]>([])
  const [tags, setTags] = useState('')
  const [ignoreFingerprint, setIgnoreFingerprint] = useState(false)
  const [oast, setOast] = useState(true)
  const [oastAvailable, setOastAvailable] = useState(false)
  const [starting, setStarting] = useState(false)

  useEffect(() => {
    if (!open) return
    // Reset per-open and load the current rule set, defaulting the selection to
    // the enabled rules (what a plain scan would run).
    setSeverities([])
    setTags('')
    setIgnoreFingerprint(false)
    setOast(true)
    api
      .activeScanRules()
      .then((res) => {
        setRules(res.rules)
        setSelectedRules(res.rules.filter((r) => r.enabled).map((r) => r.id))
      })
      .catch(() => {
        setRules([])
        setSelectedRules([])
      })
    // OAST is available only when a callback listener domain is configured.
    api
      .getCallbackConfig()
      .then((c) => setOastAvailable(!!c.domain))
      .catch(() => setOastAvailable(false))
  }, [open])

  if (!open || !target) return null

  const toggleRule = (id: string, on: boolean) =>
    setSelectedRules((prev) => (on ? [...prev, id] : prev.filter((r) => r !== id)))

  const start = async () => {
    setStarting(true)
    const tagList = tags
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean)
    await initiateScan({
      scope: target.scope,
      origin: target.origin,
      url: target.url,
      requestId: target.requestId,
      rules: selectedRules,
      severity: severities,
      tags: tagList,
      ignoreFingerprint,
      // Only meaningful when OAST is available; the server gates it regardless.
      oast: oastAvailable ? oast : undefined,
    })
    setStarting(false)
    close()
  }

  const templateSelected = selectedRules.includes('templatesig')

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50" onClick={close}>
      <div
        className="bg-surface-card border border-border rounded p-4 w-[32rem] space-y-3"
        onClick={(e) => e.stopPropagation()}
      >
        <div>
          <h3 className="text-sm font-semibold text-content-primary">Scan with options</h3>
          <p className="text-[11px] text-content-muted mt-0.5 truncate">{target.label}</p>
        </div>

        {/* Rules */}
        <div className="space-y-1.5">
          <span className="text-xs text-content-muted">Rules</span>
          <div className="flex flex-wrap items-center gap-3">
            {rules.map((r) => (
              <label key={r.id} className="flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={selectedRules.includes(r.id)}
                  onChange={(e) => toggleRule(r.id, e.target.checked)}
                />
                <span className="text-xs text-content-secondary">{r.name}</span>
              </label>
            ))}
            {rules.length === 0 && <span className="text-xs text-content-muted">No rules available</span>}
          </div>
        </div>

        {/* Template-signature options */}
        <div className="border-t border-border-subtle pt-3 space-y-2">
          <span className="text-xs text-content-muted">
            Template signatures{!templateSelected && ' (rule not selected)'}
          </span>
          <div className={`flex flex-wrap items-center gap-3 ${templateSelected ? '' : 'opacity-50 pointer-events-none'}`}>
            <MultiSelectDropdown
              label="Severity"
              options={SEVERITY_OPTIONS}
              selected={severities}
              onChange={setSeverities}
              tooltip="Run only signatures of these severities; empty runs all"
            />
            <label className="flex items-center gap-1.5">
              <span className="text-xs text-content-muted">Tags</span>
              <input
                className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-40"
                placeholder="e.g. wordpress, exposure"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
              />
            </label>
          </div>
          <label className={`flex items-center gap-1.5 cursor-pointer ${templateSelected ? '' : 'opacity-50 pointer-events-none'}`}>
            <input
              type="checkbox"
              className="accent-accent"
              checked={ignoreFingerprint}
              onChange={(e) => setIgnoreFingerprint(e.target.checked)}
            />
            <span className="text-xs text-content-secondary">Ignore fingerprint (run every signature, not just those matching the host's stack)</span>
          </label>
        </div>

        {/* Out-of-band (OAST) testing — only when a callback listener is configured. */}
        <div className="border-t border-border-subtle pt-3">
          <label className={`flex items-center gap-1.5 ${oastAvailable ? 'cursor-pointer' : 'opacity-50'}`}>
            <input
              type="checkbox"
              className="accent-accent"
              checked={oastAvailable && oast}
              disabled={!oastAvailable}
              onChange={(e) => setOast(e.target.checked)}
            />
            <span className="text-xs text-content-secondary">
              Out-of-band (OAST) testing — blind SQLi/RCE via callback
              {!oastAvailable && (
                <span className="text-content-muted"> · requires a configured callback listener</span>
              )}
            </span>
          </label>
        </div>

        <div className="flex justify-end gap-2 pt-1">
          <button
            onClick={close}
            className="px-3 py-1.5 rounded-sm text-xs text-content-secondary hover:text-content-primary hover:bg-surface-input"
          >
            Cancel
          </button>
          <button
            onClick={start}
            disabled={starting || selectedRules.length === 0}
            className="px-3 py-1.5 rounded-sm text-xs bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {starting ? 'Starting…' : 'Start scan'}
          </button>
        </div>
      </div>
    </div>
  )
}
