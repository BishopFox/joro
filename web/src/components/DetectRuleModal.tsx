import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { X } from 'lucide-react'
import { api } from '../lib/api'
import { CATEGORY_OPTIONS } from '../lib/detectFilters'
import { categoryPill, severityBadge, SEVERITY_ORDER, type Severity } from '../lib/severity'
import type { DetectRule } from '../stores/detectStore'
import { useToastStore } from '../stores/toastStore'
import ConfirmModal from './ConfirmModal'
import { Tooltip } from './Tooltip'

// DetectRuleModal is the per-rule configuration surface. It owns the state that
// only exists while a rule is being configured: the editable draft, the regex
// test sample, and its result.
//
// Enabled and Severity are at the top and are editable for built-in rules as
// well as custom ones; everything below is read-only for a built-in.

const emptyRuleDraft: Partial<DetectRule> = {
  name: '',
  description: '',
  category: 'secrets',
  severity: 'medium',
  confidence: 'medium',
  target: 'response_body',
  pattern: '',
  groupBy: 'evidence',
  captureGroup: 0,
  redactEvidence: false,
}

type TestResult = {
  valid: boolean
  error?: string
  matches?: { match: string; redacted: string; offset: number; passes: boolean }[]
}

export default function DetectRuleModal({
  rule,
  creating,
  onClose,
  onChanged,
}: {
  rule: DetectRule | null
  creating?: boolean
  onClose: () => void
  onChanged: () => void | Promise<void>
}) {
  const addToast = useToastStore((s) => s.addToast)

  // A custom rule opens straight into edit mode.
  const [draft, setDraft] = useState<Partial<DetectRule> | null>(() => {
    if (creating) return { ...emptyRuleDraft }
    if (rule && !rule.builtin) return { ...rule }
    return null
  })
  const [dirty, setDirty] = useState(false)
  const [testSample, setTestSample] = useState('')
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [busy, setBusy] = useState(false)

  const patchDraft = useCallback((patch: Partial<DetectRule>) => {
    setDraft((d) => ({ ...(d ?? {}), ...patch }))
    setDirty(true)
  }, [])

  // Backdrop click and Escape are ignored while a draft has unsaved edits; use
  // Cancel.
  const guardedClose = useCallback(() => {
    if (draft && dirty) {
      addToast('Unsaved rule changes — use Cancel to discard', 'info')
      return
    }
    onClose()
  }, [draft, dirty, onClose, addToast])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        guardedClose()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [guardedClose])

  // Client-side regex preview only. JavaScript accepts lookahead and
  // backreferences that Go's RE2 rejects, so the backend stays authoritative.
  const localRegexError = useMemo(() => {
    if (!draft?.pattern) return null
    try {
      new RegExp(draft.pattern, 'g')
      return null
    } catch (err) {
      return (err as Error).message
    }
  }, [draft?.pattern])

  async function run<T>(fn: () => Promise<T>, ok?: string): Promise<T | null> {
    setBusy(true)
    try {
      const out = await fn()
      if (ok) addToast(ok, 'info')
      await onChanged()
      return out
    } catch (err) {
      addToast((err as Error).message, 'error')
      return null
    } finally {
      setBusy(false)
    }
  }

  async function toggleEnabled(enabled: boolean) {
    if (!rule) return
    await run(() => api.setDetectRuleEnabled(rule.id, enabled))
  }

  async function changeSeverity(sev: string) {
    if (!rule) return
    await run(() => api.setDetectRuleSeverity(rule.id, sev))
  }

  async function saveDraft() {
    if (!draft) return
    const saved = await run(
      () =>
        draft.id
          ? api.updateDetectRule(draft.id, draft)
          : api.addDetectRule(draft),
      draft.id ? 'Rule updated' : 'Rule created'
    )
    if (saved) {
      setDirty(false)
      onClose()
    }
  }

  async function deleteRule() {
    if (!rule) return
    setConfirmDelete(false)
    const done = await run(() => api.deleteDetectRule(rule.id), 'Rule deleted')
    if (done !== null) onClose()
  }

  async function resetRule() {
    if (!rule) return
    await run(() => api.resetDetectRule(rule.id), 'Rule reset to defaults')
  }

  async function runTest() {
    if (!draft?.pattern) return
    const res = await api
      .testDetectRule({
        pattern: draft.pattern,
        sample: testSample,
        captureGroup: draft.captureGroup ?? 0,
        minEntropy: draft.minEntropy ?? 0,
        minLength: draft.minLength ?? 0,
      })
      .catch((err: Error) => {
        addToast(err.message, 'error')
        return null
      })
    if (res) setTestResult(res)
  }

  const title = creating ? 'New rule' : (rule?.name ?? 'Rule')

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
      onMouseDown={guardedClose}
    >
      <div
        className="flex flex-col w-full max-w-3xl max-h-[85vh] bg-surface-card border border-border rounded shadow-lg overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border shrink-0">
          <span className="text-xs font-semibold text-content-primary uppercase tracking-wide truncate">
            {title}
          </span>
          {rule && !creating && (
            <>
              {categoryPill(rule.category)}
              <span
                className={`inline-block px-1 py-px rounded-sm bg-surface-input text-[10px] font-semibold uppercase tracking-wide align-middle ${
                  rule.builtin ? 'text-accent-secondary' : 'text-accent-tertiary'
                }`}
              >
                {rule.builtin ? 'Built-in' : 'Custom'}
              </span>
              {severityBadge(rule.severity)}
            </>
          )}
          <button
            onClick={guardedClose}
            className="ml-auto w-6 h-5 flex items-center justify-center rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover"
          >
            <X size={12} />
          </button>
        </div>

        <div className="flex-1 overflow-auto min-h-0 px-4 py-3 space-y-3">
          {/* Opt in/out + severity: the two routine actions, available for
              built-in rules as well as custom ones. */}
          {rule && !creating && (
            <div className="flex flex-wrap items-center gap-4 pb-3 border-b border-border-subtle">
              <label className="flex items-center gap-1.5 text-xs text-content-secondary">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={rule.enabled}
                  disabled={busy}
                  onChange={(e) => void toggleEnabled(e.target.checked)}
                />
                Enabled
              </label>
              <label className="flex items-center gap-1.5 text-xs text-content-secondary">
                <span>Severity</span>
                <Tooltip content="Overrides the shipped default for this rule. Applies to findings from the next scan onward.">
                  <select
                    value={rule.severity}
                    disabled={busy}
                    onChange={(e) => void changeSeverity(e.target.value)}
                    className="bg-surface-input text-xs px-2 py-1 rounded-sm border border-border"
                  >
                    {SEVERITY_ORDER.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </Tooltip>
              </label>
              {rule.findingCount ? (
                <span className="text-[10px] text-content-muted">
                  {rule.findingCount} finding{rule.findingCount === 1 ? '' : 's'} so far
                </span>
              ) : null}
            </div>
          )}

          {draft ? (
            <RuleForm
              draft={draft}
              patch={patchDraft}
              localRegexError={localRegexError}
              testSample={testSample}
              setTestSample={setTestSample}
              testResult={testResult}
              onTest={() => void runTest()}
            />
          ) : rule ? (
            <RuleReference rule={rule} />
          ) : null}
        </div>

        {/* Footer actions */}
        <div className="flex items-center gap-2 px-4 py-3 border-t border-border shrink-0">
          {draft ? (
            <>
              <button
                onClick={() => void saveDraft()}
                disabled={busy}
                className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
              >
                {draft.id ? 'Save changes' : 'Create rule'}
              </button>
              <button
                onClick={onClose}
                className="px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs font-semibold"
              >
                Cancel
              </button>
              {rule && !rule.builtin && (
                <button
                  onClick={() => setConfirmDelete(true)}
                  className="ml-auto px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-semantic-error text-xs font-semibold"
                >
                  Delete rule
                </button>
              )}
            </>
          ) : (
            <>
              {rule?.builtin && (
                <>
                  <Tooltip content="Built-in rules cannot be edited. Cloning makes an editable custom copy.">
                    <button
                      onClick={() => {
                        setDraft({
                          ...rule,
                          id: undefined,
                          builtin: false,
                          name: `${rule.name} (copy)`,
                        })
                        setDirty(true)
                      }}
                      className="px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs font-semibold"
                    >
                      Clone to custom
                    </button>
                  </Tooltip>
                  <button
                    onClick={() => void resetRule()}
                    disabled={busy}
                    className="px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs font-semibold disabled:opacity-50"
                  >
                    Reset to defaults
                  </button>
                </>
              )}
              <button
                onClick={onClose}
                className="ml-auto px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs font-semibold"
              >
                Close
              </button>
            </>
          )}
        </div>
      </div>

      {confirmDelete && rule && (
        <ConfirmModal
          title={`Delete rule "${rule.name}"?`}
          message="The rule is removed. Findings it already produced are kept."
          confirmLabel="Delete rule"
          onConfirm={() => void deleteRule()}
          onClose={() => setConfirmDelete(false)}
        />
      )}
    </div>
  )
}

// field renders one labelled row in the reference view.
function field(label: string, value?: string, mono?: boolean): ReactNode {
  if (!value) return null
  return (
    <div key={label}>
      <div className="text-[10px] text-content-muted uppercase tracking-wide">{label}</div>
      <div className={`text-xs text-content-secondary break-all ${mono ? 'font-mono' : ''}`}>
        {value}
      </div>
    </div>
  )
}

// RuleReference is the read-only view of a built-in rule: what it looks for, and
// every gate that decides when it applies.
function RuleReference({ rule }: { rule: DetectRule }) {
  return (
    <div className="space-y-2">
      {field('Description', rule.description)}
      {field('Remediation', rule.remediation)}
      {field('Rule ID', rule.id, true)}
      {field('Kind', rule.kind)}
      {field('Target', rule.target)}
      {field('Confidence', rule.confidence)}
      {field('Grouping', rule.groupBy ?? 'evidence')}
      {field('Status gate', rule.statusCodes)}
      {field('Scheme gate', rule.scheme)}
      {field('Content types', rule.contentTypes?.join(', '))}
      {field('Post-filters', rule.postFilters?.join(', '))}
      {rule.minEntropy ? field('Min entropy', String(rule.minEntropy)) : null}
      {field('Analyzer', rule.analyzer, true)}
      {rule.pattern && (
        <div>
          <div className="text-[10px] text-content-muted uppercase tracking-wide mb-1">Pattern</div>
          <pre className="bg-surface-input border border-border rounded-sm p-2 text-[11px] font-mono text-content-secondary whitespace-pre-wrap break-all">
            {rule.pattern}
          </pre>
        </div>
      )}
    </div>
  )
}

// RuleForm is the editable form for a custom rule, plus the pattern tester.
function RuleForm({
  draft,
  patch,
  localRegexError,
  testSample,
  setTestSample,
  testResult,
  onTest,
}: {
  draft: Partial<DetectRule>
  patch: (p: Partial<DetectRule>) => void
  localRegexError: string | null
  testSample: string
  setTestSample: (v: string) => void
  testResult: TestResult | null
  onTest: () => void
}) {
  const inputCls = 'bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border flex-1'
  const row = (label: string, node: ReactNode) => (
    <label className="flex items-start gap-1.5">
      <span className="text-xs text-content-muted w-28 pt-1.5 shrink-0">{label}</span>
      {node}
    </label>
  )

  return (
    <div className="space-y-2">
      {row(
        'Name',
        <input
          value={draft.name ?? ''}
          onChange={(e) => patch({ name: e.target.value })}
          className={inputCls}
        />
      )}
      {row(
        'Description',
        <input
          value={draft.description ?? ''}
          onChange={(e) => patch({ description: e.target.value })}
          className={inputCls}
        />
      )}
      {row(
        'Category',
        <select
          value={draft.category ?? 'secrets'}
          onChange={(e) => patch({ category: e.target.value })}
          className={inputCls}
        >
          {CATEGORY_OPTIONS.map((c) => (
            <option key={c.key} value={c.key}>
              {c.label}
            </option>
          ))}
        </select>
      )}
      {row(
        'Severity',
        <select
          value={draft.severity ?? 'medium'}
          onChange={(e) => patch({ severity: e.target.value as Severity })}
          className={inputCls}
        >
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      )}
      {row(
        'Confidence',
        <select
          value={draft.confidence ?? 'medium'}
          onChange={(e) => patch({ confidence: e.target.value as DetectRule['confidence'] })}
          className={inputCls}
        >
          {['high', 'medium', 'low'].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      )}
      {row(
        'Target',
        <select
          value={draft.target ?? 'response_body'}
          onChange={(e) => patch({ target: e.target.value })}
          className={inputCls}
        >
          {['response_body', 'response_header', 'request_body', 'request_header', 'url'].map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      )}
      {row(
        'Grouping',
        <Tooltip content="How repeated matches collapse: one finding per distinct value, per URL, or per host.">
          <select
            value={draft.groupBy ?? 'evidence'}
            onChange={(e) => patch({ groupBy: e.target.value })}
            className={inputCls}
          >
            <option value="evidence">Per distinct value</option>
            <option value="url">Per URL</option>
            <option value="host">Per host</option>
          </select>
        </Tooltip>
      )}
      {row(
        'Capture group',
        <Tooltip content="Which submatch becomes the evidence. 0 uses the whole match.">
          <input
            type="number"
            min={0}
            value={draft.captureGroup ?? 0}
            onChange={(e) => patch({ captureGroup: Number(e.target.value) })}
            className={inputCls}
          />
        </Tooltip>
      )}
      {row(
        'Min entropy',
        <Tooltip content="Rejects matches below this Shannon entropy in bits per character. Useful for generic patterns; leave at 0 for structurally distinctive ones.">
          <input
            type="number"
            step="0.1"
            min={0}
            value={draft.minEntropy ?? 0}
            onChange={(e) => patch({ minEntropy: Number(e.target.value) })}
            className={inputCls}
          />
        </Tooltip>
      )}
      <label className="flex items-center gap-1.5 text-xs text-content-muted">
        <input
          type="checkbox"
          className="accent-accent"
          checked={Boolean(draft.redactEvidence)}
          onChange={(e) => patch({ redactEvidence: e.target.checked })}
        />
        Redact the matched value in stored evidence
      </label>

      <div>
        <div className="text-[10px] text-content-muted uppercase tracking-wide mb-1">Pattern</div>
        <textarea
          value={draft.pattern ?? ''}
          onChange={(e) => patch({ pattern: e.target.value })}
          rows={3}
          spellCheck={false}
          className="w-full bg-surface-input text-xs font-mono px-2 py-1 border border-border rounded-sm"
        />
        {localRegexError && (
          <div className="text-semantic-error text-[10px]">{localRegexError}</div>
        )}
        <div className="text-[10px] text-content-muted mt-0.5">
          Client-side preview only — the backend uses Go RE2, which rejects lookahead,
          lookbehind, and backreferences. Save or Test to validate for real.
        </div>
      </div>

      <div>
        <div className="text-[10px] text-content-muted uppercase tracking-wide mb-1">
          Test sample
        </div>
        <textarea
          value={testSample}
          onChange={(e) => setTestSample(e.target.value)}
          rows={3}
          spellCheck={false}
          placeholder="Paste a response body to test the pattern against"
          className="w-full bg-surface-input text-xs font-mono px-2 py-1 border border-border rounded-sm"
        />
        <button
          onClick={onTest}
          className="text-xs px-2 py-1 mt-1 rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover"
        >
          Test pattern
        </button>
        {testResult && (
          <div className="mt-1 text-[11px]">
            {!testResult.valid ? (
              <span className="text-semantic-error">{testResult.error}</span>
            ) : testResult.matches && testResult.matches.length > 0 ? (
              <div className="space-y-0.5">
                {testResult.matches.map((m, i) => (
                  <div key={i} className="flex items-center gap-2 font-mono">
                    <span className={m.passes ? 'text-semantic-success' : 'text-content-muted'}>
                      {m.passes ? 'match' : 'filtered'}
                    </span>
                    <span className="text-content-secondary truncate">{m.match}</span>
                    <span className="text-content-muted">@{m.offset}</span>
                  </div>
                ))}
              </div>
            ) : (
              <span className="text-content-muted">Pattern is valid, no matches in sample.</span>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
