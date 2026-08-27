import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Bot,
  ChevronDown,
  ChevronRight,
  Eye,
  EyeOff,
  Filter,
  Plus,
  Power,
  PowerOff,
  Terminal,
  Upload,
  Workflow,
} from 'lucide-react'
import { api, type AutomationKind, type AutomationSummary, type Trigger } from '../../lib/api'
import { downloadPackage, pickPackage } from '../../lib/automationPackage'
import { useAutomationStore } from '../../stores/automationStore'
import { useTriggerStore } from '../../stores/triggerStore'
import { useToastStore } from '../../stores/toastStore'
import ConfirmModal from '../ConfirmModal'
import ScriptEditor, { OPERATOR_STARTED, blankManifest, starterSource, type EditorDraft } from './ScriptEditor'
import TriggerEditor from './TriggerEditor'

/**
 * Settings -> Automation -> Scripting: one surface for the three things that used to be
 * three tabs.
 *
 * A rail beside the editor rather than a table you drill into and cannot get back from.
 * What is being authored — an automation, the lens it renders, the trigger that wakes it —
 * are one subject looked at from three angles, and the old shape made moving between them a
 * one-way jump that also discarded whatever the panel was holding.
 *
 * The rail owns selection and nothing else. Each editor keeps its own buffer and reports
 * whether it is dirty, so leaving one mid-edit asks first.
 */

/** What the detail pane is showing. A trigger being created has no id yet, so it travels as
 *  a draft rather than as a lookup key. */
type Selection =
  | { kind: 'automation'; id?: string; draft?: EditorDraft; seq?: number }
  | { kind: 'trigger'; id?: string; draft?: Trigger; seq?: number }
  | null

/** The declared triggers the Dispatcher would watch — what enabling an automation arms. */
function declaredEvents(triggers: string[] | undefined): string[] {
  return (triggers ?? []).filter((t) => !OPERATOR_STARTED.includes(t))
}

export default function ScriptingPanel() {
  const addToast = useToastStore((s) => s.addToast)
  const { scripts, scriptsUnavailable, refreshScripts, scriptKinds, scriptingEnabled } =
    useAutomationStore()
  const {
    triggers: catalog,
    fields,
    events,
    valueLen,
    unavailable: triggersUnavailable,
    refresh: refreshTriggers,
  } = useTriggerStore()

  const [sel, setSel] = useState<Selection>(null)
  const [newOpen, setNewOpen] = useState(false)
  const [showBuiltins, setShowBuiltins] = useState(false)
  // Asked before a selection change throws away an edit. Held as the pending selection, so
  // confirming is just applying it.
  const [leaving, setLeaving] = useState<{ to: Selection } | null>(null)
  // Read through a ref rather than state: the editors report it on every keystroke and the
  // rail only ever asks at the moment of a click, so re-rendering the whole panel for it
  // would cost a render per character typed.
  const dirty = useRef(false)
  // Bumped for every unsaved draft, and used as the editor's key. Two new drafts in a row
  // both have no id, so without this the second reuses the first's component — and
  // ScriptEditor seeds its buffer from the draft prop once, on mount, so the second would
  // be silently ignored.
  const draftSeq = useRef(0)

  useEffect(() => {
    refreshScripts()
    refreshTriggers()
  }, [refreshScripts, refreshTriggers])

  const setDirty = useCallback((d: boolean) => {
    dirty.current = d
  }, [])

  /** Change what the detail pane shows, asking first if the current editor has unsaved work. */
  const select = useCallback((to: Selection) => {
    if (dirty.current) {
      setLeaving({ to })
      return
    }
    dirty.current = false
    setSel(to)
  }, [])

  const guard = useCallback(
    async (fn: () => Promise<unknown>, ok?: string) => {
      try {
        await fn()
        if (ok) addToast(ok, 'info')
        await refreshScripts()
      } catch (e) {
        addToast(String(e instanceof Error ? e.message : e), 'error')
      }
    },
    [addToast, refreshScripts]
  )

  const automations = useMemo(() => scripts.filter((s) => !s.lens), [scripts])
  // Sorted the way the viewer sorts its tabs, so the rail reads as the strip an operator
  // will see rather than as an unordered set.
  const lenses = useMemo(
    () =>
      scripts
        .filter((s) => s.lens)
        .slice()
        .sort((a, b) => (a.lensOrder ?? 0) - (b.lensOrder ?? 0) || (a.lens?.label ?? '').localeCompare(b.lens?.label ?? '')),
    [scripts]
  )
  const custom = useMemo(() => catalog.filter((t) => !t.builtin), [catalog])
  const builtins = useMemo(() => catalog.filter((t) => t.builtin), [catalog])

  const newAutomation = (kind: AutomationKind, lens = false) => {
    const m = blankManifest(kind)
    select({
      kind: 'automation',
      seq: ++draftSeq.current,
      draft: {
        manifest: lens ? { ...m, lens: { label: '', part: 'response' } } : m,
        source: kind === 'command' ? '' : starterSource(lens),
      },
    })
  }

  const newTrigger = async () => {
    const on = events.find((e) => fields[e]) ?? 'request.captured'
    try {
      const seed = await api.seedTrigger(on)
      select({
        kind: 'trigger',
        seq: ++draftSeq.current,
        draft: { id: '', name: '', on, graph: seed.graph, usedBy: [] },
      })
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

      // Opened in the editor rather than installed straight away: importing someone else's
      // automation is exactly when reading it first matters.
      select({
        kind: 'automation',
        seq: ++draftSeq.current,
        draft: { manifest: bundle.manifest, source: bundle.source },
      })
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

  if (scriptsUnavailable && triggersUnavailable) {
    return (
      <div className="flex-1 overflow-auto p-5">
        <h3 className="text-sm font-semibold text-content-primary mb-2">Scripting</h3>
        <p className="text-[11px] text-content-secondary leading-relaxed max-w-xl">
          {scriptsUnavailable}
        </p>
      </div>
    )
  }

  const railRow = (active: boolean) =>
    `w-full text-left px-2 py-1 rounded-sm flex items-center gap-1.5 ${
      active ? 'bg-surface-input text-content-primary' : 'text-content-secondary hover:bg-surface-hover'
    }`

  const sectionHead = (label: string, count: number) => (
    <div className="px-2 pt-3 pb-1 text-[10px] font-semibold uppercase tracking-wide text-content-muted flex items-center gap-1">
      {label}
      <span className="text-content-muted font-normal">{count}</span>
    </div>
  )

  const automationRow = (s: AutomationSummary, lens: boolean) => {
    const active = sel?.kind === 'automation' && sel.id === s.id
    return (
      <div key={s.id} className="flex items-center gap-0.5 pr-1">
        <button onClick={() => select({ kind: 'automation', id: s.id })} className={`${railRow(active)} min-w-0 flex-1`}>
          <span className="truncate text-[11px]">{lens ? s.lens?.label || s.name : s.name}</span>
          {s.kind === 'command' && (
            <Terminal
              size={9}
              strokeWidth={2}
              className="shrink-0 text-semantic-warning"
              aria-label="runs a local command"
            />
          )}
          {s.hasGraph && (
            <Workflow
              size={9}
              strokeWidth={2}
              className="shrink-0 text-accent-secondary"
              aria-label="built on the canvas"
            />
          )}
          {s.author && (
            <Bot size={9} strokeWidth={2} className="shrink-0 text-content-muted" aria-label={`stored by ${s.author}`} />
          )}
          {s.paused && (
            <span className="shrink-0 text-[9px] text-semantic-warning" title={s.pausedReason}>
              paused
            </span>
          )}
        </button>
        <button
          onClick={() =>
            guard(
              () => api.setScriptEnabled(s.id, !s.enabled),
              lens
                ? s.enabled
                  ? `Hid ${s.lens?.label}`
                  : `Showing ${s.lens?.label}`
                : s.enabled
                  ? `Disabled ${s.id}`
                  : `Enabled ${s.id}`
            )
          }
          className={`shrink-0 px-0.5 ${s.enabled ? 'text-semantic-success' : 'text-content-muted'} hover:text-accent`}
          title={
            lens
              ? s.enabled
                ? 'Hide this tab'
                : 'Show this tab'
              : s.enabled
                ? 'Disable'
                : s.paused
                  ? 'Enable (clears the pause)'
                  : `Enable${declaredEvents(s.triggers).length ? ` — arms ${declaredEvents(s.triggers).join(', ')}` : ''}`
          }
        >
          {lens ? (
            s.enabled ? (
              <Eye size={12} strokeWidth={2} />
            ) : (
              <EyeOff size={12} strokeWidth={2} />
            )
          ) : s.enabled ? (
            <Power size={12} strokeWidth={2} />
          ) : (
            <PowerOff size={12} strokeWidth={2} />
          )}
        </button>
      </div>
    )
  }

  const triggerRow = (t: Trigger) => {
    const active = sel?.kind === 'trigger' && sel.id === t.id
    return (
      <button key={t.id} onClick={() => select({ kind: 'trigger', id: t.id })} className={railRow(active)}>
        <span className="truncate text-[11px]">{t.builtin ? t.id : t.name}</span>
        {!t.builtin && (
          <Filter size={9} strokeWidth={2} className="shrink-0 text-accent-tertiary" aria-label={`on ${t.on}`} />
        )}
        {t.problem && (
          <span className="shrink-0 text-[9px] text-semantic-error" title={t.problem}>
            broken
          </span>
        )}
        {t.usedBy.length > 0 && (
          <span className="ml-auto shrink-0 text-[9px] text-content-muted" title={t.usedBy.join(', ')}>
            {t.usedBy.length}
          </span>
        )}
      </button>
    )
  }

  return (
    <div className="flex flex-1 min-h-0">
      <div className="w-56 shrink-0 border-r border-border overflow-y-auto flex flex-col">
        <div className="sticky top-0 bg-surface-card border-b border-border-subtle px-2 py-1.5 flex items-center gap-1 z-10">
          <div className="relative">
            <button
              onClick={() => setNewOpen((o) => !o)}
              className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold"
            >
              <Plus size={11} strokeWidth={2.4} aria-hidden="true" />
              New
              <ChevronDown size={10} strokeWidth={2.4} aria-hidden="true" />
            </button>
            {newOpen && (
              <>
                {/* A backdrop rather than a blur handler: a click on one of the items below
                    must land before the menu closes. */}
                <div className="fixed inset-0 z-20" onClick={() => setNewOpen(false)} />
                <div className="absolute left-0 top-full mt-1 z-30 w-40 bg-surface-card border border-border rounded-sm shadow-sm py-1">
                  {[
                    { label: 'Script', run: () => newAutomation('js'), off: !scriptingEnabled },
                    { label: 'Lens', run: () => newAutomation('js', true), off: !scriptingEnabled },
                    {
                      label: 'Local command',
                      run: () => newAutomation('command'),
                      off: !scriptKinds.includes('command'),
                    },
                    { label: 'Trigger', run: newTrigger, off: !!triggersUnavailable },
                  ].map((it) => (
                    <button
                      key={it.label}
                      disabled={it.off}
                      onClick={() => {
                        setNewOpen(false)
                        it.run()
                      }}
                      className="w-full text-left px-2.5 py-1 text-[11px] text-content-secondary hover:bg-surface-hover hover:text-content-primary disabled:opacity-40 disabled:hover:bg-transparent"
                    >
                      {it.label}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
          <button
            onClick={importFile}
            className="ml-auto inline-flex items-center gap-1 text-[11px] px-1.5 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
            title="Import a .jauto package"
          >
            <Upload size={11} strokeWidth={2} aria-hidden="true" />
          </button>
        </div>

        <div className="p-1 pb-4">
          {sectionHead('Automations', automations.length)}
          {automations.length === 0 ? (
            <p className="px-2 py-1 text-[10px] text-content-muted italic">None installed.</p>
          ) : (
            automations.map((s) => automationRow(s, false))
          )}

          {sectionHead('Lenses', lenses.length)}
          {lenses.length === 0 ? (
            <p className="px-2 py-1 text-[10px] text-content-muted italic">
              An automation that declares a lens renders a viewer tab.
            </p>
          ) : (
            lenses.map((s) => automationRow(s, true))
          )}

          {sectionHead('Triggers', custom.length)}
          {custom.length === 0 ? (
            <p className="px-2 py-1 text-[10px] text-content-muted italic">
              Joro&rsquo;s own events fire every time; a custom trigger adds conditions.
            </p>
          ) : (
            custom.map(triggerRow)
          )}

          <button
            onClick={() => setShowBuiltins((v) => !v)}
            className="w-full text-left px-2 py-1 text-[10px] text-content-muted hover:text-content-secondary flex items-center gap-1"
          >
            {showBuiltins ? (
              <ChevronDown size={10} strokeWidth={2.4} aria-hidden="true" />
            ) : (
              <ChevronRight size={10} strokeWidth={2.4} aria-hidden="true" />
            )}
            Built-in events {builtins.length}
          </button>
          {showBuiltins && builtins.map(triggerRow)}
        </div>
      </div>

      <div className="flex-1 min-h-0 flex flex-col">
        {sel?.kind === 'automation' ? (
          <ScriptEditor
            // Keyed so switching rows rebuilds the buffer instead of leaking the previous
            // automation's source into the next one.
            key={sel.id ?? `new-${sel.seq ?? 0}`}
            id={sel.id}
            draft={sel.draft}
            onClose={() => select(null)}
            onDirtyChange={setDirty}
            onSaved={async (id) => {
              await refreshScripts()
              await refreshTriggers()
              // An install has no id until it lands; adopt it so the rail highlights the row
              // and a second Save updates rather than trying to install again.
              if (id && !sel.id) setSel({ kind: 'automation', id })
            }}
            onDeleted={async () => {
              await refreshScripts()
              setSel(null)
            }}
            onExport={exportOne}
            onEditTrigger={(id) => select({ kind: 'trigger', id })}
          />
        ) : sel?.kind === 'trigger' ? (
          <TriggerEditor
            key={sel.id ?? `new-trigger-${sel.seq ?? 0}`}
            draft={sel.id ? (catalog.find((t) => t.id === sel.id) ?? null) : (sel.draft ?? null)}
            fields={fields}
            events={events}
            valueLen={valueLen}
            onClose={() => select(null)}
            onDirtyChange={setDirty}
            onSaved={async (id) => {
              await refreshTriggers()
              await refreshScripts()
              if (id && !sel.id) setSel({ kind: 'trigger', id })
            }}
            onDeleted={async () => {
              await refreshTriggers()
              setSel(null)
            }}
          />
        ) : (
          <div className="flex-1 overflow-auto p-8">
            <h3 className="text-sm font-semibold text-content-primary mb-2">Scripting</h3>
            <p className="text-[11px] text-content-muted leading-relaxed max-w-xl">
              Pick something from the rail, or start a new one. An automation is code Joro runs on your
              behalf — by hand, on a trigger, or when an agent asks for it by id. A lens is an automation
              that renders a tab in the request viewer instead. A trigger is what wakes one: Joro&rsquo;s
              own events fire every time they happen, and a custom trigger adds conditions so it fires on
              some of them.
            </p>
            <p className="text-[10px] text-content-muted leading-relaxed max-w-xl mt-2">
              Code lives in <code className="font-mono">~/.joro/automations/</code> and never travels
              inside a project config — what an automation stores with{' '}
              <code className="font-mono">joro.storage</code> does, because that describes one engagement.
              An automation is always installed disabled; enabling it is what arms its triggers.
            </p>
          </div>
        )}
      </div>

      {leaving && (
        <ConfirmModal
          title="Discard changes"
          message="This editor has unsaved changes. Leaving now throws them away."
          confirmLabel="Discard"
          onConfirm={() => {
            const to = leaving.to
            setLeaving(null)
            dirty.current = false
            setSel(to)
          }}
          onClose={() => setLeaving(null)}
        />
      )}
    </div>
  )
}
