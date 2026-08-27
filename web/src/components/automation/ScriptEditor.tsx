import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import CodeMirror from '@uiw/react-codemirror'
import { ReactFlowProvider } from '@xyflow/react'
import { EditorView } from '@codemirror/view'
import { javascript } from '@codemirror/lang-javascript'
import { oneDark } from '@codemirror/theme-one-dark'
import {
  api,
  type AutomationKind,
  type AutomationLimits,
  type AutomationManifest,
  type CommandSpec,
  type ScriptRun,
} from '../../lib/api'
import { compile } from '../../lib/flowCompile'
import {
  NODE_SPECS,
  findNode as findFlowNode,
  seedGraph,
  syncTriggerNodes,
  tidy,
  wiringGraph,
  type FlowGraph,
} from '../../lib/flowGraph'
import { useAutomationStore } from '../../stores/automationStore'
import { useSdkStore } from '../../stores/sdkStore'
import { useTriggerStore } from '../../stores/triggerStore'
import { useToastStore } from '../../stores/toastStore'
import ConfirmModal from '../ConfirmModal'
import AutomationHeader, { AutomationOptions, OPERATOR_STARTED } from './AutomationHeader'
import CommandForm from './CommandForm'
import FlowCanvas, { FlowPalette, FlowRail } from './FlowCanvas'
import RunOutput from './RunOutput'
import SdkReference from './SdkReference'

// Re-exported so the surfaces that need the same split — the rail, saying what enabling an
// automation would arm — import it from the editor they already depend on rather than
// keeping a second copy of the list.
export { OPERATOR_STARTED }

const STARTER = `async function run(ctx) {
  // ctx.trigger tells you why this ran; ctx.input carries anything passed in.
  // joro.* is the whole SDK — see the reference below the editor.
  const recent = await joro.history.list({ limit: 10 });
  console.log(recent);
  return { looked: true };
}
`

const LENS_STARTER = `async function run(ctx) {
  // A lens is handed the bytes already on screen, base64 in ctx.input.raw, and returns
  // what the tab should show. It runs with sends disabled.
  const text = atob(ctx.input.raw);
  return { text, language: "json" };
}
`

/** The body a new automation starts from. A lens has a different contract, so it gets a
 *  different starter rather than a comment telling the operator to rewrite this one. */
export function starterSource(lens = false): string {
  return lens ? LENS_STARTER : STARTER
}

export interface EditorDraft {
  manifest: AutomationManifest
  source: string
}

/** A blank spec, so the command form never has to cope with an absent one. */
const BLANK_SPEC: CommandSpec = { path: '', stdin: 'none', inline: '', output: 'text' }

export function blankManifest(kind: AutomationKind = 'js'): AutomationManifest {
  const base = { id: '', name: '', version: '1.0.0', triggers: ['manual'] }
  return kind === 'command'
    ? { ...base, kind, command: { ...BLANK_SPEC } }
    : // A script starts with a canvas, because that is the way an automation is authored
      // here — the code half is what the canvas compiles to. Hand-written stays available
      // through Detach, and an automation installed before this, or by an agent, has no
      // graph and keeps its code; both show the wiring they do have instead.
      { ...base, kind, sdkVersion: '1', graph: seedGraph(['manual']) }
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
  onClose,
  onSaved,
  onDeleted,
  onDirtyChange,
  onExport,
  onEditTrigger,
}: {
  /** Editing an installed automation, or undefined for a new one. */
  id?: string
  /** Seed for a new automation, or one imported from a file. */
  draft?: EditorDraft
  onClose: () => void
  /** Called after a successful write, with the stored id — which an install only has once
   *  it lands, and which the rail adopts so a second Save updates rather than reinstalls. */
  onSaved: (id: string) => void | Promise<void>
  onDeleted?: () => void | Promise<void>
  /** Reported on every edit so the shell can ask before throwing the buffer away. */
  onDirtyChange?: (dirty: boolean) => void
  onExport?: (id: string) => void
  onEditTrigger?: (id: string) => void
}) {
  const addToast = useToastStore((s) => s.addToast)
  // The global run budget, so the boxes below show what a run actually gets today rather
  // than an empty field. Settings -> Automation -> Settings is where it is set.
  const globalBudget = useAutomationStore((st) => st.budget)
  const refreshBudget = useAutomationStore((st) => st.refreshBudget)
  // The kinds this build offers, whether the script half is live, and the command
  // vocabulary — all served, so this form cannot offer something the server would refuse.
  const kinds = useAutomationStore((st) => st.scriptKinds)
  const scriptingEnabled = useAutomationStore((st) => st.scriptingEnabled)
  const commandMeta = useAutomationStore((st) => st.commandMeta)
  const scripts = useAutomationStore((st) => st.scripts)
  // Both built-in events and custom triggers, so the options offer everything an automation
  // can be pointed at rather than only the events Joro ships.
  const catalog = useTriggerStore((st) => st.triggers)
  const refreshTriggers = useTriggerStore((st) => st.refresh)
  // The SDK surface drives the canvas palette and every call node's argument ports, which
  // are generated from each method's JSON Schema rather than listed here.
  const sdkMethods = useSdkStore((st) => st.methods)
  const refreshSdk = useSdkStore((st) => st.refresh)

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
  const [lensOrder, setLensOrder] = useState('0')
  const [confirmDelete, setConfirmDelete] = useState(false)
  // Graph first: it is what the automation does, and the generated code is a view of it. A
  // hand-written automation opens on the same tab, showing the wiring it does have.
  const [view, setView] = useState<'graph' | 'code'>('graph')
  const [confirmDetach, setConfirmDetach] = useState(false)
  // Whether the package as stored has a canvas. Distinguishes the two ways the code and the
  // canvas can disagree, which read very differently: a stored canvas whose file has since
  // changed was edited outside Joro, while an absent one means the operator has started
  // authoring over a hand-written body.
  const [storedHadGraph, setStoredHadGraph] = useState(false)
  // The selected box, held here rather than in the canvas because the rail renders its
  // inspector and the two are no longer the same component.
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
  const canvasWrap = useRef<HTMLDivElement>(null)
  // What the buffer looked like when it was last in step with the server. Compared rather
  // than tracked with a flag so that typing a change and undoing it leaves the editor clean.
  const [pristine, setPristine] = useState(() => JSON.stringify([draft?.manifest ?? blankManifest(), draft?.source ?? STARTER]))
  // Why the command line cannot currently be stored, when it cannot.
  //
  // This gate has to be here rather than left to the server, which is the asymmetry with a
  // script: a broken script can be saved because the server compiles it and refuses, but a
  // command line that does not parse never reaches the server at all — only the last spec
  // that did. Without this, Save would install the previous argument list while the
  // operator reads different text.
  const [commandError, setCommandError] = useState<string | undefined>()

  // The kind is fixed once installed: the server refuses a change, because swapping a
  // script for a command is not editing a body but replacing it with a different sort of
  // thing, and the revision history would read as one artifact when it is two.
  const kind: AutomationKind = manifest.kind ?? 'js'
  const isCommand = kind === 'command'
  const spec = manifest.command ?? BLANK_SPEC
  const summary = id ? scripts.find((s) => s.id === id) : undefined

  const dirty = JSON.stringify([manifest, source]) !== pristine
  useEffect(() => {
    onDirtyChange?.(dirty)
  }, [dirty, onDirtyChange])
  // Leaving the editor cannot leave a stale dirty flag behind on the shell.
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  useEffect(() => {
    if (!id) return
    let cancelled = false
    api
      .getScript(id)
      .then((pkg) => {
        if (cancelled) return
        setManifest(pkg.manifest)
        setSource(pkg.source ?? '')
        setPristine(JSON.stringify([pkg.manifest, pkg.source ?? '']))
        setBaseHash(pkg.sourceHash)
        setAuthor(pkg.state.author ?? '')
        setOverride(pkg.state.limits ?? {})
        setEffective(pkg.effectiveLimits ?? null)
        setLensOrder(String(pkg.state.lensOrder ?? 0))
        setStoredHadGraph(!!pkg.manifest.graph)
      })
      .catch((e) => addToast(String(e instanceof Error ? e.message : e), 'error'))
    return () => {
      cancelled = true
    }
  }, [id, addToast])

  useEffect(() => {
    refreshBudget()
    refreshTriggers()
    refreshSdk()
  }, [refreshBudget, refreshTriggers, refreshSdk])

  const extensions = useMemo(() => [javascript(), EditorView.lineWrapping], [])

  // ---- the canvas ----

  const graph = manifest.graph ?? null

  const compiled = useMemo(
    () => (graph ? compile(graph, sdkMethods) : null),
    [graph, sdkMethods]
  )

  /** What actually gets stored and run. A graph automation's source is generated, so the
   *  buffer is not consulted — there is one answer to what this automation does. */
  const effectiveSource = compiled ? compiled.source : source

  /** The .js on disk is not what this graph produces, which means it was edited outside
   *  Joro — the entrypoint is a real file an operator can open, by design. Answered by
   *  recompiling rather than by a stored hash: compilation is deterministic, so the
   *  comparison is exact and there is no second copy of the fact to go stale. */
  const diverged = !!graph && !!id && !!compiled && source !== '' && source !== compiled.source
  /** The stored .js is not what the stored canvas produces, so it was edited outside Joro —
   *  the entrypoint is a real file an operator can open, by design. */
  const graphStale = diverged && storedHadGraph
  /** The operator has started building over a body that was written by hand. Not a problem,
   *  but saving replaces that code, and they should not learn it from the diff afterwards. */
  const graphTakingOver = diverged && !storedHadGraph

  /** Compile errors keyed by the box that produced them, for the canvas to mark. */
  const nodeErrors = useMemo(() => {
    const out: Record<string, string[]> = {}
    for (const e of compiled?.errors ?? []) {
      if (!e.nodeId) continue
      out[e.nodeId] = [...(out[e.nodeId] ?? []), e.message]
    }
    return out
  }, [compiled])

  const graphErrors = (compiled?.errors ?? []).filter((e) => !e.nodeId)

  /** The box a failed run's stack points at, when the code came from the canvas. */
  const failedNode = useMemo(() => {
    if (!compiled || !graph || !run?.result?.err) return undefined
    for (const m of run.result.err.matchAll(/:(\d+):\d+/g)) {
      const id = compiled.lineMap[Number(m[1])]
      const n = id ? findFlowNode(graph, id) : undefined
      if (n) return n
    }
    return undefined
  }, [compiled, graph, run])

  /** What the canvas marks: what will not compile, plus where the last run actually broke. */
  const canvasErrors = useMemo(() => {
    if (!failedNode || !run?.result?.err) return nodeErrors
    return { ...nodeErrors, [failedNode.id]: [...(nodeErrors[failedNode.id] ?? []), run.result.err.split('\n')[0]] }
  }, [nodeErrors, failedNode, run])

  const triggerInfo = useMemo(
    () => Object.fromEntries(catalog.map((t) => [t.id, { name: t.builtin ? t.id : t.name, on: t.on, problem: t.problem }])),
    [catalog]
  )

  // The manifest is the authority on what wakes an automation, so the canvas follows its
  // trigger list rather than holding a second one.
  const canvasGraph: FlowGraph = useMemo(() => {
    if (graph) return syncTriggerNodes(graph, manifest.triggers ?? [])
    return wiringGraph(manifest.triggers ?? [], kind, manifest.lens)
  }, [graph, manifest.triggers, manifest.lens, kind])

  const onGraphChange = (g: FlowGraph) => patch({ graph: g })

  // Adding and removing a trigger box is adding and removing the manifest's declaration of
  // it. The box follows, because syncTriggerNodes derives the boxes from that list — the
  // canvas never holds a second copy of what wakes this automation.
  const addTrigger = (ref: string) => {
    if ((manifest.triggers ?? []).includes(ref)) return
    patch({ triggers: [...(manifest.triggers ?? []), ref] })
  }
  const removeTrigger = (ref: string) => {
    patch({ triggers: (manifest.triggers ?? []).filter((t) => t !== ref) })
  }

  const patch = (p: Partial<AutomationManifest>) => setManifest((m) => ({ ...m, ...p }))
  const patchLimits = (p: Partial<AutomationLimits>) =>
    setManifest((m) => ({ ...m, limits: { ...m.limits, ...p } }))

  /** What a run gets right now for one field, for use as a placeholder. */
  const globalOf = (k: keyof AutomationLimits) => globalBudget?.effective[k]

  /** The same, from whichever budget governs this kind. Only the wall clock is shared
   *  between the two, so this takes one key rather than being general. */
  const commandOr = (k: 'timeoutMs') => (isCommand ? globalBudget?.command.effective[k] : globalOf(k))

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
    let storedId = id ?? ''
    const ok = await guard(async () => {
      // A command sends no source: the server renders one from the spec, and anything
      // sent here would be ignored rather than merged. A graph automation sends what its
      // canvas compiles to, which is also what replaces a hand edit to the file.
      const body = isCommand ? '' : effectiveSource
      const pkg = id
        ? await api.updateScript(id, manifest, body, baseHash)
        : await api.installScript(manifest, body)
      setBaseHash(pkg.sourceHash)
      // Take the stored manifest back, rather than keeping what was sent. Normalize and
      // Validate rewrite a command's path to the absolute one they resolved, so without
      // this the form keeps saying `grep` while the hash beside it describes
      // `/usr/bin/grep` — and a PATH change between two saves would cut a revision with
      // nothing on screen to explain it. For a command it is also the payoff of resolving
      // once: the operator watches the program become the binary that will run.
      setManifest(pkg.manifest)
      const stored = isCommand ? source : (pkg.source ?? body)
      setSource(stored)
      setPristine(JSON.stringify([pkg.manifest, stored]))
      storedId = pkg.manifest.id
      // Saving from here is the operator writing the code, whoever wrote it before.
      setAuthor('')
    }, id ? 'Saved' : 'Installed (disabled until you enable it)')
    if (ok) await onSaved(storedId)
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
      // A script runs the buffer, not what is on disk: reviewing means running a draft
      // before committing to it. A command runs what is installed, since its body reached
      // the server as a manifest rather than as text.
      setRun(
        await api.runScript(
          isCommand ? { scriptId: id, input: parsed } : { source: effectiveSource, input: parsed }
        )
      )
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

  const commitLensOrder = async (v: string, commit: boolean) => {
    setLensOrder(v)
    if (!commit || !id || Number(v) === (summary?.lensOrder ?? 0)) return
    await guard(async () => {
      await api.setScriptPrefs(id, { lensOrder: Number(v) || 0 })
      await onSaved(id)
    })
  }

  const onKindChange = (next: AutomationKind) => {
    // Rebuild from a blank manifest of the new kind rather than patching the field, so the
    // fields that belong to the other kind are actually gone instead of lingering for the
    // server to reject.
    const blank = blankManifest(next)
    setManifest({
      ...blank,
      id: manifest.id,
      name: manifest.name,
      version: manifest.version,
      description: manifest.description,
    })
    setSource(next === 'command' ? '' : starterSource(!!manifest.lens))
  }

  // A command's body is its program, not its source; the server derives the source from
  // the spec, so requiring one here would refuse every valid command package. What it does
  // need is a command line that parsed — see commandError.
  // A canvas that will not compile does not get to write a file. This is the same gate a
  // command's unparsed command line gets and for the same reason: the server would accept
  // the generated program — a box wired to a value that only exists inside a loop is a
  // reference error at run time, not a parse error — so refusing here is the only place it
  // can be refused before it is stored.
  const canSave =
    manifest.id.trim() !== '' &&
    (compiled?.errors.length ?? 0) === 0 &&
    (isCommand ? spec.path.trim() !== '' && !commandError : effectiveSource.trim() !== '')

  // A command can only be run once installed. The run endpoint accepts inline *source* and
  // nothing else, deliberately — an unsaved argv has nowhere to be recorded from — so the
  // draft-then-run loop a script gets does not apply and the button says why.
  const canRun = isCommand ? !!id : effectiveSource.trim() !== ''

  return (
    // One provider around the whole editor. The palette sits in the header and needs the
    // viewport to place a box in the middle of what is on screen, so the provider has to
    // enclose the header too — not just the canvas.
    <ReactFlowProvider>
      <div className="flex flex-col flex-1 min-h-0">
        <AutomationHeader
          id={id}
          manifest={manifest}
          baseHash={baseHash}
          author={author}
          busy={busy}
          canSave={canSave}
          canRun={canRun}
          dirty={dirty}
          enabled={summary?.enabled}
          paused={summary?.paused}
          pausedReason={summary?.pausedReason}
          onRun={runNow}
          onSave={save}
          onToggleEnabled={
            id
              ? () =>
                  guard(async () => {
                    await api.setScriptEnabled(id, !summary?.enabled)
                    await onSaved(id)
                  })
              : undefined
          }
          onExport={onExport && id ? () => onExport(id) : undefined}
          view={view}
          onView={setView}
          hasGraph={!!graph}
          graphStale={graphStale}
          // The messages, not a count: "1 problem" with no way to see what it is stops the
          // operator exactly where they need to act.
          problems={(compiled?.errors ?? []).map((e) => (e.nodeId ? `${e.nodeId}: ${e.message}` : e.message))}
          onDelete={onDeleted ? () => setConfirmDelete(true) : undefined}
          onClose={onClose}
          // Adding a box is a canvas action, so its buttons sit over the canvas rather than
          // down the rail, where they pushed this automation's own settings below the fold.
          toolbar={
            view === 'graph' ? (
              <FlowPalette
                graph={canvasGraph}
                methods={sdkMethods}
                onChange={onGraphChange}
                onSelect={setSelectedNode}
                derived={!graph}
                // A lens is started by the viewer, so Normalize drops any dispatched trigger
                // declared beside one. Offering those here would mean adding a box that
                // vanishes on save.
                triggers={manifest.lens ? catalog.filter((t) => OPERATOR_STARTED.includes(t.id)) : catalog}
                declared={manifest.triggers ?? []}
                onAddTrigger={addTrigger}
                // Only a script has a body a canvas can author. A command's is its program, so
                // its diagram stays a diagram.
                onPromote={
                  isCommand
                    ? undefined
                    : (apply) => patch({ graph: apply(tidy(seedGraph(manifest.triggers ?? []), sdkMethods)) })
                }
                wrapRef={canvasWrap}
              />
            ) : undefined
          }
        />

        {/* The two ways the file and the canvas disagree. Both offer the same way out, and both
            stay up until it is taken — a banner over the thing it is about, rather than a modal
            fired once at the moment the operator was busy doing something else. */}
        {/* The two ways the file and the canvas disagree. A statement, not a control: Detach
            lives in the rail with the rest of what can be done to this automation, and a
            second copy of it here would be a button in a banner that is trying to be read. */}
        {(graphStale || graphTakingOver) && (
          <div className="shrink-0 border-b border-semantic-warning px-3 py-2">
            <p className="text-[10px] text-semantic-warning leading-snug">
              {graphStale ? (
                <>
                  The stored code is not what this canvas produces, so{' '}
                  <code className="font-mono">{manifest.entrypoint ?? 'index.js'}</code> was edited
                  outside Joro. The file is what runs — the canvas is only showing something else.
                  Saving replaces the file with what the canvas produces; Detach, in the rail, keeps
                  the file and drops the canvas.
                </>
              ) : (
                <>
                  This automation&rsquo;s body was written by hand. Saving replaces{' '}
                  <code className="font-mono">{manifest.entrypoint ?? 'index.js'}</code> with what this
                  canvas produces. Nothing is written until you save; Detach, in the rail, keeps the
                  code and drops the canvas.
                </>
              )}
            </p>
          </div>
        )}

        {graphErrors.length > 0 && view === 'graph' && (
          <div className="shrink-0 border-b border-border px-3 py-1.5 space-y-0.5">
            {graphErrors.map((e, i) => (
              <p key={i} className="text-[10px] text-semantic-error leading-snug">
                {e.message}
              </p>
            ))}
          </div>
        )}

        {/* One provider around body and rail together. The rail's Add needs the viewport to
            place a box in the middle of what is on screen, and useReactFlow reads it from the
            provider's store rather than from the <ReactFlow> element itself. */}
          <div className="flex flex-1 min-h-0">
            {/* The body pane: the canvas, the code it produces, or a spec form for a command.
                All three fill the same space, because each is the part of the package that
                decides what happens. */}
            {view === 'graph' ? (
              <div className="flex-1 min-h-0 flex p-2">
                <FlowCanvas
                  graph={canvasGraph}
                  methods={sdkMethods}
                  onChange={onGraphChange}
                  errors={canvasErrors}
                  triggerInfo={triggerInfo}
                  derived={!graph}
                  selected={selectedNode}
                  onSelect={setSelectedNode}
                  onEditTrigger={onEditTrigger}
                  onOpenBody={() => setView('code')}
                  onRemoveTrigger={removeTrigger}
                  wrapRef={canvasWrap}
                />
              </div>
            ) : isCommand ? (
              <div className="flex-1 min-h-0">
                <CommandForm
                  spec={spec}
                  meta={commandMeta}
                  triggers={manifest.triggers ?? []}
                  isLens={!!manifest.lens}
                  onChange={(c, invalid) => {
                    setCommandError(invalid)
                    patch({ command: c })
                  }}
                />
              </div>
            ) : (
              /* Editor. The height chain is load-bearing: flex-1 relative min-h-0, then an
                 absolutely positioned child, because .cm-editor is height:100% !important. */
              <div className="flex-1 relative min-h-0">
                <div className="absolute inset-0 overflow-hidden">
                  <CodeMirror
                    value={effectiveSource}
                    theme={oneDark}
                    height="100%"
                    // Read-only while a canvas owns the body: two ways to write one program
                    // would leave the operator guessing which one Save used.
                    editable={!graph}
                    onChange={setSource}
                    extensions={extensions}
                    basicSetup={{ lineNumbers: true, foldGutter: true }}
                  />
                </div>
              </div>
            )}

            {/* The one rail. The automation's settings are always in it, whichever view is
                open, because they are read against the thing they describe. Below them sits
                whatever the current view adds: the palette and the selected box, or the SDK. */}
            <div className="w-72 shrink-0 border-l border-border overflow-y-auto p-3 space-y-3">
              <AutomationOptions
                id={id}
                manifest={manifest}
                patch={patch}
                patchLimits={patchLimits}
                kind={kind}
                isCommand={isCommand}
                kinds={kinds}
                scriptingEnabled={scriptingEnabled}
                commandMeta={commandMeta}
                onKindChange={onKindChange}
                override={override}
                setOverride={setOverride}
                effective={effective}
                saveOverride={saveOverride}
                lensOrder={lensOrder}
                onLensOrder={commitLensOrder}
                busy={busy}
                globalOf={globalOf}
                commandOr={commandOr}
                input={input}
                setInput={setInput}
              />

              <div className="border-t border-border pt-3">
                {view === 'graph' ? (
                  <FlowRail
                    graph={canvasGraph}
                    methods={sdkMethods}
                    onChange={onGraphChange}
                    selected={selectedNode}
                    onSelect={setSelectedNode}
                    errors={canvasErrors}
                    derived={!graph}
                    onRemoveTrigger={removeTrigger}
                    onEditTrigger={onEditTrigger}
                    onOpenBody={() => setView('code')}
                  />
                ) : (
                  <div className="space-y-2">
                    {!isCommand && graph && (
                      <p className="text-[10px] text-content-muted leading-snug">
                        Generated from the canvas, and read-only here. Detach, below, hands it over to
                        edit by hand.
                      </p>
                    )}
                    {!isCommand && !graph && (
                      /* No Build button here. Authoring on the canvas belongs to the Graph
                         tab, and having its entry point live in the code half is what made it
                         read as a separate feature rather than as the default way to write
                         one. */
                      <p className="text-[10px] text-content-muted leading-snug">
                        Hand-written. The Graph tab shows what wakes this and what it produces, and
                        adding a box there takes over the body.
                      </p>
                    )}
                    {/* JavaScript only: a command calls no SDK, so the reference would document
                        a surface it cannot reach. What it can reach is the placeholder list,
                        which CommandForm shows beside the arguments that use it. */}
                    {!isCommand && <SdkReference />}
                  </div>
                )}
              </div>

              {/* Detach belongs to the automation rather than to one view of it: the banner
                  that names it can be over the canvas, so it has to be reachable from there
                  too, not only from the code half. */}
              {!isCommand && graph && (
                <div className="border-t border-border pt-3">
                  <button
                    onClick={() => setConfirmDetach(true)}
                    className="w-full text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
                    title="Drop the canvas and keep the code it produced, to edit by hand"
                  >
                    Detach canvas
                  </button>
                </div>
              )}
            </div>
          </div>

        {/* A failed run names a line of generated code, which means nothing to someone
            looking at boxes. The compiler kept a line-to-box map, and jsruntime.Prepare
            documents that its erasures preserve line numbers, so the two line up exactly. */}
        {run && failedNode && (
          <div className="shrink-0 border-t border-semantic-error px-3 py-1.5">
            <p className="text-[10px] text-semantic-error leading-snug">
              This failed in the <strong>{NODE_SPECS[failedNode.type].label}</strong> box{' '}
              <code className="font-mono">{failedNode.id}</code>
              {view === 'code' ? '.' : ' — it is marked on the canvas.'}
            </p>
          </div>
        )}

        {run && <RunOutput run={run} onClose={() => setRun(null)} />}

        {confirmDetach && (
          <ConfirmModal
            title="Detach the canvas"
            message="The code stays exactly as it is and becomes yours to edit by hand. The canvas is dropped, and rebuilding one starts from scratch."
            confirmLabel="Detach"
            onConfirm={() => {
              setConfirmDetach(false)
              // The generated program is kept as the buffer, so detaching hands over what was
              // on screen rather than reverting to whatever the file said before.
              if (compiled && !graphStale) setSource(compiled.source)
              patch({ graph: undefined })
              setView('code')
            }}
            onClose={() => setConfirmDetach(false)}
          />
        )}

        {confirmDelete && id && (
          <ConfirmModal
            title="Uninstall automation"
            message={`Remove ${id}? Its code and everything it has stored are deleted.`}
            confirmLabel="Uninstall"
            onConfirm={async () => {
              setConfirmDelete(false)
              const ok = await guard(() => api.deleteScript(id), `Uninstalled ${id}`)
              if (ok) await onDeleted?.()
            }}
            onClose={() => setConfirmDelete(false)}
          />
        )}
      </div>
    </ReactFlowProvider>
  )
}
