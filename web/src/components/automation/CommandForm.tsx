import { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight, Plus, Trash2, Wand2 } from 'lucide-react'
import type { CommandMeta, CommandSpec } from '../../lib/api'
import {
  formatCommandLine,
  isParseError,
  namesInput,
  parseCommandLine,
  placeholdersUsed,
  roundTrips,
  INPUT_TOKEN,
} from '../../lib/cmdline'
import { useRedact } from '../../stores/streamerStore'

const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border w-full'

/** Prose for each input source. The values come from the server; only the wording is here,
 *  because a bare `both` in a select tells the operator nothing. A mode the server adds
 *  without an entry falls back to its own name rather than disappearing. */
const SOURCE_LABELS: Record<string, { label: string; hint: string }> = {
  none: { label: 'Nothing', hint: 'The program runs with no input.' },
  request: { label: 'Request bytes', hint: 'The raw request, headers and body.' },
  response: { label: 'Response bytes', hint: 'The raw response, headers and body.' },
  both: { label: 'Request + response', hint: 'Both, separated by a blank line.' },
  trigger: {
    label: 'Trigger event (JSON)',
    hint: 'The event payload. The only input a finding or a finished campaign has — neither carries a transaction.',
  },
}

/** What the parts of a materialized input file are called, same idea as SOURCE_LABELS. */
const PART_LABELS: Record<string, string> = {
  request: 'Request bytes',
  response: 'Response bytes',
  both: 'Request + response',
  trigger: 'Trigger event (JSON)',
}

/**
 * The body of a command automation: what to run, and what to feed it.
 *
 * This occupies the pane a script's code editor occupies, because it is the same thing —
 * the part of the package that decides what happens. The sidebar beside it holds the
 * metadata for both kinds.
 *
 * # One box, and why that is safe
 *
 * The command is typed as a line and split by `lib/cmdline.ts` before it is stored, so what
 * reaches the server is still `path` + `args[]`. The tokenizer's own header carries the
 * argument for why author-time splitting keeps localcmd's invariant intact; the thing to
 * know here is that this component must never seed the box from anything captured.
 *
 * The row editor is kept and is not a legacy path. It is the surface for a spec that has no
 * one-line form — an argument holding a newline is a legal spec — and forcing it on rather
 * than rendering a lossy line is what makes the box trustworthy for everything else.
 *
 * # Nothing here restates a server rule
 *
 * Every closed choice, and now every placeholder description, comes from `meta`. The
 * paragraph this form used to carry about which placeholders an attacker controls was a
 * prose copy of `checkCaptured`, and it would have been wrong the day a placeholder was
 * added.
 */
export default function CommandForm({
  spec,
  meta,
  triggers,
  isLens,
  onChange,
}: {
  spec: CommandSpec
  meta: CommandMeta | null
  /** The triggers the manifest declares, for the availability warning. */
  triggers: string[]
  /** Whether the manifest declares a lens, which is started by the viewer rather than a
   *  trigger and therefore always has a transaction. */
  isLens: boolean
  /** `invalid` is the parse error, when there is one. The editor gates Save on it: the bad
   *  text never reaches the server, so nothing downstream can refuse it. */
  onChange: (next: CommandSpec, invalid?: string) => void
}) {
  const patch = (p: Partial<CommandSpec>) => onChange({ ...spec, ...p })
  const args = useMemo(() => spec.args ?? [], [spec.args])

  // Where the spec currently says the input comes from. One select drives both fields: the
  // select says which bytes, and where {{INPUT}} appears says which field carries them.
  const declared = spec.inline || (spec.stdin && spec.stdin !== 'none' ? spec.stdin : 'none')

  // The select's own answer, held apart from the spec, because the spec cannot hold it
  // while the command line names no input: deleting {{INPUT}} would otherwise snap the
  // select back to Nothing under the operator's cursor and take the "you chose an input the
  // command never reads" warning with it — the warning exists for exactly that moment.
  const [picked, setPicked] = useState(declared)
  useEffect(() => {
    if (declared !== 'none') setPicked(declared)
  }, [declared])
  const source = declared !== 'none' ? declared : picked

  const stdinPipe = !!spec.stdin && spec.stdin !== 'none'
  const rendered = formatCommandLine(spec.path, args, stdinPipe)

  // A spec with no one-line form has to be edited as rows, and so does one whose stdin and
  // inline name different sources — one select cannot show two answers. Both are reachable
  // only by a hand edit or an imported package, and both are shown rather than mangled.
  const twoSources = !!spec.inline && stdinPipe && spec.inline !== spec.stdin
  const mustUseRows = rendered === null || twoSources

  const [rows, setRows] = useState(false)
  const showRows = rows || mustUseRows

  return (
    <div className="h-full overflow-y-auto p-4 space-y-4">
      <Section
        label="Input source"
        hint={SOURCE_LABELS[source]?.hint ?? 'What the command is given to work with.'}
      >
        <select
          className={inputCls}
          value={source}
          onChange={(e) => {
            const next = e.target.value
            setPicked(next)
            // Choosing Nothing while an argument still reads {{INPUT}} makes a spec the
            // server refuses at install. Reported here instead, because the operator is
            // looking at both halves of the contradiction right now.
            const orphaned = next === 'none' && args.some(namesInput)
            onChange(
              { ...spec, ...withSource(args, next) },
              orphaned
                ? `an argument still reads ${INPUT_TOKEN}, so the input source cannot be Nothing`
                : undefined,
            )
          }}
        >
          {(meta?.stdinModes ?? ['none']).map((m) => (
            <option key={m} value={m}>
              {SOURCE_LABELS[m]?.label ?? m}
            </option>
          ))}
        </select>
      </Section>

      {showRows ? (
        <RowsEditor
          spec={spec}
          args={args}
          mustUseRows={mustUseRows}
          twoSources={twoSources}
          onBackToText={() => setRows(false)}
          onChange={onChange}
        />
      ) : (
        <CommandBox
          spec={spec}
          args={args}
          source={source}
          rendered={rendered ?? ''}
          meta={meta}
          triggers={triggers}
          isLens={isLens}
          onUseRows={() => setRows(true)}
          onPickSource={setPicked}
          onChange={onChange}
        />
      )}

      <Advanced spec={spec} meta={meta} patch={patch} />
    </div>
  )
}

/**
 * Recompute the two source fields when the select changes.
 *
 * `stdin` and `inline` are derived rather than edited: which one holds the source is
 * decided by where `{{INPUT}}` appears in the arguments, so a change here only has to
 * re-apply that rule.
 */
function withSource(args: string[], next: string): Partial<CommandSpec> {
  if (next === 'none') return { stdin: 'none', inline: '' }

  const inline = args.some(namesInput)
  return {
    // Piping stays on unless an argument is reading the input instead, so switching source
    // never silently changes the delivery the operator already chose.
    stdin: inline ? 'none' : next,
    inline: inline ? next : '',
  }
}

/** The command line, its preview, and everything that explains it. */
function CommandBox({
  spec,
  args,
  source,
  rendered,
  meta,
  triggers,
  isLens,
  onUseRows,
  onPickSource,
  onChange,
}: {
  spec: CommandSpec
  args: string[]
  source: string
  rendered: string
  meta: CommandMeta | null
  triggers: string[]
  isLens: boolean
  onUseRows: () => void
  onPickSource: (s: string) => void
  onChange: (next: CommandSpec, invalid?: string) => void
}) {
  // The box holds its own text, for the reason PairRows below documents at length: a spec
  // arrives asynchronously and a half-typed line is a state no spec can represent. Re-render
  // from the spec only when it changes underneath us, comparing against what was last
  // pushed up so this does not become a loop.
  const [text, setText] = useState(rendered)
  const pushed = useRef(rendered)

  useEffect(() => {
    if (rendered === pushed.current) return
    pushed.current = rendered
    setText(rendered)
  }, [rendered])

  // An empty box is not an error to report: a new command opens on one, and "name a
  // program to run" in red before the operator has typed anything reads as a fault. Save
  // is already blocked by the empty path.
  const blank = text.trim() === ''
  const parsed = useMemo(() => parseCommandLine(text), [text])
  const error = !blank && isParseError(parsed) ? parsed : null
  const fix = error?.fix

  // Checked on every keystroke because web/ has no test runner: if the parser and the
  // formatter disagree about this particular text, saving would store an argument list the
  // operator is not reading. See roundTrips.
  const lossy = !blank && !error && !roundTrips(text)

  const write = (next: string) => {
    setText(next)
    const p = parseCommandLine(next)

    if (next.trim() === '') {
      // Clearing the box empties the command rather than holding the last one, so what is
      // on screen and what would be saved agree. The empty path is what blocks Save.
      pushed.current = ''
      onChange({ ...spec, path: '', args: [] })
      return
    }
    if (isParseError(p)) {
      // Keep the last good spec but report the text as invalid, so Save is disabled rather
      // than installing an argument list that no longer matches what is on screen.
      onChange(spec, p.error)
      return
    }
    if (!roundTrips(next)) {
      onChange(spec, 'this line cannot be stored as an argument list without changing it')
      return
    }

    const inline = p.args.some(namesInput)
    // Naming the input before choosing a source is the normal order to type in, so the
    // first mention picks one rather than erroring. Request bytes, because a command
    // automation is overwhelmingly about a request the operator selected.
    const src = source === 'none' && (p.stdinPipe || inline) ? 'request' : source
    if (src !== source) onPickSource(src)

    const nextSpec: CommandSpec = {
      ...spec,
      path: p.path,
      args: p.args,
      stdin: p.stdinPipe && src !== 'none' ? src : 'none',
      inline: inline && src !== 'none' ? src : '',
    }
    pushed.current = formatCommandLine(nextSpec.path, p.args, p.stdinPipe) ?? next
    onChange(nextSpec)
  }

  const usesInline = args.some(namesInput)
  const readsInput = usesInline || (!!spec.stdin && spec.stdin !== 'none')

  return (
    <>
      <Section
        label="Command"
        hint="Split into a program and a list of arguments when you save. There is no shell — quotes group words, and every other character is literal."
        action={
          <button
            onClick={onUseRows}
            className="text-[10px] text-content-muted hover:text-content-primary"
          >
            Edit as rows
          </button>
        }
      >
        <textarea
          className={`${inputCls} font-mono h-16 resize-y`}
          value={text}
          spellCheck={false}
          placeholder={`${INPUT_TOKEN} | grep -ai password`}
          onChange={(e) => write(e.target.value)}
        />

        {error && (
          <div className="mt-1">
            <p className="text-[10px] text-semantic-error leading-snug">{error.error}</p>
            {fix && (
              <button
                onClick={() => write(fix)}
                className="mt-1 inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
              >
                <Wand2 size={11} strokeWidth={2} aria-hidden="true" />
                Rewrite as <code className="font-mono">{fix}</code>
              </button>
            )}
          </div>
        )}

        {lossy && !error && (
          <p className="text-[10px] text-semantic-error mt-1 leading-snug">
            This line does not survive being stored and read back, so it cannot be saved from
            here. Edit it as rows instead, where what you see is the argument list itself.
          </p>
        )}

        {!error &&
          parsed &&
          !isParseError(parsed) &&
          parsed.warnings.map((w) => (
            <p key={w} className="text-[10px] text-semantic-warning mt-1 leading-snug">
              {w}
            </p>
          ))}

        {usesInline && source === 'none' && (
          <p className="text-[10px] text-semantic-error mt-1 leading-snug">
            An argument reads <code className="font-mono">{INPUT_TOKEN}</code>, so the input source
            cannot be Nothing. Choose one above, or take the placeholder out of the command.
          </p>
        )}

        {source !== 'none' && !readsInput && (
          <p className="text-[10px] text-semantic-warning mt-1 leading-snug">
            You chose an input source but the command never reads it. Put{' '}
            <code className="font-mono">{INPUT_TOKEN} |</code> at the head of the line to pipe it
            in, or write <code className="font-mono">{INPUT_TOKEN}</code> inside an argument.
          </p>
        )}
      </Section>

      <Section label="Will run">
        <WillRun spec={spec} args={args} source={source} />
      </Section>

      {usesInline && (
        <p className="text-[10px] text-semantic-warning leading-snug -mt-2">
          These bytes become part of the program's command line, which other processes on this
          machine can read. Piping them instead — <code className="font-mono">{INPUT_TOKEN} |</code>{' '}
          at the head — keeps them off it and has no size limit. Turn on credential masking under
          Advanced for anything that sends them on.
        </p>
      )}

      <Placeholders
        meta={meta}
        triggers={triggers}
        isLens={isLens}
        used={placeholdersUsed(args)}
        files={spec.files ?? {}}
        hasSource={source !== 'none'}
      />
    </>
  )
}

/**
 * What the run will actually do, one fact per line.
 *
 * Numbered arguments rather than a joined line, and that is the point: once the input is
 * also a joined line, a joined preview agrees in exactly the cases that do not matter and
 * diverges in the ones that do. It is also the only review surface there is, because a
 * command cannot be test-run until it has been installed.
 */
function WillRun({ spec, args, source }: { spec: CommandSpec; args: string[]; source: string }) {
  const redact = useRedact()
  const sourceLabel = SOURCE_LABELS[source]?.label.toLowerCase() ?? source
  // An absolute program path carries the OS username. The arguments are the
  // operator's own authored text and stay readable — they are what the row means.
  const lines: [string, string][] = [['program', spec.path ? redact(spec.path, 'path') : '(none yet)']]

  args.forEach((a, i) => {
    lines.push([
      `argv[${i + 1}]`,
      namesInput(a) ? a.split(INPUT_TOKEN).join(`‹${sourceLabel}›`) : a,
    ])
  })

  if (spec.stdin && spec.stdin !== 'none') lines.push(['stdin', sourceLabel])
  for (const [key, part] of Object.entries(spec.files ?? {})) {
    lines.push([`file`, `{{${key}}} = ${(PART_LABELS[part] ?? part).toLowerCase()}`])
  }
  for (const [name, v] of Object.entries(spec.env ?? {})) lines.push(['env', `${name}=${redact(v, 'secret')}`])
  for (const name of spec.envPass ?? []) lines.push(['env', `${name} (inherited)`])
  if (spec.useProxy) lines.push(['proxy', "through Joro's proxy"])
  if (spec.redact) lines.push(['redact', 'credential headers masked'])

  return (
    <pre className="font-mono text-[11px] bg-surface-input rounded p-2 whitespace-pre-wrap break-all">
      {lines.map(([k, v]) => (
        <div key={`${k}:${v}`}>
          <span className="text-content-muted">{k.padEnd(9, ' ')}</span>
          {v === '' ? <span className="text-content-muted">(empty)</span> : v}
        </div>
      ))}
    </pre>
  )
}

/**
 * The placeholder reference: one row each, with what it is and where it comes from.
 *
 * Rendered from what the server serves, both halves — localcmd describes the grammar it
 * enforces and jsautomation says which trigger supplies what. The availability column is
 * what makes the warning below possible: a placeholder the chosen triggers do not supply
 * fails the run, and until now that only showed up as a failed run.
 */
function Placeholders({
  meta,
  triggers,
  isLens,
  used,
  files,
  hasSource,
}: {
  meta: CommandMeta | null
  triggers: string[]
  isLens: boolean
  used: string[]
  files: Record<string, string>
  hasSource: boolean
}) {
  const [open, setOpen] = useState(false)
  if (!meta || meta.placeholders.length === 0) return null

  // A lens is started by the viewer and always has a transaction, so it is the trigger that
  // applies whenever one is declared.
  const active = isLens ? ['lens'] : triggers
  const fileKeys = Object.keys(files)

  const availableOn = (name: string) => {
    const on = Object.entries(meta.availability)
      .filter(([, names]) => names.includes(name))
      .map(([t]) => t)
    return on
  }

  // A name every active trigger supplies is fine. One that some do not is a run that fails
  // under those, which is worth saying while the form is open.
  const missing = used.filter((name) => {
    if (fileKeys.includes(name)) return false
    const on = availableOn(name)
    if (on.length === 0) return false // always available, e.g. SCRATCH
    return active.some((t) => !on.includes(t))
  })

  return (
    <Section label="Placeholders">
      <table className="w-full text-[11px]">
        <thead>
          <tr className="text-content-muted uppercase tracking-wide text-[10px] text-left">
            <th className="py-1 pr-2 font-semibold">Token</th>
            <th className="py-1 pr-2 font-semibold">What it is</th>
            <th className="py-1 font-semibold">Available on</th>
          </tr>
        </thead>
        <tbody>
          {meta.placeholders.map((p) => {
            const on = availableOn(p.name)
            const unusable = p.source === 'input' && !hasSource
            return (
              <tr key={p.name} className="border-t border-border-subtle align-top">
                <td className="py-1.5 pr-2 whitespace-nowrap">
                  <code
                    className={`font-mono ${used.includes(p.name) ? 'text-accent-secondary' : ''}`}
                  >
                    {p.token}
                  </code>
                </td>
                <td className="py-1.5 pr-2 text-content-secondary leading-snug">
                  {p.description}
                  {open && (
                    <span className="block text-[10px] text-content-muted">
                      Must be {p.grammar}.
                    </span>
                  )}
                </td>
                <td className="py-1.5 text-[10px] text-content-muted leading-snug">
                  {unusable
                    ? 'choose an input source first'
                    : on.length === 0
                      ? 'always'
                      : on.map((t) => <code key={t} className="font-mono block">{t}</code>)}
                </td>
              </tr>
            )
          })}
          {fileKeys.map((k) => (
            <tr key={k} className="border-t border-border-subtle align-top">
              <td className="py-1.5 pr-2 whitespace-nowrap">
                <code className="font-mono">{`{{${k}}}`}</code>
              </td>
              <td className="py-1.5 pr-2 text-content-secondary leading-snug">
                Path of the input file you declared under Advanced.
              </td>
              <td className="py-1.5 text-[10px] text-content-muted">always</td>
            </tr>
          ))}
        </tbody>
      </table>

      {missing.length > 0 && (
        <p className="text-[10px] text-semantic-warning mt-1.5 leading-snug">
          {missing.map((m) => `{{${m}}}`).join(', ')}{' '}
          {missing.length === 1 ? 'is' : 'are'} not supplied by every trigger you selected, and a
          run that has no value for a placeholder is refused rather than run without it.
        </p>
      )}

      <p className="text-[10px] text-content-muted mt-1.5 leading-snug">
        Substitution happens after the line is split, so a value containing a space stays one
        argument. A value that would start an argument with a dash is refused, because there it
        would be read as an option.{' '}
        <button onClick={() => setOpen((o) => !o)} className="hover:text-content-primary underline">
          {open ? 'Hide' : 'Show'} what each one has to look like
        </button>
      </p>
    </Section>
  )
}

/** The per-argument editor, and the only correct surface for a spec with no one-line form. */
function RowsEditor({
  spec,
  args,
  mustUseRows,
  twoSources,
  onBackToText,
  onChange,
}: {
  spec: CommandSpec
  args: string[]
  mustUseRows: boolean
  twoSources: boolean
  onBackToText: () => void
  onChange: (next: CommandSpec, invalid?: string) => void
}) {
  const patch = (p: Partial<CommandSpec>) => onChange({ ...spec, ...p })

  return (
    <>
      <Section
        label="Program"
        hint="Resolved through PATH when you save, and stored as an absolute path — so the binary you review is the one that runs."
        action={
          mustUseRows ? undefined : (
            <button
              onClick={onBackToText}
              className="text-[10px] text-content-muted hover:text-content-primary"
            >
              Edit as a command line
            </button>
          )
        }
      >
        <input
          className={`${inputCls} font-mono joro-redact-field`}
          value={spec.path}
          placeholder="grep"
          onChange={(e) => patch({ path: e.target.value })}
        />
      </Section>

      <Section
        label="Arguments"
        hint="One per row, passed as a list. There is no shell, so nothing here is split, expanded or interpreted — an argument containing a space or a semicolon reaches the program as one argument."
      >
        <div className="space-y-1">
          {args.map((a, i) => (
            <div key={i} className="flex items-center gap-1">
              <span className="text-[10px] text-content-muted font-mono w-5 shrink-0 text-right">
                {i + 1}
              </span>
              <input
                className={`${inputCls} font-mono`}
                value={a}
                onChange={(e) =>
                  patch({ args: args.map((x, j) => (j === i ? e.target.value : x)) })
                }
              />
              <button
                onClick={() => patch({ args: args.filter((_, j) => j !== i) })}
                className="text-content-muted hover:text-semantic-error shrink-0"
                aria-label={`Remove argument ${i + 1}`}
              >
                <Trash2 size={12} strokeWidth={2} />
              </button>
            </div>
          ))}
          <button
            onClick={() => patch({ args: [...args, ''] })}
            className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
          >
            <Plus size={11} strokeWidth={2.4} aria-hidden="true" />
            Add argument
          </button>
        </div>

        {mustUseRows && (
          <p className="text-[10px] text-semantic-warning mt-1.5 leading-snug">
            {twoSources
              ? 'Standard input and the inline placeholder name different sources, which one select cannot show. Rows are the surface that can.'
              : 'This command holds an argument with a line break in it, which has no single-line form. Rows are the surface that can show it exactly.'}
          </p>
        )}
      </Section>
    </>
  )
}

/**
 * Everything that is not what runs: what else the program is given, and what Joro does
 * around it.
 *
 * Collapsed by default with a count of what is set, so it is never quietly hiding
 * configuration. The rationale for each of these lives in the Go doc comments that enforce
 * them — a line each here, which is what the operator needs at the point of the choice.
 */
function Advanced({
  spec,
  meta,
  patch,
}: {
  spec: CommandSpec
  meta: CommandMeta | null
  patch: (p: Partial<CommandSpec>) => void
}) {
  const [open, setOpen] = useState(false)

  const set =
    Object.keys(spec.files ?? {}).length +
    Object.keys(spec.env ?? {}).length +
    (spec.envPass ?? []).length +
    (spec.useProxy ? 1 : 0) +
    (spec.redact ? 1 : 0) +
    (spec.output && spec.output !== 'text' ? 1 : 0)

  return (
    <div className="border-t border-border-subtle pt-3">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 text-[10px] font-semibold text-content-muted uppercase tracking-wide hover:text-content-primary"
      >
        <ChevronRight
          size={11}
          strokeWidth={2.4}
          aria-hidden="true"
          className={open ? 'rotate-90' : ''}
        />
        Advanced
        {set > 0 && (
          <span className="ml-1 px-1 py-px rounded-sm bg-surface-input text-content-secondary normal-case tracking-normal">
            {set} set
          </span>
        )}
      </button>

      {open && (
        <div className="space-y-4 mt-3">
          <Section
            label="Input files"
            hint="Writes a part of the transaction into the working directory before the program starts. The key is the placeholder that resolves to its path — for a tool that wants a file rather than a pipe."
          >
            <PairRows
              pairs={spec.files ?? {}}
              keyPlaceholder="REQUEST_FILE"
              onChange={(files) => patch({ files })}
              renderValue={(v, setValue) => (
                <select className={inputCls} value={v} onChange={(e) => setValue(e.target.value)}>
                  {(meta?.fileParts ?? ['request']).map((p) => (
                    <option key={p} value={p}>
                      {PART_LABELS[p] ?? p}
                    </option>
                  ))}
                </select>
              )}
            />
          </Section>

          <Section
            label="Environment"
            hint="Extra variables. The base is PATH, HOME and the platform essentials; Joro's own environment is not inherited, so nothing your shell exports reaches the program unless you name it."
          >
            <PairRows
              pairs={spec.env ?? {}}
              keyPlaceholder="NAME"
              onChange={(env) => patch({ env })}
              renderValue={(v, setValue) => (
                <input
                  className={`${inputCls} font-mono`}
                  value={v}
                  onChange={(e) => setValue(e.target.value)}
                />
              )}
            />
            <label className="block mt-2">
              <span className="block text-[10px] text-content-muted mb-0.5">
                Inherit from Joro's environment — names, comma-separated
              </span>
              <input
                className={`${inputCls} font-mono`}
                value={(spec.envPass ?? []).join(', ')}
                placeholder="HOME, SSL_CERT_DIR"
                onChange={(e) =>
                  patch({
                    envPass: e.target.value
                      .split(',')
                      .map((x) => x.trim())
                      .filter(Boolean),
                  })
                }
              />
            </label>
          </Section>

          <Section label="Behaviour">
            <Check
              checked={!!spec.useProxy}
              onChange={(v) => patch({ useProxy: v })}
              label="Route its traffic through Joro's proxy"
              hint="Sets the proxy and CA-bundle variables, so a tool that honours them lands in History under your scope and rewriting rules. A default, not a control: Joro cannot bound where a separate process connects."
            />
            <Check
              checked={!!spec.redact}
              onChange={(v) => patch({ redact: v })}
              label="Mask credentials in what it reads"
              hint="Off by default, because the usual reason to send a request somewhere is to replay it and a masked cookie tests an anonymous endpoint. On for anything that sends the bytes on."
            />
          </Section>

          <Section label="Output rendering" hint="How a lens tab renders what the program printed.">
            <select
              className={inputCls}
              value={spec.output ?? 'text'}
              onChange={(e) => patch({ output: e.target.value })}
            >
              {(meta?.outputModes ?? ['text']).map((m) => (
                <option key={m} value={m}>
                  {m === 'json' ? 'JSON' : 'Plain text'}
                </option>
              ))}
            </select>
          </Section>
        </div>
      )}
    </div>
  )
}

function Section({
  label,
  hint,
  action,
  children,
}: {
  label: string
  hint?: string
  action?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div>
      <div className="flex items-baseline gap-2 mb-1">
        <label className="block text-[10px] font-semibold text-content-muted uppercase tracking-wide">
          {label}
        </label>
        {action && <span className="ml-auto">{action}</span>}
      </div>
      {children}
      {hint && <p className="text-[10px] text-content-muted mt-1 leading-snug">{hint}</p>}
    </div>
  )
}

function Check({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  label: string
  hint: string
}) {
  return (
    <label className="flex items-start gap-1.5 text-[11px] text-content-secondary mt-2 first:mt-0">
      <input
        type="checkbox"
        className="mt-0.5"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        {label}
        <span className="block text-[10px] text-content-muted leading-snug">{hint}</span>
      </span>
    </label>
  )
}

/**
 * Editable key/value rows over a plain object.
 *
 * The rows live here rather than being derived from the object on every render, and they
 * have to: a row whose key is still being typed is not yet a member of the object, so
 * deriving would make a new row disappear the instant it was added and would drop a key
 * mid-edit the moment it passed through the empty string. Local rows can hold a half-typed
 * state that the object cannot represent.
 *
 * Rows are keyed by index for the same reason — keying by the key itself would remount the
 * input on every keystroke and lose the caret.
 *
 * The object still wins when it changes underneath us, which is what the effect is for: the
 * editor loads a package asynchronously, so this mounts against an empty spec and gets the
 * real one a moment later. Comparing against what we last pushed up is what stops that
 * becoming a loop.
 */
function PairRows({
  pairs,
  keyPlaceholder,
  onChange,
  renderValue,
}: {
  pairs: Record<string, string>
  keyPlaceholder: string
  onChange: (next: Record<string, string>) => void
  renderValue: (value: string, set: (v: string) => void) => React.ReactNode
}) {
  const [rows, setRows] = useState<[string, string][]>(() => Object.entries(pairs))
  const pushed = useRef(collapse(Object.entries(pairs)))

  useEffect(() => {
    const incoming = JSON.stringify(pairs)
    if (incoming === JSON.stringify(pushed.current)) return
    pushed.current = pairs
    setRows(Object.entries(pairs))
  }, [pairs])

  const write = (next: [string, string][]) => {
    setRows(next)
    const collapsed = collapse(next)
    pushed.current = collapsed
    onChange(collapsed)
  }

  return (
    <div className="space-y-1">
      {rows.map(([k, v], i) => (
        <div key={i} className="flex items-center gap-1">
          <input
            className={`${inputCls} font-mono w-40 shrink-0`}
            value={k}
            placeholder={keyPlaceholder}
            onChange={(e) => write(rows.map((p, j) => (j === i ? [e.target.value, p[1]] : p)))}
          />
          <div className="flex-1 min-w-0">
            {renderValue(v, (nv) => write(rows.map((p, j) => (j === i ? [p[0], nv] : p))))}
          </div>
          <button
            onClick={() => write(rows.filter((_, j) => j !== i))}
            className="text-content-muted hover:text-semantic-error shrink-0"
            aria-label={`Remove ${k || 'row'}`}
          >
            <Trash2 size={12} strokeWidth={2} />
          </button>
        </div>
      ))}
      <button
        onClick={() => write([...rows, ['', '']])}
        className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary"
      >
        <Plus size={11} strokeWidth={2.4} aria-hidden="true" />
        Add
      </button>
    </div>
  )
}

/** Rows to the object they represent: blank keys are omitted, and a later row wins a
 *  duplicate, which is the same precedence a literal object would give. */
function collapse(rows: [string, string][]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of rows) if (k.trim() !== '') out[k] = v
  return out
}
