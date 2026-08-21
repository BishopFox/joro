/**
 * The command box's grammar: text in, a program and an argument list out.
 *
 * # Why this can exist at all
 *
 * `internal/localcmd` refuses any field that takes a command line as one string, because a
 * parsed argument list is what stops captured bytes steering a command. This does not
 * reintroduce one. It runs in the browser, at author time, and what it produces is
 * `path` + `args[]` — the same wire shape, the same manifest on disk, the same Go types.
 *
 * The property localcmd protects is not "no text is ever split". It is that the number of
 * argv elements, their boundaries, and the identity of the program are fixed *before any
 * wire-derived byte is known*. Substitution then runs over an array that already exists, so
 * a `{{URL}}` resolving to something with a space in it lands in exactly one element. This
 * file splits the template. It never splits a resolved value.
 *
 * That property has one precondition, and it is the reason to state it here rather than
 * leave it implicit:
 *
 *   **Nothing derived from captured traffic may ever be the input to `parseCommandLine`.**
 *
 * Today nothing is — a command is authored only in `CommandForm`, and no context menu seeds
 * this box. A future "send this URL to a command…" affordance that pre-filled it with a
 * captured value would put a wire value through a splitter and end the property. Do not
 * add one.
 *
 * # Not a shell
 *
 * Quoting groups words. Nothing else is interpreted:
 *
 *   - Words split on ASCII space and tab. Deliberately not a JavaScript `\s` class, which
 *     matches U+00A0 and U+FEFF — a non-breaking space pasted out of a web page would be
 *     split here while surviving `formatCommandLine`, and the round trip would silently
 *     change the argument list. `isSeparator` is shared by both directions so they cannot
 *     disagree.
 *   - `'…'` is fully literal and holds no escapes, so it cannot contain a `'`.
 *   - `"…"` is literal except `\"` and `\\`.
 *   - **A backslash outside quotes is an ordinary character.** This is the load-bearing
 *     decision. `Spec.Validate` rewrites `path` to an absolute one, so on Windows every
 *     reload of an existing command carries `C:\tools\x.exe`; with backslash as an escape
 *     that round trip would quietly produce `C:toolsx.exe`, and every backslash in every
 *     regular-expression argument would halve on each save. This is effectively
 *     PowerShell's rule. There is no POSIX/Windows mode toggle — two grammars would be two
 *     bugs, and the operator would have to know which one they were in.
 *   - `$` `` ` `` `~` `*` `;` `&` `>` `<` `(` `)` `{` `}` are ordinary characters. A `|` or
 *     a `>` reaches the program as an argument; `warnings` says so rather than the parse
 *     failing, because `find … -exec … ';'` is a real command.
 *
 * # The one piece of editor syntax
 *
 * `{{INPUT}}` leading the line before a `|`, or trailing it after a `<`, means "pipe the
 * input source to this program's standard input". In that position it is consumed here and
 * never reaches `args`; the caller turns it into `spec.stdin`. Anywhere else it is left
 * alone, because there it is a real placeholder the server substitutes into the argument.
 *
 * # Round trip
 *
 * `parseCommandLine(formatCommandLine(spec))` must reproduce the spec exactly. Not the
 * other way round: `format(parse(text))` normalizes quoting, so the box holds its own text
 * and is never re-rendered from the spec mid-edit.
 *
 * Losslessness is a correctness requirement rather than polish. A command package's stored
 * source is `Spec.Render()`, and the store cuts a revision whenever its hash changes — so a
 * lossy round trip would alter what runs for someone who opened the editor to fix a
 * description. And `importPackage` validates only the manifest id, so a crafted `.jauto`
 * could otherwise show one command line and install a different argument list.
 */

/** Word separators. ASCII only, shared by the parser and the formatter. */
export function isSeparator(ch: string): boolean {
  return ch === ' ' || ch === '\t'
}

/** Tokens that look like shell operators. Passed through literally; warned about. */
const SHELL_LOOKALIKES = ['|', '||', '>', '>>', '<', '<<', '&', '&&', ';', '`', '$(']

/** The editor-syntax token, wrapped. Kept as a literal here and checked against the
 *  server's `inputToken` by the caller, so the two cannot silently diverge. */
export const INPUT_TOKEN = '{{INPUT}}'

const PLACEHOLDER_RE = /\{\{([A-Z][A-Z0-9_]*)\}\}/g

/** The same shape, non-global, for a one-shot test. A `/g` regex carries `lastIndex`
 *  between calls, which makes `test` answer differently on identical input. */
const PLACEHOLDER_TEST = /\{\{[A-Z][A-Z0-9_]*\}\}/

export interface ParsedCommand {
  path: string
  args: string[]
  /** The line asked for the input source on standard input, with a leading `{{INPUT}} |`
   *  or a trailing `< {{INPUT}}`. */
  stdinPipe: boolean
  /** An argument names `{{INPUT}}`, so the input is substituted inline instead. */
  usesInline: boolean
  /** Non-fatal notes: shell operators passed through as ordinary arguments. */
  warnings: string[]
}

export interface CommandLineError {
  error: string
  /** A corrected line the UI can offer as a one-click fix, when there is an obvious one. */
  fix?: string
}

export type ParseResult = ParsedCommand | CommandLineError

export function isParseError(r: ParseResult): r is CommandLineError {
  return (r as CommandLineError).error !== undefined
}

/** One token, plus whether any part of it was quoted — which is what tells `{{INPUT}}`
 *  used as editor syntax apart from a literal the operator quoted deliberately. */
interface Token {
  text: string
  quoted: boolean
}

/**
 * Split a line into tokens by the grammar above.
 *
 * Returns a message rather than throwing, because every caller renders it next to the box.
 */
function tokenize(line: string): { tokens: Token[] } | CommandLineError {
  const tokens: Token[] = []

  let cur = ''
  let started = false
  let quoted = false
  let i = 0

  const flush = () => {
    if (started) tokens.push({ text: cur, quoted })
    cur = ''
    started = false
    quoted = false
  }

  while (i < line.length) {
    const ch = line[i]

    if (isSeparator(ch)) {
      flush()
      i++
      continue
    }

    if (ch === "'") {
      const end = line.indexOf("'", i + 1)
      if (end < 0) {
        return { error: "unclosed ' — a single-quoted argument needs a closing quote" }
      }
      cur += line.slice(i + 1, end)
      started = true
      quoted = true
      i = end + 1
      continue
    }

    if (ch === '"') {
      i++
      let closed = false
      while (i < line.length) {
        const c = line[i]
        if (c === '\\' && (line[i + 1] === '"' || line[i + 1] === '\\')) {
          cur += line[i + 1]
          i += 2
          continue
        }
        if (c === '"') {
          closed = true
          i++
          break
        }
        cur += c
        i++
      }
      if (!closed) {
        return { error: 'unclosed " — a double-quoted argument needs a closing quote' }
      }
      started = true
      quoted = true
      continue
    }

    cur += ch
    started = true
    i++
  }
  flush()

  return { tokens }
}

/**
 * Parse the command box.
 *
 * The order matters: editor syntax is recognised and removed first, so what is left is
 * unambiguously a program and its arguments.
 */
export function parseCommandLine(text: string): ParseResult {
  const t = tokenize(text.trim())
  if ('error' in t) return t

  let tokens = t.tokens
  if (tokens.length === 0) {
    return { error: 'no command — name a program to run' }
  }

  let stdinPipe = false

  // `echo "{{INPUT}}" | prog …` is the shell idiom for the head form, and it is the line
  // an operator writes first because it is what a shell would need. Recognised by name and
  // answered with a rewrite rather than an error, because the intent is unambiguous and
  // the correction is mechanical.
  const idiom = matchEchoIdiom(tokens)
  if (idiom) {
    return {
      error:
        `Joro is not a shell, so ${idiom.program} does not run and its output is not piped. ` +
        `Write ${INPUT_TOKEN} | at the head instead — Joro feeds the input source straight ` +
        `to the program's standard input.`,
      fix: idiom.fix,
    }
  }

  // Head form: {{INPUT}} | prog …
  if (tokens.length >= 2 && isInputToken(tokens[0]) && tokens[1].text === '|' && !tokens[1].quoted) {
    stdinPipe = true
    tokens = tokens.slice(2)
    if (tokens.length === 0) {
      return { error: `nothing after ${INPUT_TOKEN} | — name a program to receive the input` }
    }
  }

  // Tail form: prog … < {{INPUT}}
  const n = tokens.length
  if (n >= 3 && tokens[n - 2].text === '<' && !tokens[n - 2].quoted && isInputToken(tokens[n - 1])) {
    if (stdinPipe) {
      return {
        error: `the input is already piped at the head of the line, so the trailing < ${INPUT_TOKEN} is a second one`,
      }
    }
    stdinPipe = true
    tokens = tokens.slice(0, n - 2)
  }

  const [program, ...rest] = tokens

  if (PLACEHOLDER_TEST.test(program.text)) {
    return {
      error:
        'the program cannot be a {{PLACEHOLDER}}: placeholders resolve in arguments only, ' +
        'and which binary runs has to be settled when you save so the one you review is the ' +
        'one that runs',
    }
  }

  const args = rest.map((tok) => tok.text)
  const warnings: string[] = []
  rest.forEach((tok, idx) => {
    if (!tok.quoted && SHELL_LOOKALIKES.includes(tok.text)) {
      warnings.push(
        `Joro is not a shell, so ${tok.text} is passed to the program as argument ${idx + 1} ` +
          `rather than doing anything. Quote it to say you meant that.`,
      )
    }
  })

  return {
    path: program.text,
    args,
    stdinPipe,
    usesInline: args.some(namesInput),
    warnings,
  }
}

function isInputToken(tok: Token): boolean {
  return !tok.quoted && tok.text === INPUT_TOKEN
}

/** Whether an argument names {{INPUT}} as a placeholder, anywhere within it. */
export function namesInput(arg: string): boolean {
  PLACEHOLDER_RE.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = PLACEHOLDER_RE.exec(arg)) !== null) {
    if (m[1] === 'INPUT') return true
  }
  return false
}

/** Every placeholder name an argument list references, deduplicated, in first-use order. */
export function placeholdersUsed(args: string[]): string[] {
  const out: string[] = []
  for (const a of args) {
    PLACEHOLDER_RE.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = PLACEHOLDER_RE.exec(a)) !== null) {
      if (!out.includes(m[1])) out.push(m[1])
    }
  }
  return out
}

/** `echo "{{INPUT}}" | prog …` and its relatives, which mean the head form. */
function matchEchoIdiom(tokens: Token[]): { program: string; fix: string } | null {
  if (tokens.length < 3) return null

  const program = tokens[0].text
  if (!['echo', 'printf', 'cat'].includes(program)) return null

  // Quoted or bare: `echo "{{INPUT}}"` is the form a shell would need, and `echo {{INPUT}}`
  // is what someone writes who has stopped thinking about the shell. Both mean the same
  // thing here.
  if (tokens[1].text !== INPUT_TOKEN) return null

  const pipe = tokens[2]
  if (pipe.quoted || pipe.text !== '|') return null

  const rest = tokens.slice(3)
  if (rest.length === 0) return null

  return {
    program,
    fix: joinTokens(
      rest.map((tok) => tok.text),
      true,
    ),
  }
}

/**
 * Render a spec back into one line, or null when it has no one-line form.
 *
 * Null rather than a best effort, and that distinction is the whole safety of the fallback:
 * `Spec.Normalize` deliberately does not trim arguments and the server refuses only NUL and
 * over-length, so an argument holding a newline is a perfectly legal spec — `awk -v RS=…`
 * is a real one. A best-effort render would show the operator a line that does not describe
 * what is stored. Null tells the form to use the row editor instead.
 */
export function formatCommandLine(path: string, args: string[], stdinPipe: boolean): string | null {
  // A spec with nothing in it is an empty line, not a quoted empty string. The blank spec
  // a new command starts from would otherwise open the box showing '' — which is what an
  // empty *argument* looks like, and is a real thing to want, so it has to mean that and
  // only that.
  if (path === '' && args.length === 0 && !stdinPipe) return ''

  const all = [path, ...args]
  if (all.some(hasControlChar)) return null
  return joinTokens(all, stdinPipe)
}

/**
 * Join tokens into a line the parser reads back as the same list.
 *
 * Only one arrangement of ordinary tokens can be misread, and it is handled here rather
 * than by quoting defensively everywhere: a trailing `< {{INPUT}}` is the tail form. The
 * head form cannot arise by accident, because the first token is always the program and
 * the head form requires `{{INPUT}}` there.
 */
function joinTokens(all: string[], stdinPipe: boolean): string {
  const out = stdinPipe ? [INPUT_TOKEN, '|'] : []

  all.forEach((tok, i) => {
    const tail = i === all.length - 1
    if (tail && tok === INPUT_TOKEN && all[i - 1] === '<') {
      // Quote the redirect rather than the placeholder: the operator wrote `<` as a
      // literal argument, and it is the one that stops being one.
      out[out.length - 1] = `'<'`
    }
    out.push(quoteToken(tok))
  })

  return out.join(' ')
}

function hasControlChar(s: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u0008\u000a-\u001f\u007f]/.test(s)
}

/**
 * Quote one token so the parser reads it back unchanged.
 *
 * Bare when it can be, `'…'` when it cannot, `"…"` when it holds a `'`. The empty string
 * has to become `''`: a bare join would drop the argument entirely, which is a silent
 * deletion rather than a formatting difference.
 *
 * Backslashes are escaped only inside the double-quoted form, because that is the only
 * form that gives them a meaning. A Windows path stays bare and stays exact.
 */
function quoteToken(s: string): string {
  if (s === '') return "''"

  const needsQuote = s.includes("'") || s.includes('"') || Array.from(s).some(isSeparator)
  if (!needsQuote) return s
  if (!s.includes("'")) return `'${s}'`
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

/**
 * Whether the line survives a round trip, checked against itself.
 *
 * `web/` has no test runner and CLAUDE.md rules out committing one, so a grammar this
 * consequential gets a check that runs in the product instead. A mismatch means the parser
 * and the formatter disagree about this particular text, and the form falls back to the
 * row editor rather than saving an argument list the operator is not reading.
 */
export function roundTrips(text: string): boolean {
  const first = parseCommandLine(text)
  if (isParseError(first)) return true // a parse error is reported on its own terms

  const rendered = formatCommandLine(first.path, first.args, first.stdinPipe)
  if (rendered === null) return false

  const second = parseCommandLine(rendered)
  if (isParseError(second)) return false

  return (
    second.path === first.path &&
    second.stdinPipe === first.stdinPipe &&
    second.args.length === first.args.length &&
    second.args.every((a, i) => a === first.args[i])
  )
}
