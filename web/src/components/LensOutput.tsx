import { useEffect, useMemo, useState } from 'react'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { oneDark } from '@codemirror/theme-one-dark'
import { css } from '@codemirror/lang-css'
import { html } from '@codemirror/lang-html'
import { javascript } from '@codemirror/lang-javascript'
import { json } from '@codemirror/lang-json'
import { api } from '../lib/api'
import { MAX_LENS_BYTES, type ViewerPart } from '../lib/lenses'

export interface LensMeta {
  host?: string
  url?: string
  method?: string
  status?: number
  contentType?: string
}

type State =
  | { kind: 'loading' }
  | { kind: 'ok'; text: string; language?: string }
  | { kind: 'error'; reason: string; detail?: string }

const LANGUAGES: Record<string, () => ReturnType<typeof json>> = {
  json,
  html,
  css,
  javascript,
  js: javascript,
}

/** Reads the value a lens returned: either a bare string or { text, language }. */
function readValue(value: unknown): { text: string; language?: string } | null {
  if (typeof value === 'string') return { text: value }
  if (value && typeof value === 'object') {
    const v = value as { text?: unknown; language?: unknown }
    if (typeof v.text === 'string') {
      return { text: v.text, language: typeof v.language === 'string' ? v.language : undefined }
    }
  }
  return null
}

/**
 * One lens tab's body: runs the automation over the bytes on screen and renders what it
 * returned. Re-runs when the bytes change, and reports a failed run here rather than as a
 * toast — the failure belongs where the output would have been.
 */
export default function LensOutput({
  scriptId,
  part,
  raw,
  meta,
}: {
  scriptId: string
  part: ViewerPart
  raw: string
  meta?: LensMeta
}) {
  const [state, setState] = useState<State>({ kind: 'loading' })

  useEffect(() => {
    let cancelled = false
    setState({ kind: 'loading' })

    const truncated = raw.length > MAX_LENS_BYTES
    const slice = truncated ? raw.slice(0, MAX_LENS_BYTES) : raw
    let b64: string
    try {
      b64 = btoa(slice)
    } catch {
      setState({ kind: 'error', reason: 'these bytes could not be encoded for a lens' })
      return
    }

    api
      .runScript({
        scriptId,
        trigger: 'lens',
        input: { part, raw: b64, truncated, ...meta },
      })
      .then((run) => {
        if (cancelled) return
        // Branch on the stable code; show the prose, which is what an operator reads.
        if (run.result.outcome !== 'success') {
          setState({ kind: 'error', reason: run.result.reason, detail: run.result.err })
          return
        }
        const v = readValue(run.result.value)
        setState(
          v
            ? { kind: 'ok', ...v }
            : { kind: 'error', reason: 'this lens returned no text', detail: 'Return { text } or a string.' }
        )
      })
      .catch((e) => {
        if (cancelled) return
        setState({ kind: 'error', reason: String(e instanceof Error ? e.message : e) })
      })

    return () => {
      cancelled = true
    }
    // meta is not a dependency: it describes the same transaction as raw, so it cannot
    // change without raw changing, and it is a fresh object literal on every render.
  }, [scriptId, part, raw])

  const extensions = useMemo(() => {
    const lang = state.kind === 'ok' ? LANGUAGES[state.language?.toLowerCase() ?? ''] : undefined
    return lang ? [lang(), EditorView.lineWrapping] : [EditorView.lineWrapping]
  }, [state])

  if (state.kind === 'loading') {
    return (
      <div className="absolute inset-0 flex items-center justify-center text-content-muted text-xs">
        Running…
      </div>
    )
  }

  if (state.kind === 'error') {
    return (
      <div className="absolute inset-0 overflow-auto p-3 text-[11px]">
        <div className="text-semantic-warning font-semibold">{state.reason}</div>
        {state.detail && (
          <pre className="font-mono whitespace-pre-wrap text-semantic-error mt-1">{state.detail}</pre>
        )}
      </div>
    )
  }

  return (
    <div className="absolute inset-0 overflow-hidden">
      <CodeMirror
        value={state.text}
        theme={oneDark}
        readOnly={true}
        height="100%"
        extensions={extensions}
        basicSetup={{ lineNumbers: true, foldGutter: false }}
      />
    </div>
  )
}
