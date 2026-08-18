import { useEffect, useState } from 'react'
import { ChevronDown, ChevronRight, AlertTriangle, Pencil } from 'lucide-react'
import { api, type SdkMethod } from '../../lib/api'

/**
 * The joro.* surface, for whoever is writing a script.
 *
 * Served from GET /automation/sdk, which joins the binding table with each capability's
 * registered title and description — the same text a language model reads as its tool
 * contract. One source, so a method that exists is documented and a documented method
 * exists, and neither can drift from what the sandbox actually exposes.
 *
 * There is deliberately no editor autocomplete: @codemirror/autocomplete is not a declared
 * dependency and its popup has no theme CSS here, so it would arrive off-palette. A list
 * you can read beside the code covers discovery without that.
 */
export default function SdkReference() {
  const [open, setOpen] = useState(false)
  const [methods, setMethods] = useState<SdkMethod[]>([])
  const [storage, setStorage] = useState<{ js: string; description: string }[]>([])
  const [globals, setGlobals] = useState<{ js: string; description: string }[]>([])
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    if (!open || methods.length > 0) return
    api
      .getScriptSdk()
      .then((d) => {
        setMethods(d.methods ?? [])
        setStorage(d.storage ?? [])
        setGlobals(d.globals ?? [])
      })
      .catch(() => {
        /* the panel simply stays empty; the editor above still works */
      })
  }, [open, methods.length])

  return (
    <div className="border border-border rounded">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-1.5 px-2 py-1.5 text-[10px] font-semibold text-content-muted uppercase tracking-wide"
      >
        {open ? <ChevronDown size={12} strokeWidth={2} /> : <ChevronRight size={12} strokeWidth={2} />}
        SDK reference
      </button>

      {open && (
        <div className="px-2 pb-2 space-y-1.5">
          <p className="text-[10px] text-content-muted leading-snug">
            Every method is <code className="font-mono">await</code>-able and throws on failure, with{' '}
            <code className="font-mono">err.code</code> carrying the reason. Arguments match the tool
            of the same name.
          </p>

          {methods.map((m) => (
            <div key={m.js}>
              <button
                onClick={() => setExpanded(expanded === m.js ? null : m.js)}
                className="w-full text-left flex items-start gap-1 hover:bg-surface-hover rounded px-1 py-0.5"
              >
                <code className="font-mono text-[10px] text-accent-secondary break-all">{m.js}</code>
                <span className="ml-auto shrink-0 inline-flex gap-0.5 pt-0.5">
                  {m.sendsTraffic && (
                    <span title="Sends traffic to a target">
                      <AlertTriangle size={9} strokeWidth={2} className="text-semantic-warning" aria-hidden="true" />
                    </span>
                  )}
                  {m.mutating && (
                    <span title="Changes Joro's own state">
                      <Pencil size={9} strokeWidth={2} className="text-semantic-special" aria-hidden="true" />
                    </span>
                  )}
                </span>
              </button>
              {expanded === m.js && (
                <div className="px-1 pb-1 space-y-1">
                  {m.description && (
                    <p className="text-[10px] text-content-secondary leading-snug">{m.description}</p>
                  )}
                  {m.argsExample !== undefined && m.argsExample !== null && (
                    <pre className="font-mono text-[10px] bg-surface-input rounded p-1 overflow-x-auto">
                      {JSON.stringify(m.argsExample)}
                    </pre>
                  )}
                </div>
              )}
            </div>
          ))}

          <DocList title="Storage" items={storage} />
          <DocList title="Globals" items={globals} />
        </div>
      )}
    </div>
  )
}

/** A named group of one-line entries: storage verbs, sandbox globals. */
function DocList({ title, items }: { title: string; items: { js: string; description: string }[] }) {
  if (items.length === 0) return null
  return (
    <div className="pt-1 border-t border-border-subtle">
      <p className="text-[10px] font-semibold text-content-muted uppercase tracking-wide mb-0.5">{title}</p>
      {items.map((s) => (
        <div key={s.js} className="px-1 py-0.5">
          <code className="font-mono text-[10px] text-accent-secondary break-all">{s.js}</code>
          <p className="text-[10px] text-content-muted leading-snug">{s.description}</p>
        </div>
      ))}
    </div>
  )
}
