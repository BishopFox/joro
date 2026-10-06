import { useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { api } from '../../lib/api'
import { Tooltip } from '../Tooltip'
import {
  type PayloadSource,
  type SourceKind,
  type SourceMode,
  type WordlistCatalog,
  defaultSource,
  sourceCount,
} from '../../lib/fuzzSources'

interface Props {
  label: string
  placeholder: string
  wordlist: string
  wordlistFileName: string
  source: PayloadSource | undefined
  catalog: WordlistCatalog | null
  disabled: boolean
  onWordlistChange: (v: string, fileName?: string) => void
  onSourceChange: (source: PayloadSource | undefined) => void
}

function modeOf(source: PayloadSource | undefined): SourceMode {
  if (!source) return 'manual'
  return source.kind === 'builtin' ? 'builtin' : 'generator'
}

const GENERATOR_KINDS: SourceKind[] = ['numbers', 'chars', 'lengths', 'dates']

export default function PayloadSourcePanel(props: Props) {
  const { label, placeholder, wordlist, wordlistFileName, source, catalog, disabled } = props
  const fileRef = useRef<HTMLInputElement>(null)
  const mode = modeOf(source)

  const manualLines = wordlist.split('\n').filter((l) => l.trim() !== '').length
  const genCount = mode === 'manual' ? manualLines : sourceCount(source, catalog)

  function setMode(next: SourceMode) {
    if (next === 'manual') props.onSourceChange(undefined)
    else if (next === 'builtin') props.onSourceChange({ kind: 'builtin', list: catalog?.builtins[0]?.id ?? '' })
    else props.onSourceChange(defaultSource('numbers'))
  }

  function patch(p: Partial<PayloadSource>) {
    if (!source) return
    props.onSourceChange({ ...source, ...p })
  }

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => props.onWordlistChange(String(reader.result ?? ''), file.name)
    reader.readAsText(file)
    e.target.value = ''
  }

  return (
    <div className="flex flex-col overflow-hidden min-h-0 flex-1">
      {/* Header: label + count + mode selector */}
      <div className="flex items-center gap-2 px-2 py-1 bg-surface-card border-b border-border shrink-0">
        <span className="text-xs text-content-muted">
          {label} ({genCount < 0 ? '—' : genCount.toLocaleString()} payloads)
        </span>
        {mode === 'manual' && wordlistFileName && (
          <span className="text-xs text-content-secondary truncate max-w-32">{wordlistFileName}</span>
        )}
        <div className="flex items-center gap-0.5 ml-auto bg-surface-input rounded-sm p-0.5">
          {(['manual', 'builtin', 'generator'] as SourceMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              disabled={disabled}
              className={`text-xs px-2 py-0.5 rounded-sm capitalize ${
                mode === m ? 'bg-accent text-black' : 'text-content-secondary hover:text-content-primary'
              }`}
            >
              {m === 'builtin' ? 'Built-in' : m}
            </button>
          ))}
        </div>
      </div>

      {mode === 'manual' && (
        <>
          <div className="flex items-center gap-1 px-2 py-1 bg-surface-card border-b border-border shrink-0">
            <label className="text-xs px-2 py-0.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary cursor-pointer">
              Upload
              <input
                ref={fileRef}
                type="file"
                accept=".txt,.lst,.list,.wordlist,text/*"
                onChange={handleFile}
                className="hidden"
                disabled={disabled}
              />
            </label>
            {wordlist && (
              <Tooltip content="Clear wordlist">
                <button
                  onClick={() => props.onWordlistChange('')}
                  className="text-xs text-content-muted hover:text-semantic-error px-1 inline-flex items-center"
                  disabled={disabled}
                >
                  <X size={12} />
                </button>
              </Tooltip>
            )}
          </div>
          <textarea
            value={wordlist}
            onChange={(e) => props.onWordlistChange(e.target.value)}
            className="flex-1 bg-surface-input text-xs font-mono px-2 py-1 resize-none outline-none text-content-primary"
            placeholder={placeholder}
            readOnly={disabled}
            spellCheck={false}
          />
        </>
      )}

      {mode === 'builtin' && (
        <div className="flex-1 overflow-y-auto bg-surface-input p-3 flex flex-col gap-3">
          <BuiltinPicker catalog={catalog} source={source!} disabled={disabled} onPatch={patch} />
          <SourcePreview source={source} />
        </div>
      )}

      {mode === 'generator' && source && (
        <div className="flex-1 overflow-y-auto bg-surface-input p-3 flex flex-col gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-content-muted w-20">Generator</span>
            <select
              value={source.kind}
              onChange={(e) => props.onSourceChange(defaultSource(e.target.value as SourceKind))}
              disabled={disabled}
              className="flex-1 bg-surface-card text-xs px-2 py-1 rounded-sm text-content-primary border border-border"
            >
              {GENERATOR_KINDS.map((k) => {
                const info = catalog?.generators.find((g) => g.id === k)
                return <option key={k} value={k}>{info?.label ?? k}</option>
              })}
            </select>
          </div>
          <GeneratorFields source={source} disabled={disabled} onPatch={patch} />
          <SourcePreview source={source} />
        </div>
      )}
    </div>
  )
}

function BuiltinPicker({ catalog, source, disabled, onPatch }: {
  catalog: WordlistCatalog | null
  source: PayloadSource
  disabled: boolean
  onPatch: (p: Partial<PayloadSource>) => void
}) {
  const categories = Array.from(new Set((catalog?.builtins ?? []).map((b) => b.category)))
  const selected = catalog?.builtins.find((b) => b.id === source.list)
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <span className="text-xs text-content-muted w-20">List</span>
        <select
          value={source.list ?? ''}
          onChange={(e) => onPatch({ list: e.target.value })}
          disabled={disabled}
          className="flex-1 bg-surface-card text-xs px-2 py-1 rounded-sm text-content-primary border border-border"
        >
          <option value="">Select a list…</option>
          {categories.map((cat) => (
            <optgroup key={cat} label={cat}>
              {(catalog?.builtins ?? [])
                .filter((b) => b.category === cat)
                .map((b) => (
                  <option key={b.id} value={b.id}>{b.label} ({b.count})</option>
                ))}
            </optgroup>
          ))}
        </select>
      </div>
      {selected && <p className="text-xs text-content-muted pl-20">{selected.description}</p>}
    </div>
  )
}

function GeneratorFields({ source, disabled, onPatch }: {
  source: PayloadSource
  disabled: boolean
  onPatch: (p: Partial<PayloadSource>) => void
}) {
  if (source.kind === 'numbers') {
    const digits = source.numberMode === 'digits'
    return (
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs text-content-muted w-20">Mode</span>
          <div className="flex items-center gap-0.5 bg-surface-card rounded-sm p-0.5">
            {(['range', 'digits'] as const).map((m) => (
              <button
                key={m}
                onClick={() => onPatch({ numberMode: m })}
                disabled={disabled}
                className={`text-xs px-2 py-0.5 rounded-sm capitalize ${
                  (source.numberMode ?? 'range') === m ? 'bg-accent text-black' : 'text-content-secondary hover:text-content-primary'
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        </div>
        {digits ? (
          <>
            <NumField label="Min digits" value={source.minDigits} disabled={disabled} onChange={(v) => onPatch({ minDigits: v })} />
            <NumField label="Max digits" value={source.maxDigits} disabled={disabled} onChange={(v) => onPatch({ maxDigits: v })} />
          </>
        ) : (
          <>
            <NumField label="Min" value={source.min} disabled={disabled} onChange={(v) => onPatch({ min: v })} />
            <NumField label="Max" value={source.max} disabled={disabled} onChange={(v) => onPatch({ max: v })} />
            <NumField label="Step" value={source.step} disabled={disabled} onChange={(v) => onPatch({ step: v })} />
            <NumField label="Pad width" value={source.pad} disabled={disabled} onChange={(v) => onPatch({ pad: v })} />
            <div className="flex items-center gap-2">
              <span className="text-xs text-content-muted w-20">Base</span>
              <label className="text-xs text-content-secondary flex items-center gap-1">
                <input type="checkbox" checked={!!source.hex} disabled={disabled} onChange={(e) => onPatch({ hex: e.target.checked })} />
                Hexadecimal
              </label>
              {source.hex && (
                <label className="text-xs text-content-secondary flex items-center gap-1">
                  <input type="checkbox" checked={!!source.upper} disabled={disabled} onChange={(e) => onPatch({ upper: e.target.checked })} />
                  Uppercase
                </label>
              )}
            </div>
          </>
        )}
        <TextField label="Prefix" value={source.prefix} disabled={disabled} onChange={(v) => onPatch({ prefix: v })} />
        <TextField label="Suffix" value={source.suffix} disabled={disabled} onChange={(v) => onPatch({ suffix: v })} />
      </div>
    )
  }

  if (source.kind === 'chars') {
    return (
      <div className="flex flex-col gap-2">
        <TextField label="Charset" value={source.charset} disabled={disabled} onChange={(v) => onPatch({ charset: v })} mono />
        <NumField label="Min length" value={source.minLen} disabled={disabled} onChange={(v) => onPatch({ minLen: v })} />
        <NumField label="Max length" value={source.maxLen} disabled={disabled} onChange={(v) => onPatch({ maxLen: v })} />
      </div>
    )
  }

  if (source.kind === 'lengths') {
    return (
      <div className="flex flex-col gap-2">
        <TextField label="Character" value={source.char} disabled={disabled} onChange={(v) => onPatch({ char: v })} mono />
        <NumField label="Min length" value={source.minLen} disabled={disabled} onChange={(v) => onPatch({ minLen: v })} />
        <NumField label="Max length" value={source.maxLen} disabled={disabled} onChange={(v) => onPatch({ maxLen: v })} />
        <NumField label="Step" value={source.step} disabled={disabled} onChange={(v) => onPatch({ step: v })} />
      </div>
    )
  }

  // dates
  return (
    <div className="flex flex-col gap-2">
      <TextField label="Start (Y-M-D)" value={source.dateStart} disabled={disabled} onChange={(v) => onPatch({ dateStart: v })} mono />
      <TextField label="End (Y-M-D)" value={source.dateEnd} disabled={disabled} onChange={(v) => onPatch({ dateEnd: v })} mono />
      <NumField label="Step (days)" value={source.dateStep} disabled={disabled} onChange={(v) => onPatch({ dateStep: v })} />
      <TextField label="Format" value={source.dateFmt} disabled={disabled} onChange={(v) => onPatch({ dateFmt: v })} mono placeholder="2006-01-02" />
    </div>
  )
}

function NumField({ label, value, disabled, onChange }: {
  label: string; value: number | undefined; disabled: boolean; onChange: (v: number) => void
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-content-muted w-20">{label}</span>
      <input
        type="number"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value === '' ? 0 : Number(e.target.value))}
        disabled={disabled}
        className="w-28 bg-surface-card text-xs px-2 py-1 rounded-sm text-content-primary border border-border outline-none"
      />
    </div>
  )
}

function TextField({ label, value, disabled, onChange, mono, placeholder }: {
  label: string; value: string | undefined; disabled: boolean; onChange: (v: string) => void; mono?: boolean; placeholder?: string
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-content-muted w-20">{label}</span>
      <input
        type="text"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        placeholder={placeholder}
        spellCheck={false}
        className={`flex-1 bg-surface-card text-xs px-2 py-1 rounded-sm text-content-primary border border-border outline-none ${mono ? 'font-mono' : ''}`}
      />
    </div>
  )
}

// SourcePreview debounces a call to the resolver so the operator sees the real
// count and the first generated values, straight from the server that will run them.
function SourcePreview({ source }: { source: PayloadSource | undefined }) {
  const [state, setState] = useState<{ count: number; sample: string[]; exceedsLimit: boolean } | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!source) { setState(null); setError(null); return }
    let cancelled = false
    const t = setTimeout(() => {
      api.fuzzPreviewSource(source)
        .then((res) => { if (!cancelled) { setState(res); setError(null) } })
        .catch((e) => { if (!cancelled) { setState(null); setError(e?.message || 'invalid source') } })
    }, 300)
    return () => { cancelled = true; clearTimeout(t) }
  }, [source])

  if (error) return <p className="text-xs text-semantic-error">{error}</p>
  if (!state) return <p className="text-xs text-content-muted">Preview…</p>
  return (
    <div className="text-xs text-content-muted border-t border-border-subtle pt-2">
      <span className={state.exceedsLimit ? 'text-semantic-error' : 'text-content-secondary'}>
        ≈ {state.count.toLocaleString()} payloads
        {state.exceedsLimit && ' (exceeds the 10,000,000 limit)'}
      </span>
      {state.sample.length > 0 && (
        <span className="font-mono"> — {state.sample.slice(0, 8).map((s) => s || '∅').join(', ')}…</span>
      )}
    </div>
  )
}
