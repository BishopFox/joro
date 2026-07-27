import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { Tooltip } from './Tooltip'

export interface MultiSelectOption {
  key: string
  label: string
  title?: string
}

type Props = {
  label: string
  options: MultiSelectOption[]
  selected: string[]
  onChange: (next: string[]) => void
  emptyLabel?: string
  tooltip?: string
  maxSummary?: number
}

// MultiSelectDropdown is a compact checkbox popover for filter bars: the trigger
// summarizes the selection ("Method: GET, POST") and the panel holds one
// checkbox per option. The panel is `position: fixed` so it escapes the filter
// bar and the site-map modal card, which would otherwise clip it — but it stays
// a DOM child of the root div (no portal) so click-outside works off a single
// `contains` check and, inside a modal, a panel click can't reach the backdrop's
// dismiss handler.
export default function MultiSelectDropdown({
  label,
  options,
  selected,
  onChange,
  emptyLabel = 'Any',
  tooltip,
  maxSummary = 3,
}: Props) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const btnRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState<{ top: number; left: number }>({ top: 0, left: 0 })

  useLayoutEffect(() => {
    if (!open) return
    const place = () => {
      const r = btnRef.current?.getBoundingClientRect()
      if (!r) return
      const panel = panelRef.current?.getBoundingClientRect()
      let left = r.left
      let top = r.bottom + 4
      if (panel) {
        if (left + panel.width > window.innerWidth) left = window.innerWidth - panel.width - 4
        if (top + panel.height > window.innerHeight) top = r.top - panel.height - 4
      }
      setPos({ top: Math.max(4, top), left: Math.max(4, left) })
    }
    place()
    window.addEventListener('resize', place)
    return () => window.removeEventListener('resize', place)
  }, [open])

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        setOpen(false)
        btnRef.current?.focus()
      }
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  function toggle(key: string) {
    onChange(selected.includes(key) ? selected.filter((k) => k !== key) : [...selected, key])
  }

  const summary =
    selected.length === 0 ? emptyLabel
      : selected.length > maxSummary ? `${selected.length} selected`
      : selected.join(', ')

  const trigger = (
    <button
      ref={btnRef}
      type="button"
      onClick={() => setOpen((v) => !v)}
      onKeyDown={(e) => {
        if (e.key === 'ArrowDown' && !open) {
          e.preventDefault()
          setOpen(true)
        }
      }}
      className="flex items-center gap-1.5 px-2 py-1.5 rounded-sm text-xs bg-surface-input border border-border text-content-secondary hover:text-content-primary hover:border-accent-secondary transition-colors"
    >
      <span className="text-content-muted">{label}</span>
      <span className={selected.length > 0 ? 'text-content-primary' : 'italic text-content-muted'}>{summary}</span>
      <ChevronDown size={12} aria-hidden="true" className="shrink-0" />
    </button>
  )

  return (
    <div className="relative" ref={rootRef}>
      {tooltip ? <Tooltip content={tooltip}>{trigger}</Tooltip> : trigger}

      {open && (
        <div
          ref={panelRef}
          style={{ position: 'fixed', top: pos.top, left: pos.left }}
          // Arrow keys are swallowed so History's document-level row navigation
          // can't move the table selection while the panel has focus.
          onKeyDown={(e) => { if (e.key === 'ArrowUp' || e.key === 'ArrowDown') e.stopPropagation() }}
          className="w-40 z-50 bg-surface-card border border-border rounded shadow-lg py-1 text-xs"
        >
          <div className="max-h-64 overflow-y-auto">
            {options.map((opt) => (
              <label
                key={opt.key}
                title={opt.title}
                className="flex items-center gap-2 px-2 py-1 cursor-pointer hover:bg-surface-hover"
              >
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={selected.includes(opt.key)}
                  onChange={() => toggle(opt.key)}
                />
                <span className="text-content-secondary">{opt.label}</span>
              </label>
            ))}
          </div>
          {selected.length > 0 && (
            <button
              type="button"
              onClick={() => onChange([])}
              className="w-full text-left px-2 py-1 border-t border-border-subtle text-content-muted hover:text-content-primary hover:bg-surface-hover"
            >
              Clear
            </button>
          )}
        </div>
      )}
    </div>
  )
}
