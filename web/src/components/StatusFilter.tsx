import { useEffect, useRef, useState } from 'react'
import { STATUS_CLASS_OPTIONS } from '../lib/requestFilters'
import { Tooltip } from './Tooltip'

const COMMIT_DELAY_MS = 250

type Props = {
  classes: string[]
  codes: string
  onChange: (patch: { statusClasses?: string[]; statusCodes?: string }) => void
  label?: string
}

// StatusFilter pairs status-class toggle chips (1xx…5xx plus "none" for requests
// with no captured response) with a box for exact codes and ranges. Chips and
// codes are OR'd. The patch keys match the field names in both requestStore's
// RequestFilter and SitemapFilter, so callers pass their setter straight in.
export default function StatusFilter({ classes, codes, onChange, label = 'Status' }: Props) {
  // The codes box is debounced: History refetches on every filter change, so
  // committing per keystroke would fire a request per character.
  const [draft, setDraft] = useState(codes)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  // Resync when the filter is reset externally (e.g. "Clear filters"), dropping
  // any pending commit so a stale draft can't overwrite the reset.
  useEffect(() => {
    clearTimeout(timer.current)
    setDraft(codes)
  }, [codes])

  useEffect(() => () => clearTimeout(timer.current), [])

  function editCodes(v: string) {
    setDraft(v)
    clearTimeout(timer.current)
    timer.current = setTimeout(() => onChange({ statusCodes: v }), COMMIT_DELAY_MS)
  }

  function toggleClass(key: string) {
    onChange({ statusClasses: classes.includes(key) ? classes.filter((k) => k !== key) : [...classes, key] })
  }

  return (
    <div className="flex items-center gap-1.5">
      <span className="text-xs text-content-muted">{label}</span>
      <div className="flex items-center gap-1">
        {STATUS_CLASS_OPTIONS.map((opt) => (
          <Tooltip key={opt.key} content={opt.title}>
            <button
              type="button"
              onClick={() => toggleClass(opt.key)}
              className={`px-1.5 h-5 flex items-center justify-center text-[10px] rounded-sm font-semibold leading-none ${
                classes.includes(opt.key)
                  ? 'bg-accent text-content-primary'
                  : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
              }`}
            >
              {opt.label}
            </button>
          </Tooltip>
        ))}
      </div>
      <Tooltip content="Exact codes and inclusive ranges, comma-separated — OR'd with the class chips">
        <input
          className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-28"
          placeholder="403,500-599"
          value={draft}
          onChange={(e) => editCodes(e.target.value)}
        />
      </Tooltip>
    </div>
  )
}
