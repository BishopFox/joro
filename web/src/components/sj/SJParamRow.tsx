import { useState } from 'react'
import { MoreVertical } from 'lucide-react'
import type { SJParam } from '../../lib/sjTypes'
import { Tooltip } from '../Tooltip'

/** The "Other…" option's value. NUL-prefixed so no real value collides with it,
 *  and written as an escape because a literal NUL makes git treat the file as
 *  binary — no diff, no blame, never reviewed. */
const OTHER_SENTINEL = '\u0000other'

/** One parameter's editing row.
 *
 *  The `in` badge is monochrome deliberately. severity.tsx records that
 *  semantic-success collides with semantic-info or accent-tertiary depending on
 *  the theme and that the three accents are reserved for selection and primary
 *  actions; four more hues for four `in` values is exactly the mistake that
 *  comment warns about. */
export default function SJParamRow({
  param,
  value,
  enabled,
  onChange,
  onToggle,
  onMenu,
}: {
  param: SJParam
  value: string
  enabled: boolean
  onChange: (v: string) => void
  onToggle: (on: boolean) => void
  onMenu: (x: number, y: number) => void
}) {
  // An enum is a starting point, not a constraint: testing a value the document
  // says is impossible is the entire job, so the dropdown always offers a way
  // out of itself.
  const hasEnum = (param.enum?.length ?? 0) > 0
  const [freeText, setFreeText] = useState(!hasEnum || !param.enum!.includes(value))

  const missingRequired = param.required && !enabled

  return (
    <div
      className={`px-2 py-1 border-b border-border-subtle last:border-0 ${
        missingRequired ? 'border-l-2 border-l-semantic-warning' : ''
      }`}
      onContextMenu={(e) => {
        e.preventDefault()
        e.stopPropagation()
        onMenu(e.clientX, e.clientY)
      }}
    >
      <div className="flex items-center gap-1.5">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onToggle(e.target.checked)}
          className="shrink-0"
          title={
            param.required
              ? 'Required by the document. Unticking it sends the request without it, which is a legitimate test.'
              : 'Include this parameter'
          }
        />
        <span className="px-1 py-px rounded-sm text-[9px] bg-surface-input text-content-secondary shrink-0">
          {param.in}
        </span>
        <span className="text-xs text-content-primary font-semibold truncate">{param.name}</span>
        {param.required && (
          <span className={missingRequired ? 'text-semantic-warning' : 'text-semantic-error'} title="required">
            *
          </span>
        )}
        <span className="text-[10px] text-content-muted truncate">
          {param.type}
          {param.format ? `(${param.format})` : ''}
        </span>
        {param.explodedFrom && (
          <Tooltip content={`Sent as its own query parameter; the document declares it inside the object "${param.explodedFrom}"`}>
            <span className="text-[9px] text-content-muted">from {param.explodedFrom}</span>
          </Tooltip>
        )}
        {param.deprecated && <span className="text-[9px] text-semantic-warning">deprecated</span>}
        <button
          onClick={(e) => {
            e.stopPropagation()
            const r = (e.target as HTMLElement).getBoundingClientRect()
            onMenu(r.left, r.bottom)
          }}
          className="ml-auto text-content-muted hover:text-content-primary shrink-0"
          title="Actions"
        >
          <MoreVertical size={12} />
        </button>
      </div>

      {param.description && (
        <div className="text-[10px] text-content-muted truncate ml-6" title={param.description}>
          {param.description}
        </div>
      )}

      <div className="ml-6 mt-0.5 flex items-center gap-1">
        {hasEnum && !freeText ? (
          <select
            value={value}
            onChange={(e) => {
              if (e.target.value === OTHER_SENTINEL) {
                setFreeText(true)
                return
              }
              onChange(e.target.value)
            }}
            className="flex-1 bg-surface-input border border-border rounded-sm px-1.5 py-0.5 text-xs"
          >
            {param.enum!.map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
            <option value={OTHER_SENTINEL}>Other…</option>
          </select>
        ) : (
          <>
            <input
              value={value}
              onChange={(e) => onChange(e.target.value)}
              placeholder={param.default}
              className="flex-1 bg-surface-input border border-border rounded-sm px-1.5 py-0.5 text-xs font-mono"
            />
            {hasEnum && (
              <button
                onClick={() => {
                  setFreeText(false)
                  onChange(param.enum![0])
                }}
                className="text-[10px] text-accent-secondary hover:underline shrink-0"
              >
                list
              </button>
            )}
          </>
        )}
      </div>
    </div>
  )
}
