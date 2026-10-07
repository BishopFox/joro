import { Fragment, useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { severityBadge } from '../lib/severity'

// One rule row — passive detect rules and active-scan checks both map onto this,
// so the two sections render identically.
export interface RuleRowVM {
  id: string
  name: string
  description?: string
  severity: string
  confidence?: string
  target?: string
  originLabel: string
  originBuiltin: boolean
  enabled: boolean
  hits?: number
  onToggle: (enabled: boolean) => void
  onClick?: () => void
  onHits?: () => void
}

// One collapsible group.
export interface RuleGroupVM {
  key: string
  label: string
  description?: string
  rows: RuleRowVM[]
  onEnableAll: () => void
  onDisableAll: () => void
}

interface Props {
  title?: string
  subtitle?: string
  groups: RuleGroupVM[]
  expanded: Set<string>
  onToggleExpand: (key: string) => void
  // When any filter is active, groups render expanded so matches aren't hidden.
  filtering: boolean
  emptyText: string
}

// Rows per page within a group; groups larger than this paginate rather than
// rendering thousands of rows at once.
const PAGE_SIZE = 100

function originPill(builtin: boolean, label: string) {
  return (
    <span
      className={`inline-block px-1 py-px rounded-sm bg-surface-input text-[10px] font-semibold uppercase tracking-wide align-middle ${
        builtin ? 'text-accent-secondary' : 'text-accent-tertiary'
      }`}
    >
      {label}
    </span>
  )
}

// RuleTableSection renders a labelled section (e.g. "Active Rules") as a grouped,
// collapsible table identical in shape to the detect rules table, so active and
// passive rules are indistinguishable but for the header. Groups start collapsed
// (an absent key in `expanded`).
export default function RuleTableSection({
  title,
  subtitle,
  groups,
  expanded,
  onToggleExpand,
  filtering,
  emptyText,
}: Props) {
  const [pages, setPages] = useState<Record<string, number>>({})
  const setPage = (key: string, n: number) => setPages((prev) => ({ ...prev, [key]: n }))

  return (
    <div className="border-b border-border">
      {(title || subtitle) && (
        <div className="flex items-center gap-1.5 px-2 py-1.5 bg-surface-card">
          {title && (
            <span className="text-[10px] font-semibold uppercase tracking-wide text-content-secondary">
              {title}
            </span>
          )}
          {subtitle && <span className="text-[10px] text-content-muted">· {subtitle}</span>}
        </div>
      )}
      <table className="w-full text-xs">
        <thead className="bg-surface-card text-content-muted uppercase">
          <tr>
            <th className="px-2 py-1 w-8" />
            <th className="px-2 py-1 text-left">Rule</th>
            <th className="px-2 py-1 text-left w-20">Severity</th>
            <th className="px-2 py-1 text-left w-14">Conf</th>
            <th className="px-2 py-1 text-left w-32">Target</th>
            <th className="px-2 py-1 text-left w-20">Origin</th>
            <th className="px-2 py-1 text-right w-12">Hits</th>
          </tr>
        </thead>
        <tbody>
          {groups.length === 0 && (
            <tr>
              <td colSpan={7} className="px-2 py-6 text-center text-content-muted text-xs">
                {emptyText}
              </td>
            </tr>
          )}
          {groups.map((g) => {
            const isCollapsed = !filtering && !expanded.has(g.key)
            const onCount = g.rows.filter((r) => r.enabled).length
            const pageCount = Math.ceil(g.rows.length / PAGE_SIZE)
            const page = Math.min(pages[g.key] ?? 0, Math.max(0, pageCount - 1))
            const shown = pageCount > 1 ? g.rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE) : g.rows
            return (
              <Fragment key={g.key}>
                <tr className="cursor-pointer hover:bg-surface-hover" onClick={() => !filtering && onToggleExpand(g.key)}>
                  <td colSpan={7} className="px-2 py-1 bg-surface-input text-[10px] text-content-muted uppercase tracking-wide">
                    <span className="flex items-center gap-2">
                      {filtering ? <span className="w-3" /> : isCollapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
                      <span className="normal-case font-semibold text-content-secondary">{g.label}</span>
                      <span>({g.rows.length})</span>
                      <span className={onCount === g.rows.length ? '' : 'text-semantic-warning'}>{onCount} on</span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          g.onEnableAll()
                        }}
                        className="text-accent-secondary hover:underline normal-case"
                      >
                        Enable all
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          g.onDisableAll()
                        }}
                        className="text-accent-secondary hover:underline normal-case"
                      >
                        Disable all
                      </button>
                      {g.description && <span className="normal-case text-content-muted font-normal">— {g.description}</span>}
                    </span>
                  </td>
                </tr>
                {!isCollapsed &&
                  shown.map((r) => (
                    <tr
                      key={r.id}
                      className={`border-b border-border-subtle hover:bg-surface-hover ${r.onClick ? 'cursor-pointer' : ''} ${
                        r.enabled ? '' : 'opacity-60'
                      }`}
                      onClick={r.onClick}
                    >
                      <td className="px-2 py-1">
                        <input
                          type="checkbox"
                          className="accent-accent"
                          checked={r.enabled}
                          onClick={(e) => e.stopPropagation()}
                          onChange={(e) => r.onToggle(e.target.checked)}
                        />
                      </td>
                      <td className="px-2 py-1">
                        <div className="text-content-secondary truncate max-w-md">{r.name}</div>
                        {r.description && (
                          <div className="text-[10px] text-content-muted truncate max-w-md">{r.description}</div>
                        )}
                      </td>
                      <td className="px-2 py-1">{severityBadge(r.severity)}</td>
                      <td className="px-2 py-1 text-content-muted">{r.confidence ?? '—'}</td>
                      <td className="px-2 py-1 text-content-muted truncate">{r.target ?? '—'}</td>
                      <td className="px-2 py-1">{originPill(r.originBuiltin, r.originLabel)}</td>
                      <td className="px-2 py-1 text-right">
                        {r.hits ? (
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              r.onHits?.()
                            }}
                            className="text-accent-secondary hover:underline"
                          >
                            {r.hits}
                          </button>
                        ) : (
                          <span className="text-content-muted">0</span>
                        )}
                      </td>
                    </tr>
                  ))}
                {!isCollapsed && pageCount > 1 && (
                  <tr className="bg-surface-card">
                    <td colSpan={7} className="px-2 py-1.5">
                      <span className="flex items-center gap-3 text-[10px] text-content-muted">
                        <button
                          disabled={page === 0}
                          onClick={() => setPage(g.key, page - 1)}
                          className="px-1.5 py-0.5 rounded-sm bg-surface-input hover:bg-surface-hover disabled:opacity-40"
                        >
                          Prev
                        </button>
                        <span>
                          {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, g.rows.length)} of {g.rows.length}
                        </span>
                        <button
                          disabled={page >= pageCount - 1}
                          onClick={() => setPage(g.key, page + 1)}
                          className="px-1.5 py-0.5 rounded-sm bg-surface-input hover:bg-surface-hover disabled:opacity-40"
                        >
                          Next
                        </button>
                      </span>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
