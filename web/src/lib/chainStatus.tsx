import type { ReactNode } from 'react'
import type { ChainCell, ChainVerdictKind, ChainVariantKind } from './chainTypes'

// Rendering only.
//
// The rubric itself — which cell state a response earns, and what a variant
// proved — is computed in internal/chainrun and ships on every result, so there
// is no second copy of it here to drift. This file turns those strings into
// pills, and nothing else.
//
// Each pill carries a letter as well as a colour, for the reason sjStatus.tsx
// records: semantic-success collides with semantic-info and accent-tertiary
// depending on the theme, and a grid read by colour alone is unreadable in at
// least one of them. Exactly one band gets a background fill.

const cellClass: Record<ChainCell, string> = {
  ok: 'text-semantic-success',
  changed: 'text-semantic-warning',
  blocked: 'text-semantic-info',
  unresolved: 'bg-semantic-error-bg text-content-primary',
  skipped: 'text-content-muted',
  error: 'text-semantic-error',
}

const cellLetter: Record<ChainCell, string> = {
  ok: '=',
  changed: '~',
  blocked: 'B',
  unresolved: '?',
  skipped: '-',
  error: '!',
}

const cellTitle: Record<ChainCell, string> = {
  ok: 'Same structural response as the baseline',
  changed: 'Answered differently from the baseline',
  blocked: 'The baseline succeeded here and this did not',
  unresolved: 'Did not send: a value this step needs was never produced in this ordering',
  skipped: 'This variant left the step out',
  error: 'The send itself failed',
}

export function cellPill(cell: ChainCell | undefined, status: number, note?: string): ReactNode {
  if (!cell) {
    return <span className="text-content-muted" title="Not run yet">·</span>
  }
  const label = cell === 'skipped' || cell === 'unresolved' || cell === 'error' ? '' : String(status || '')
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded font-mono text-xs ${cellClass[cell]}`}
      title={note ? `${cellTitle[cell]} - ${note}` : cellTitle[cell]}
    >
      <span className="font-bold">{cellLetter[cell]}</span>
      {label && <span>{label}</span>}
    </span>
  )
}

const verdictClass: Record<ChainVerdictKind, string> = {
  baseline: 'text-content-muted',
  bypassed: 'bg-semantic-error-bg text-content-primary',
  enforced: 'text-semantic-success',
  amplified: 'bg-semantic-error-bg text-content-primary',
  idempotent: 'text-semantic-success',
  inconclusive: 'text-semantic-warning',
}

const verdictLetter: Record<ChainVerdictKind, string> = {
  baseline: 'B',
  bypassed: '!',
  enforced: 'E',
  amplified: '!',
  idempotent: 'I',
  inconclusive: '?',
}

export function verdictPill(verdict: ChainVerdictKind | undefined, detail?: string): ReactNode {
  if (!verdict) {
    return <span className="text-content-muted text-xs">pending</span>
  }
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs ${verdictClass[verdict]}`}
      title={detail || ''}
    >
      <span className="font-bold font-mono">{verdictLetter[verdict]}</span>
      <span>{verdict}</span>
    </span>
  )
}

/** Is this verdict one the operator should look at first? */
export function isFinding(verdict: ChainVerdictKind | undefined): boolean {
  return verdict === 'bypassed' || verdict === 'amplified'
}

const kindLabel: Record<ChainVariantKind, string> = {
  baseline: 'baseline',
  omit: 'skip',
  repeat: 'repeat',
  move: 'reorder',
}

export function variantKindLabel(kind: ChainVariantKind): string {
  return kindLabel[kind] ?? kind
}

export function methodClass(method: string): string {
  switch (method.toUpperCase()) {
    case 'GET':
      return 'text-semantic-info'
    case 'POST':
      return 'text-semantic-success'
    case 'PUT':
    case 'PATCH':
      return 'text-semantic-warning'
    case 'DELETE':
      return 'text-semantic-error'
    default:
      return 'text-content-secondary'
  }
}

export function formatSize(n: number): string {
  if (n < 1024) return `${n}`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}k`
  return `${(n / 1024 / 1024).toFixed(1)}M`
}
