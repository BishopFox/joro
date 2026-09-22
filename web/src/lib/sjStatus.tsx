import type { ReactNode } from 'react'
import type { SJTriage, SJVerdict } from './sjTypes'

// Rendering only. The rubric itself is computed server-side and ships on every
// result, so there is no second copy of it here to drift — unlike the status
// filter and the hex dump, which are keep-in-sync pairs by necessity.
//
// Each pill carries a letter as well as a colour. severity.tsx records why:
// `semantic-success` collides with `semantic-info` or `accent-tertiary`
// depending on the theme, so hue alone does not survive a theme switch. As
// there, exactly one band gets a background fill, which keeps it distinct even
// where two hues sit close together.

const TRIAGE_CLS: Record<SJTriage, string> = {
  good: 'text-semantic-success',
  warn: 'text-semantic-warning',
  bad: 'bg-semantic-error-bg text-content-primary',
}

const TRIAGE_LETTER: Record<SJTriage, string> = { good: 'G', warn: 'W', bad: 'B' }

const TRIAGE_TITLE: Record<SJTriage, string> = {
  good: 'the request was accepted (2xx)',
  warn: 'neither accepted nor cleanly refused',
  bad: 'refused or absent (401, 403, 404)',
}

/** triagePill renders the band marker plus its status code. */
export function triagePill(triage: SJTriage | undefined, status: number, skipped?: string): ReactNode {
  if (skipped) {
    return (
      <span className="text-content-muted text-[10px]" title={`not sent: ${skipped}`}>
        skipped
      </span>
    )
  }
  const band = triage ?? 'warn'
  return (
    <span className="inline-flex items-center gap-1" title={TRIAGE_TITLE[band]}>
      <span className={`px-1 rounded-sm text-[10px] font-bold ${TRIAGE_CLS[band]}`}>
        {TRIAGE_LETTER[band]}
      </span>
      <span className="text-content-secondary tabular-nums">{status || '-'}</span>
    </span>
  )
}

const VERDICT_CLS: Record<SJVerdict, string> = {
  open: 'bg-semantic-error-bg text-content-primary',
  broken: 'text-semantic-error',
  denied: 'text-content-muted',
  expected: 'text-content-secondary',
  error: 'text-semantic-warning',
}

const VERDICT_LABEL: Record<SJVerdict, string> = {
  open: 'unauthenticated',
  broken: 'broken access',
  denied: 'denied',
  expected: 'as expected',
  error: 'error',
}

/** verdictPill renders one matrix row's conclusion. */
export function verdictPill(verdict: SJVerdict, detail?: string): ReactNode {
  return (
    <span className={`px-1.5 py-px rounded-sm text-[10px] ${VERDICT_CLS[verdict]}`} title={detail || ''}>
      {VERDICT_LABEL[verdict]}
    </span>
  )
}

/** formatSize renders a byte count compactly. */
export function formatSize(n: number): string {
  if (!n) return '0'
  if (n < 1024) return String(n)
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`
  return `${(n / 1024 / 1024).toFixed(1)}M`
}

/** methodClass tints a method token. Deliberately restrained: the palette's
 *  three accents are spoken for by selection and primary actions, so only the
 *  two methods that change state are marked at all. */
export function methodClass(method: string): string {
  switch (method.toUpperCase()) {
    case 'DELETE':
      return 'text-semantic-error'
    case 'POST':
    case 'PUT':
    case 'PATCH':
      return 'text-semantic-warning'
    default:
      return 'text-content-secondary'
  }
}
