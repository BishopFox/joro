import type { ReactNode } from 'react'

// Severity and category rendering for detection findings, shared by the findings
// table, the detail pane, the count bar, and the rules table. Scope is narrow:
// only severity, confidence, and category.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'high' | 'medium' | 'low'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
}

export const SEVERITY_OPTIONS = [
  {
    key: 'critical',
    label: 'Critical',
    title:
      'High-grade PII (national ID or payment card), or anything that alone leads to severe compromise: RCE, auth bypass, a served database dump',
  },
  {
    key: 'high',
    label: 'High',
    title: 'Account credentials, sensitive API keys, database connection strings, low-level PII',
  },
  { key: 'medium', label: 'Medium', title: 'Anything not covered by the other bands' },
  { key: 'low', label: 'Low', title: 'An exposed configuration file or similar' },
  {
    key: 'info',
    label: 'Info',
    title:
      'Not directly exploitable on its own: exposed panels, missing headers, information disclosure, analytics keys',
  },
]

export const CONFIDENCE_OPTIONS = [
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
]

// SEVERITY_CLS maps the five levels onto the semantic palette. Unusable tokens:
// `semantic-success` collides with `semantic-info` or `accent-tertiary` depending
// on the theme, `semantic-special` collides with `semantic-error` in five themes,
// and the three accent tokens are reserved for selection state and primary
// actions. Critical is the only background fill, so it stays distinct from High
// in themes where the error and warning hues are close.
const SEVERITY_CLS: Record<Severity, string> = {
  critical: 'bg-semantic-error-bg text-content-primary',
  high: 'bg-surface-input text-semantic-error',
  medium: 'bg-surface-input text-semantic-warning',
  low: 'bg-surface-input text-semantic-info',
  info: 'bg-surface-input text-content-muted',
}

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Crit',
  high: 'High',
  medium: 'Med',
  low: 'Low',
  info: 'Info',
}

const BADGE_BASE =
  'inline-block px-1 py-px rounded-sm text-[10px] font-bold uppercase tracking-wide align-middle'

// severityBadge renders a severity pill.
export function severityBadge(sev: string): ReactNode {
  const key = (sev || 'info') as Severity
  const cls = SEVERITY_CLS[key] ?? SEVERITY_CLS.info
  const label = SEVERITY_LABEL[key] ?? sev
  return <span className={`${BADGE_BASE} ${cls}`}>{label}</span>
}

// severityTextClass returns just the text colour, for icons and inline text.
export function severityTextClass(sev: string): string {
  switch (sev as Severity) {
    case 'critical':
      return 'text-semantic-error'
    case 'high':
      return 'text-semantic-error'
    case 'medium':
      return 'text-semantic-warning'
    case 'low':
      return 'text-semantic-info'
    default:
      return 'text-content-muted'
  }
}

export const CATEGORY_LABEL: Record<string, string> = {
  secrets: 'Secrets',
  credentials: 'Creds',
  pii: 'PII',
  access: 'Access',
  disclosure: 'Disclosure',
  headers: 'Headers',
  cookies: 'Cookies',
}

// categoryPill renders a category as one neutral pill. The seven categories are
// not colour-coded: four of the seven semantic tokens are already spoken for.
export function categoryPill(cat: string): ReactNode {
  return (
    <span
      className={`${BADGE_BASE} bg-surface-input text-accent-secondary normal-case font-semibold`}
    >
      {CATEGORY_LABEL[cat] ?? cat}
    </span>
  )
}

// maxSeverity returns the highest severity in a list.
export function maxSeverity(list: string[]): Severity {
  let best: Severity = 'info'
  for (const s of list) {
    const key = s as Severity
    if ((SEVERITY_RANK[key] ?? 0) > (SEVERITY_RANK[best] ?? 0)) best = key
  }
  return best
}
