import type { Finding, DetectFilter } from '../stores/detectStore'
import { type Severity } from './severity'

// Client-side filter predicate for live-streamed findings.
//
// A detect.finding payload carries every field the filter bar filters on, so
// live inserts are gated on the full filter and the row count agrees with the
// server's total. Do not add a dimension the WebSocket payload does not carry.

export const CATEGORY_OPTIONS = [
  { key: 'secrets', label: 'Secrets', title: 'API keys, tokens, private keys' },
  { key: 'credentials', label: 'Credentials', title: 'Auth material, connection strings, credential files' },
  { key: 'pii', label: 'PII', title: 'Personal data' },
  { key: 'access', label: 'Access', title: 'Login forms, admin panels, management consoles' },
  { key: 'disclosure', label: 'Disclosure', title: 'Stack traces, versions, internal paths, exposed files' },
  { key: 'headers', label: 'Headers', title: 'Security header and CORS issues' },
  { key: 'cookies', label: 'Cookies', title: 'Cookie flag issues' },
]

export const TARGET_OPTIONS = [
  { key: 'response_body', label: 'Response body' },
  { key: 'response_header', label: 'Response header' },
  { key: 'request_body', label: 'Request body' },
  { key: 'request_header', label: 'Request header' },
  { key: 'url', label: 'URL' },
  { key: 'message', label: 'Analyzer' },
]

// matchesFindingFilter reports whether a finding belongs in the current view.
export function matchesFindingFilter(f: Finding, filter: DetectFilter): boolean {
  // False-positive handling mirrors the server: hidden unless asked for.
  if (!filter.showFalsePositives && f.falsePositive) return false

  // severities is the visible set; empty means no severity filter at all.
  if (filter.severities.length > 0 && !filter.severities.includes(f.severity as Severity)) {
    return false
  }
  if (filter.categories.length > 0 && !filter.categories.includes(f.category)) return false
  if (filter.confidence && f.confidence !== filter.confidence) return false

  if (filter.rule) {
    const needle = filter.rule.toLowerCase()
    if (
      !f.ruleId.toLowerCase().includes(needle) &&
      !f.ruleName.toLowerCase().includes(needle)
    ) {
      return false
    }
  }
  if (filter.host && !f.host.toLowerCase().includes(filter.host.toLowerCase())) return false

  if (filter.search) {
    const needle = filter.search.toLowerCase()
    if (
      !(f.evidence ?? '').toLowerCase().includes(needle) &&
      !(f.url ?? '').toLowerCase().includes(needle) &&
      !f.ruleName.toLowerCase().includes(needle) &&
      !(f.detail ?? '').toLowerCase().includes(needle)
    ) {
      return false
    }
  }
  return true
}

// buildFindingQuery converts the filter into query params for the list endpoint.
// The shared query-string builder in api.ts drops '' and 0, so booleans are sent
// as the string 'true' or omitted, and the server reads absence as false.
export function buildFindingQuery(
  filter: DetectFilter,
  sort: string,
  dir: string
): Record<string, string | number> {
  return {
    // Omitted when empty, so "no selection" means every band on the wire too.
    // minSeverity is never sent; severity would override it at the endpoint.
    ...(filter.severities.length > 0 && { severity: filter.severities.join(',') }),
    ...(filter.categories.length > 0 && { category: filter.categories.join(',') }),
    ...(filter.confidence && { confidence: filter.confidence }),
    ...(filter.rule && { ruleId: filter.rule }),
    ...(filter.host && { host: filter.host }),
    ...(filter.search && { search: filter.search }),
    ...(filter.showFalsePositives && { fp: 'all' }),
    ...(filter.includeDisabled && { includeDisabled: 'true' }),
    sort,
    dir,
    offset: filter.offset,
    // Stringified: the shared query builder drops the number 0, and limit=0
    // means "all" rather than the server's default page size.
    limit: String(filter.limit),
  }
}
