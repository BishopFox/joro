// Method and status filter options shared by the History filter bar and the
// Site Map filter modal, plus the predicate used to filter live-streamed rows
// client-side. The status expression parser mirrors parseStatusFilter in
// internal/proxy/statusfilter.go — keep the two in sync.

export const HTTP_METHOD_OPTIONS = [
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT',
].map((key) => ({ key, label: key }))

export const STATUS_CLASS_OPTIONS = [
  { key: '1xx', label: '1xx', title: 'Informational' },
  { key: '2xx', label: '2xx', title: 'Success' },
  { key: '3xx', label: '3xx', title: 'Redirection' },
  { key: '4xx', label: '4xx', title: 'Client error' },
  { key: '5xx', label: '5xx', title: 'Server error' },
  { key: 'none', label: 'none', title: 'No response captured' },
]

// LiveFilterFields is the subset of the request filter that can be evaluated
// against a WebSocket request summary (which carries no raw bytes). Both
// RequestFilter and SitemapFilter build on it.
export interface LiveFilterFields {
  methods: string[]
  statusClasses: string[]
  statusCodes: string   // free text: exact codes and ranges, e.g. "403,500-599"
  exclude: string
  extMode: 'exclude' | 'include' | ''
}

// buildStatusExpr joins the class chips and the codes box into the single
// `status` query param the backend parses.
export function buildStatusExpr(classes: string[], codes: string): string {
  const tokens = [
    ...classes,
    ...codes.split(',').map((c) => c.trim()).filter(Boolean),
  ]
  return tokens.join(',')
}

export interface ParsedStatus {
  active: boolean
  none: boolean
  classes: Set<number>        // code/100
  codes: Set<number>
  ranges: [number, number][]
}

// Single-entry parse cache: matchesLiveFilter runs per row in a batch, and the
// expression is identical across the batch.
let lastExpr: string | null = null
let lastParsed: ParsedStatus | null = null

// parseStatusExpr compiles a status expression. Like the Go implementation,
// unparsable tokens are skipped silently so a half-typed value degrades to the
// tokens that do parse; an expression with no parsable token is inactive.
export function parseStatusExpr(expr: string): ParsedStatus {
  if (expr === lastExpr && lastParsed) return lastParsed
  const p: ParsedStatus = { active: false, none: false, classes: new Set(), codes: new Set(), ranges: [] }
  for (const raw of expr.split(',')) {
    const tok = raw.trim().toLowerCase()
    if (tok === '') continue
    if (tok === 'none' || tok === '0') {
      p.none = true
    } else if (/^[1-5]xx$/.test(tok)) {
      p.classes.add(Number(tok[0]))
    } else if (tok.includes('-')) {
      const [loRaw, hiRaw] = tok.split('-', 2)
      const lo = Number(loRaw.trim())
      const hi = Number(hiRaw.trim())
      if (!Number.isInteger(lo) || !Number.isInteger(hi) || loRaw.trim() === '' || hiRaw.trim() === '' || lo > hi) continue
      p.ranges.push([lo, hi])
    } else {
      const code = Number(tok)
      if (!Number.isInteger(code) || code <= 0) continue
      p.codes.add(code)
    }
    p.active = true
  }
  lastExpr = expr
  lastParsed = p
  return p
}

// matchesStatus reports whether a status code satisfies a parsed expression. A
// code of 0 (no response captured) matches only the "none" token.
export function matchesStatus(code: number, p: ParsedStatus): boolean {
  if (!p.active) return true
  if (code === 0) return p.none
  if (p.classes.has(Math.floor(code / 100))) return true
  if (p.codes.has(code)) return true
  return p.ranges.some(([lo, hi]) => code >= lo && code <= hi)
}

// matchesExtension applies the extension include/exclude filter to a URL.
// A URL that won't parse is allowed through.
export function matchesExtension(url: string, exclude: string, extMode: string): boolean {
  if (!exclude || !extMode) return true
  const exts = new Set(exclude.split(',').map((e) => e.trim().toLowerCase()))
  try {
    const { pathname } = new URL(url)
    const dotIdx = pathname.lastIndexOf('.')
    if (dotIdx < 0) return extMode !== 'include'
    const found = exts.has(pathname.substring(dotIdx).toLowerCase())
    return extMode === 'include' ? found : !found
  } catch {
    return true
  }
}

// matchesLiveFilter is the client-side predicate for live-streamed rows. It
// evaluates only the fields present in a WebSocket summary — method, status,
// and extension. Do NOT extend it to host/search/contentType/content/scope:
// those need server-side data (raw bytes, scope rules), and mixing enforcement
// levels would make the row count disagree with the server's total.
export function matchesLiveFilter(
  item: { url: string; method: string; statusCode: number },
  f: LiveFilterFields,
): boolean {
  if (f.methods.length > 0 && !f.methods.includes(item.method.toUpperCase())) return false
  const status = parseStatusExpr(buildStatusExpr(f.statusClasses, f.statusCodes))
  if (!matchesStatus(item.statusCode, status)) return false
  return matchesExtension(item.url, f.exclude, f.extMode)
}
