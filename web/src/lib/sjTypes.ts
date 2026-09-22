// Types for the SJ tab, mirroring internal/apispec and internal/apiscan.
//
// These live beside api.ts rather than in the store because api.ts references
// them in its signatures and the store imports them too; putting them in the
// store would make api.ts depend on a zustand module.

export type SJFormat = 'openapi3' | 'swagger2'
export type SJParamIn = 'path' | 'query' | 'header' | 'cookie'
export type SJTriage = 'good' | 'warn' | 'bad'
export type SJRunKind = 'scan' | 'matrix' | 'discovery'
export type SJRunStatus = 'running' | 'complete' | 'stopped'
export type SJBodyKind = 'spec' | 'weak' | 'reference' | 'challenge' | 'skip' | 'none'
export type SJVerdict = 'open' | 'broken' | 'denied' | 'expected' | 'error'
export type SJAuthKind = 'basic' | 'bearer' | 'apiKey' | 'http' | 'oauth2' | 'openIdConnect' | 'mutualTLS'

export interface SJServer {
  url: string
  scheme?: string
  host?: string
  basePath: string
  description?: string
}

export interface SJParam {
  name: string
  in: SJParamIn
  required?: boolean
  deprecated?: boolean
  description?: string
  type?: string
  format?: string
  enum?: string[]
  /** The generated value. Used as both the initial value and the placeholder,
   *  so clearing a field still shows what it was. */
  default: string
  /** Set when this row was split out of an object-schema query parameter. */
  explodedFrom?: string
  /** Serialization. `style` is always set by the parser — form for query and
   *  cookie, simple for path and header — so an empty one never reaches here. */
  style?: string
  explode?: boolean
  /** Set when the document declared the parameter with `content` rather than
   *  `schema`, so its value is a serialized media type. */
  contentType?: string
}

export interface SJBody {
  contentType: string
  encoding: 'json' | 'xml' | 'form' | 'multipart' | 'raw'
  /** base64 — Go marshals []byte that way. */
  content: string
  fields?: string[]
}

export interface SJDiagnostic {
  kind: string
  ref?: string
  pointer?: string
  detail?: string
}

export interface SJOperation {
  id: string
  method: string
  path: string
  summary?: string
  description?: string
  tags?: string[]
  deprecated?: boolean
  params: SJParam[]
  bodies?: SJBody[]
  bodyRequired?: boolean
  responses?: Record<string, string>
  /** null means "inherit the document's"; [] means the operation explicitly
   *  opts out of authentication. The two are different statements. */
  security: { schemes: string[] }[] | null
  servers?: SJServer[]
  destructive?: boolean
  destructiveReasons?: string[]
  diagnostics?: SJDiagnostic[]
}

export interface SJAuthScheme {
  name: string
  kind: SJAuthKind
  in?: SJParamIn
  paramName?: string
  scheme?: string
  bearerFormat?: string
  description?: string
  automatable: boolean
}

/** The values the server generated this document's defaults from.
 *
 *  Effective values, not the operator's input: an empty field is filled from the
 *  server's default before parsing, so what comes back is always what a request
 *  will actually carry. */
export interface SJPlaceholders {
  string: string
  date: string
  url: string
  email: string
}

export interface SJSpec {
  id: string
  format: SJFormat
  version: string
  title: string
  description?: string
  apiVersion?: string
  servers: SJServer[]
  operations: SJOperation[]
  auth: SJAuthScheme[]
  security?: { schemes: string[] }[]
  diagnostics?: SJDiagnostic[]
  sourceUrl?: string
  sizeBytes: number
  placeholders: SJPlaceholders
}

export interface SJSpecSummary {
  id: string
  title: string
  format: SJFormat
  version: string
  operations: number
  servers: number
  diagnostics: number
  sourceUrl?: string
  sizeBytes: number
  loadedAt: string
}

export interface SJRenderBody {
  specId: string
  operationId: string
  serverIndex?: number
  scheme?: string
  host?: string
  basePath?: string
  values?: Record<string, string>
  profileId?: string
  userAgent?: string
  fuzzParam?: string
  fuzzKeyword?: string
  /** Parameters to leave out entirely, by `${in}:${name}`. Distinct from an
   *  empty entry in `values`, which means "send it empty". */
  omit?: string[]
}

export interface SJSendResult {
  raw: string
  rawResp: string
  status: number
  durationMs: number
  len: number
  seq: number
  requestId?: string
  seqNote?: string
  triage: SJTriage
  url: string
}

/** A credential as sent to the server. It never comes back. */
export interface SJCredential {
  scheme?: string
  kind: SJAuthKind
  in?: SJParamIn
  name?: string
  value?: string
  username?: string
  password?: string
}

export interface SJProfileInput {
  id: string
  label: string
  rank: number
  credentials?: SJCredential[]
  headers?: { name: string; value: string }[]
  cookies?: { name: string; value: string }[]
}

/** What the server returns about a profile: identity only, never a secret. */
export interface SJProfileSummary {
  id: string
  label: string
  rank: number
  kinds: string[]
  hasValue: boolean
  headers: number
}

export interface SJScanBody {
  specId: string
  operationIds?: string[]
  profileIds?: string[]
  serverIndex?: number
  scheme?: string
  host?: string
  basePath?: string
  values?: Record<string, Record<string, string>>
  concurrency?: number
  ratePerSec?: number
  timeoutMs?: number
  budgetMs?: number
  userAgent?: string
  allowDestructive?: boolean
  methods?: string[]
}

export interface SJDiscoverBody {
  scheme: string
  host: string
  basePath?: string
  full?: boolean
  stopOnFirst?: boolean
  concurrency?: number
  ratePerSec?: number
  timeoutMs?: number
  budgetMs?: number
  userAgent?: string
}

export interface SJResult {
  index: number
  opId?: string
  profileId?: string
  method?: string
  /** The document's template, braces intact. Present even when nothing was sent. */
  path?: string
  url?: string
  /** Path and query as actually rendered, every placeholder resolved. Absent
   *  when the item was skipped before it rendered. */
  reqPath?: string
  seq: number
  requestId?: string
  seqNote?: string
  status: number
  len: number
  ms: number
  bhash?: string
  shash?: string
  words?: number
  lines?: number
  note?: string
  triage: SJTriage
  error?: string
  /** destructive | method | budget | render */
  skipped?: string
  contentType?: string
  bodyKind?: SJBodyKind
  specTitle?: string
  specFormat?: string
  specOps?: number
}

/** A document a discovery sweep parsed mid-run, carried by `spec.run.found`.
 *  It is already in the server's spec store under `specId`, so opening it costs
 *  no second request to the target. */
export interface SJFoundSpec {
  specId: string
  title: string
  format: string
  operations: number
  sourceUrl: string
}

export interface SJRunSummary {
  id: string
  kind: SJRunKind
  specId?: string
  status: SJRunStatus
  total: number
  completed: number
  errors: number
  skipped: number
  hits: number
  createdAt: string
}

export interface SJRunDetail extends SJRunSummary {
  results: SJResult[]
  resultTotal: number
  offset: number
  limit: number
}

export interface SJMatrixCell {
  profileId: string
  rank: number
  status: number
  len: number
  bhash?: string
  shash?: string
  ms: number
  seq: number
  requestId?: string
  triage: SJTriage
  index: number
  error?: string
  skipped?: string
}

export interface SJMatrixRow {
  opId: string
  method: string
  path: string
  cells: SJMatrixCell[]
  verdict: SJVerdict
  detail?: string
}

export interface SJMatrixView {
  runId: string
  profiles: { id: string; label: string; rank: number }[]
  rows: SJMatrixRow[]
  summary: Record<string, number>
  interesting: string[]
}

/** The bag passed through navigate() when another tab sends a document here. */
export interface SJNavState {
  source: 'history' | 'detect' | 'manipulate'
  /** Preferred: SJ fetches the bytes itself, so a multi-MB document does not
   *  ride in history.pushState's structured clone on every later navigation. */
  requestId?: string
  /** Fallback for a response with no History row. base64. */
  respRaw?: string
  url?: string
  name?: string
}
