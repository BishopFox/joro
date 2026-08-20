import type { CallbackInteraction, CallbackToken } from '../stores/callbackStore'
import type { InterceptKind, PendingItem } from '../stores/interceptStore'
import type { ChatMessage, ActiveUser } from '../stores/teamStore'
import type { FlaggedSummary, FlaggedRequest } from '../stores/teamFlaggedStore'
import type { SharedConfigSummary, SharedConfig, SharedConfigPayload } from '../stores/teamSharedConfigStore'
import type {
  Finding,
  FindingOccurrence,
  DetectRule,
  DetectConfig,
  DetectSummary,
  ScanState,
} from '../stores/detectStore'

export interface CollabRequest {
  id: string
  requestor: string
  project: string
  note: string
  config?: string
  status: string
  createdAt: string
}

// ProjectMeta is the per-project metadata shown in the project browser/switcher.
export interface ProjectMeta {
  name: string
  savedAt: string
  sizeBytes: number
  requestCount: number
  noteCount: number
  findingCount: number
  autoSave: boolean
  saveHistory: boolean
  active: boolean
}
import type { XSSProbe, XSSFire, PayloadVariant, CollectedPage, CollectedPageSummary, XSSConfig } from '../stores/xssHunterStore'

export interface VersionInfo {
  version: string
  commit: string
  updateAvailable: boolean
  latestVersion: string
}

export interface NoisePattern {
  id: string
  pattern: string
}

export interface ScopeRule {
  id: string
  pattern: string
  methods: string[]
  path: string
  include: boolean
}

export interface MatchReplaceRule {
  id: string
  target: string
  matchType: string
  match: string
  replace: string
}

export interface CustomAddition {
  id: string
  type: string
  name: string
  value: string
}

export interface Note {
  id: string
  host: string
  content: string
  author: string
  createdAt: string
  updatedAt: string
}

export interface InteractProviderMeta {
  name: string
  info: { label: string; buttonLabel: string; helpText?: string }
  configSchema: ConfigField[]
}

export interface InteractInstance {
  id: string
  label: string
  hex: string
  status: string      // "connected" | "connecting" | "error" | "disabled"
  enabled: boolean
  payloadUrl: string
  meta?: Record<string, string>
}

export interface InteractInteraction {
  id: string
  instanceId: string
  hex: string
  protocol: string
  sourceIp: string
  timestamp: string
  queryName?: string
  queryType?: string
  method?: string
  path?: string
  rawRequest?: string
}

export interface SitemapVariant {
  params: string[]
  requestId: string
  count: number
}

export interface SitemapEndpoint {
  path: string
  methods: string[]
  params: string[]
  variants: SitemapVariant[]
  count: number
}

export interface SitemapHost {
  origin: string
  endpoints: SitemapEndpoint[]
  count: number
}

export interface CapturedWSMessage {
  id: string
  connectionId: string
  timestamp: string
  direction: string
  opcode: number
  payloadLength: number
  payload: string
  host: string
  url: string
  isText: boolean
}

// Automation types

/** A bearer token handed to an automation client. Never carries the secret: the
 *  plaintext exists only in the create and rotate replies. */
export interface AutomationToken {
  id: string
  name: string
  prefix: string
  /** Fully expanded capability IDs. There are no wildcards, by design — a pattern
   *  written today would silently grant capabilities shipped in a later version. */
  grants: string[]
  requireScope: boolean
  hostAllow?: string[]
  /** Lets tools return the values of Authorization, Cookie and similar headers
   *  rather than masking them. Off by default. */
  allowCredentials: boolean
  rateLimitPerMin: number
  maxConcurrent: number
  maxOutputBytes: number
  disabled: boolean
  createdAt: string
  expiresAt?: string
  rotatedAt?: string
  lastUsedAt?: string
  lastUsedCapability?: string
  useCount: number
  capsFingerprint?: string
  grantedAtVersion?: string
  /** Capabilities that exist but this token does not hold. Surfaced so an operator
   *  can review them; nothing is ever granted implicitly. */
  ungrantedCapabilities?: string[]
  sendsTraffic: boolean
  expired: boolean
}

export interface AutomationTokenInput {
  name?: string
  grants?: string[]
  requireScope?: boolean
  hostAllow?: string[]
  allowCredentials?: boolean
  rateLimitPerMin?: number
  maxConcurrent?: number
  maxOutputBytes?: number
  expiresInDays?: number
}

export interface Capability {
  id: string
  class: string
  title: string
  description: string
  mutating: boolean
  /** Emits traffic to a target host, so it is subject to the scope guard. */
  sendsTraffic: boolean
  /** Refused to a token with requireScope set or a host whitelist. A token whose
   *  authorization control is scope must not edit scope; one the operator has
   *  exempted from scope already reaches every host, so editing it grants nothing. */
  unrestrictedOnly: boolean
  /** Execution or C2. Registered only under --automation-privileged, and never
   *  bundled into a profile — the operator selects each by hand. */
  privileged: boolean
  inputSchema: unknown
  maxOutputBytes: number
  /** The MCP tool name: the capability ID with dots replaced by underscores. */
  toolName: string
}

/** A curated grant bundle. Selecting one expands it into a concrete grant list at
 *  create time; the profile is never stored on the token, so a profile that gains a
 *  capability in a later release does not widen a token issued today. */
export interface AutomationProfile {
  id: string
  title: string
  description: string
  grants: string[]
  /** The recommended token setting, not a constraint. A profile granting an
   *  unrestrictedOnly capability leaves this false or those grants are always denied. */
  requireScope: boolean
  allowsSends: boolean
  allowsCredentials: boolean
  rateLimitPerMin: number
  maxConcurrent: number
}

export interface McpState {
  enabled: boolean
  running: boolean
  port: number
  endpoint: string
  error?: string
  tokenCount: number
}

/** One console line captured from a sandboxed script. */
export interface ScriptLogLine {
  at: string
  level: string
  text: string
}

/** The outcome of one sandboxed script run. */
export interface ScriptResult {
  /** success | script exception | timeout | memory limit | sdk budget exceeded |
   *  cancelled | capability denied | runtime failure | worker lost */
  reason: string
  err?: string
  /** The JSON value run() returned, still encoded. */
  value?: unknown
  logs?: ScriptLogLine[]
  logsTruncated?: boolean
  calls: number
  sendCalls: number
  /** joro.storage calls, counted apart from capability calls because they consume no
   *  registry budget, engage no scope guard, and write no audit entry. */
  storageOps?: number
  callInputBytes: number
  callOutputBytes: number
  /** The budget this run was actually held to, after the operator's global was applied.
   *  Reported so a count has something to be read against. */
  budget?: AutomationLimits
  durationMs: number
}

export interface ScriptRun {
  id: string
  startedAt: string
  durationMs: number
  /** The launching token, not the run's own synthetic principal. */
  tokenId: string
  tokenName: string
  trigger: string
  bundle: string
  /** Verbatim, and only on the single-run endpoint. A hash alone would not answer
   *  which code an agent ran, since a one-shot script has no stored artifact. */
  source?: string
  sourceHash: string
  /** The policy the run was held to: inherited from the launching token, or from the
   *  operator's scope configuration when no token launched it. */
  requireScope: boolean
  credentials: boolean
  result: ScriptResult
}

/** The author's requested budget. Every field optional; the operator may only lower. */
export interface AutomationLimits {
  timeoutMs?: number
  memoryMb?: number
  maxCalls?: number
  maxSendCalls?: number
  maxLogBytes?: number
  maxResultBytes?: number
}

/** Which half of a transaction a lens renders. */
export type LensPart = 'request' | 'response' | 'both'

export const LENS_PARTS: LensPart[] = ['request', 'response', 'both']

/** A viewer tab an automation contributes. Bytes in, text out. */
export interface AutomationLens {
  label: string
  part: LensPart
}

/** The author-owned half of an installed automation. Cannot request capabilities: the
 *  sdkVersion selects a Joro-owned bundle, which is the point of the indirection. */
export interface AutomationManifest {
  id: string
  name: string
  version: string
  description?: string
  sdkVersion: string
  entrypoint?: string
  triggers?: string[]
  limits?: AutomationLimits
  /** Set to add a viewer tab. The operator can retitle, repoint and reorder it. */
  lens?: AutomationLens
  /** Shortest gap between two triggered runs. Combined with the operator's by taking
   *  the longer, which is why it is not inside limits. */
  minIntervalMs?: number
}

export interface AutomationRevision {
  hash: string
  at: string
  bytes: number
}

export interface AutomationLastRun {
  id: string
  at: string
  reason: string
}

/** The operator-owned half, in a separate file so an update never reverts a decision. */
export interface AutomationState {
  enabled: boolean
  /** Set by the runaway breaker, never by the operator. Enabling clears it. */
  paused?: boolean
  pausedReason?: string
  /** Individual triggers switched off: true disables, absent means armed. */
  triggersDisabled?: Record<string, boolean>
  limits?: AutomationLimits
  minIntervalMs?: number
  /** Bounds where this automation's runs may send. Exists for trigger-fired runs, which
   *  carry no launching token and are otherwise bounded by scope alone. */
  hostAllow?: string[]
  /** Overrides for the manifest's lens. Empty takes the author's value. */
  lensLabel?: string
  lensPart?: string
  lensOrder?: number
  installedAt: string
  updatedAt: string
  revisions?: AutomationRevision[]
  lastRun?: AutomationLastRun
}

/** One installed automation, source included. */
export interface AutomationPackage {
  manifest: AutomationManifest
  state: AutomationState
  source?: string
  sourceHash: string
  /** What a run of this automation actually gets: the author's request, narrowed by the
   *  operator's override, held to the global budget. Resolved server-side so no caller
   *  has to hold three halves and decide which wins. */
  effectiveLimits?: AutomationLimits
}

/** One configurable field of the run budget, with the reason it is set where it is.
 *  Served rather than restated here, so the UI cannot drift from the runtime. */
export interface BudgetSpec {
  key: string
  label: string
  /** The unit the operator types in — seconds, KB, calls. */
  unit: string
  /** Stored value = entered value x factor. Wall clock is entered in seconds and
   *  stored in milliseconds, because that is what an automation manifest declares. */
  factor: number
  /** Joro's own default, and the maximum that applies while the operator has set none.
   *  Both in the operator's unit, unlike the stored field. defaultMax is absent only on a
   *  host spec, which has no requestable side and so no maximum. */
  default: number
  defaultMax?: number
  /** The one figure the operator cannot exceed, with what it is fixed against. Absent
   *  for most fields, where their number is final. */
  cap?: number
  capReason?: string
  description: string
}

/** Limits that belong to this Joro rather than to one run. */
export interface AutomationHostLimits {
  storageOps?: number
  sourceBytes?: number
  concurrentRuns?: number
  agentLogBytes?: number
  agentResultBytes?: number
}

/** What the operator has set: per field a default and a maximum, plus the host limits. */
export interface AutomationPolicy {
  defaults?: AutomationLimits
  maxima?: AutomationLimits
  host?: AutomationHostLimits
}

export interface AutomationBudget {
  policy: AutomationPolicy
  /** What a run that asks for nothing is held to. */
  effective: AutomationLimits
  /** The most a run may ask for. Not always the shipped figure: an operator default
   *  above it raises it, because their setting has to take. */
  effectiveMax: AutomationLimits
  /** The host limits with every unset field resolved. */
  host: AutomationHostLimits
  specs: BudgetSpec[]
  hostSpecs: BudgetSpec[]
  /** The bytes the two agent-output limits share; the one ceiling here that is fixed at
   *  startup, so the pair is checked against it on save. */
  agentOutputCap: number
}

/** List projection. Source is withheld, not merely omitted. */
export interface AutomationSummary {
  id: string
  name: string
  version: string
  description?: string
  sdkVersion: string
  triggers: string[]
  /** The triggers currently live: declared, not switched off, and runnable. */
  armed: string[]
  /** The author's declaration with the operator's overrides already applied. */
  lens?: AutomationLens
  lensOrder?: number
  enabled: boolean
  paused?: boolean
  pausedReason?: string
  sourceHash: string
  sourceBytes: number
  installedAt: string
  updatedAt: string
  revisions: number
  lastRun?: AutomationLastRun
}

/** One joro.* method, joined with the capability behind it. */
export interface SdkMethod {
  js: string
  capability: string
  title?: string
  description?: string
  inputSchema?: unknown
  argsExample?: unknown
  sendsTraffic?: boolean
  mutating?: boolean
}

export interface AuditEntry {
  seq: number
  at: string
  tokenId: string
  tokenName: string
  /** Groups every call one sandboxed script made. Absent on a direct client call. */
  runId?: string
  capability: string
  result: 'ok' | 'denied' | 'error'
  code?: string
  targetHost?: string
  targetMethod?: string
  targetPath?: string
  requireScope: boolean
  /** This call could return unmasked Authorization and Cookie values. */
  credentials?: boolean
  /** An execution or C2 invocation. */
  privileged?: boolean
  /** A digest, not the arguments: arguments to a send carry credentials and
   *  payloads, and retaining them would make this a secondary secret store. */
  argsDigest?: string
  argsBytes: number
  /** A mutating capability's own description of what it altered. The one place
   *  arguments are recorded readably, because configuration is not a credential —
   *  without it an operator can see that an agent edited the proxy but not what. */
  change?: string
  outputBytes: number
  durationMs: number
  errMsg?: string
}

export interface AutomationAudit {
  entries: AuditEntry[]
  total: number
  offset: number
  limit: number
  stats: {
    lastHour: number
    deniedLastHour: number
    errorsLastHour: number
    tokens: number
    tokensActive: number
  }
}

// Plugin types
export interface PluginInfo {
  name: string
  version: string
  description: string
  type: string // "exec_provider" | "tab" | "feature" | "proxy_hook" | "dashboard"
  status: string // "loaded" | "error"
  error?: string
  hash: string
  filename: string
  hasGraph?: boolean
  tabLabel?: string
}

export interface ConfigField {
  name: string
  label: string
  type: string // "text" | "password" | "textarea" | "file"
  placeholder: string
  required: boolean
  helpText?: string
}

export interface ExecProviderInfo {
  name: string
  label: string
  configSchema: ConfigField[]
  builtin: boolean
}

export interface PluginProviderStatus {
  connected: boolean
  displayInfo?: Record<string, string>
}

export interface PluginCommandResult {
  output: string
  error?: string
  downloadId?: string
  filename?: string
  clear?: boolean
}

export interface PluginGraphNode {
  id: string
  name: string
  hostname: string
  os: string
  arch: string
  remoteAddress: string
  transport: string
  username: string
  type: string // "session" | "beacon" | "agent"
  status: string // "active" | "stale" | "dead"
}

export interface PluginGraphInfo {
  server?: { label: string; host: string; port: number }
  nodes: PluginGraphNode[]
}

const BASE = '/api/v1'

// TEAM_POLL_TIMEOUT bounds the listener-proxied polling GETs (chat/notes/flagged/
// callbacks/xss lists). When the team server is down these otherwise hang for the
// full server-side proxyToListener timeout (~10s) and saturate the browser's HTTP/1.1
// connection pool, delaying unrelated local calls (e.g. getSettings). Applied only to
// polling reads — never to mutations or /manipulate/send, which can be legitimately slow.
export const TEAM_POLL_TIMEOUT = 4000

async function req<T>(method: string, path: string, body?: unknown, timeoutMs?: number): Promise<T> {
  const ctrl = timeoutMs ? new AbortController() : undefined
  const timer = timeoutMs ? setTimeout(() => ctrl!.abort(), timeoutMs) : undefined
  try {
    const res = await fetch(`${BASE}${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl?.signal,
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error((err as { error: string }).error || res.statusText)
    }
    return res.json() as Promise<T>
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export const api = {
  // Sitemap
  getSitemap: (params: Record<string, string | number> = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ hosts: SitemapHost[] }>('GET', `/sitemap${qs ? `?${qs}` : ''}`)
  },
  // Delete a site-map node's underlying requests. Omit path for host-level
  // deletion; pass a path (including '') to scope to a single endpoint.
  deleteSitemapNode: (origin: string, path?: string) => {
    const qs = new URLSearchParams({ host: origin })
    if (path !== undefined) qs.set('path', path)
    return req<{ deleted: number }>('DELETE', `/sitemap?${qs.toString()}`)
  },

  // History
  listRequests: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ items: unknown[]; total: number; offset: number; limit: number }>(
      'GET', `/requests${qs ? `?${qs}` : ''}`
    )
  },
  getRequest: (id: string) => req<unknown>('GET', `/requests/${id}`),
  clearRequests: () => req<unknown>('DELETE', '/requests'),

  // Intercept
  getIntercept: () =>
    req<{ enabled: boolean; responsesEnabled: boolean; items: PendingItem[] }>('GET', '/intercept'),
  setInterceptEnabled: (enabled: boolean) =>
    req<{ enabled: boolean }>('PUT', '/intercept/enabled', { enabled }),
  setInterceptResponses: (enabled: boolean) =>
    req<{ enabled: boolean }>('PUT', '/intercept/responses', { enabled }),
  // Forwards every pending pause unmodified. Omit kind to release both phases.
  releaseIntercepts: (kind?: InterceptKind) =>
    req<{ released: number }>('POST', '/intercept/release', kind ? { kind } : {}),
  forwardIntercept: (id: string, patch: { reqRaw?: string; respRaw?: string }) =>
    req<unknown>('POST', `/intercept/${id}/forward`, patch),
  dropRequest: (id: string) => req<unknown>('POST', `/intercept/${id}/drop`),

  // Manipulate
  send: (raw: string, scheme: string, host: string, opts?: { updateContentLength?: boolean; followRedirects?: boolean; decompress?: boolean }) =>
    req<{ status: number; durationMs: number; rawResp: string }>(
      'POST', '/manipulate/send', { raw, scheme, host, ...opts }
    ),

  // Manipulate — WebSocket
  manipulateWSConnect: (raw: string, scheme: string, host: string) =>
    req<{ sessionId: string; status: number; rawResp: string; error: string }>(
      'POST', '/manipulate/ws/connect', { raw, scheme, host }
    ),
  manipulateWSSend: (sessionId: string, opcode: string, payload: string) =>
    req<{ ok: boolean }>('POST', `/manipulate/ws/${sessionId}/send`, { opcode, payload }),
  manipulateWSDisconnect: (sessionId: string) =>
    req<{ ok: boolean }>('POST', `/manipulate/ws/${sessionId}/disconnect`),

  // Fuzzer
  fuzzStart: (params: {
    raw: string; scheme: string; host: string;
    wordlist?: string[];
    wordlists?: Record<string, string[]>;
    attackMode?: string;
    threads: number; rateLimit: number; followRedirects: boolean;
    updateContentLength?: boolean;
    fuzzKeyword?: string;
    matchers: Array<{ type: string; value: string }>;
    filters: Array<{ type: string; value: string }>;
    matcherMode: string; filterMode: string;
    maxStoredBodies?: number;
  }) => req<{ campaignId: string; total: number }>('POST', '/fuzzer/start', params),
  fuzzStop: (id: string) => req<{ status: string }>('POST', `/fuzzer/${id}/stop`),
  fuzzListCampaigns: () => req<{ campaigns: Array<{ id: string; status: string; createdAt: string; total: number; completed: number; errors: number }> }>('GET', '/fuzzer/campaigns'),
  fuzzGetCampaign: (id: string, offset?: number, limit?: number) => {
    const params: Record<string, string | number> = {}
    if (offset) params.offset = offset
    if (limit) params.limit = limit
    const qs = new URLSearchParams(
      Object.entries(params).map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ id: string; status: string; total: number; completed: number; errors: number; results: unknown[]; resultTotal: number }>(
      'GET', `/fuzzer/campaigns/${id}${qs ? `?${qs}` : ''}`
    )
  },
  fuzzDeleteCampaign: (id: string) => req<unknown>('DELETE', `/fuzzer/campaigns/${id}`),
  fuzzGetResult: (campaignId: string, index: number) =>
    req<{ index: number; payload: string; payloads?: Record<string, string>; statusCode: number; size: number; words: number; lines: number; durationMs: number; url: string; error?: string; hasBody: boolean; reqRaw?: string; respRaw?: string }>(
      'GET', `/fuzzer/campaigns/${campaignId}/results/${index}`
    ),
  fuzzUploadWordlist: async (file: File) => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`${BASE}/fuzzer/wordlist`, { method: 'POST', body: form })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error((err as { error: string }).error || res.statusText)
    }
    return res.json() as Promise<{ lines: string[]; count: number }>
  },

  // Generate
  generate: (format: string, mode?: string, implantUrl?: string, binaryName?: string, inMemory?: boolean) =>
    req<{ fileName: string; authKey: string; content: string }>(
      'POST', '/generate', { format, mode: mode || 'webshell', implantUrl, binaryName, inMemory }),

  // Execute
  execute: (target: string, webshell: string, authKey: string, command: string) =>
    req<{ output: string; error: string }>('POST', '/execute', { target, webshell, authKey, command }),

  // Scope
  getScope: () => req<{ enabled: boolean; rules: ScopeRule[] }>('GET', '/scope'),
  setScopeEnabled: (enabled: boolean) => req<unknown>('PUT', '/scope/enabled', { enabled }),
  addScopeRule: (rule: Omit<ScopeRule, 'id'>) => req<ScopeRule>('POST', '/scope/rules', rule),
  deleteScopeRule: (id: string) => req<unknown>('DELETE', `/scope/rules/${id}`),
  importScopeRules: (
    config: { scopeEnabled?: boolean; scopeRules: Omit<ScopeRule, 'id'>[] },
    mode: 'replace' | 'merge',
  ) =>
    req<{ enabled: boolean; rules: ScopeRule[]; imported: number; skipped: number }>(
      'POST', '/scope/rules/import', { config, mode }),

  // Noise filter
  getNoise: () => req<{ enabled: boolean; patterns: NoisePattern[] }>('GET', '/noise'),
  setNoiseEnabled: (enabled: boolean) => req<unknown>('PUT', '/noise/enabled', { enabled }),
  addNoisePattern: (pattern: string) => req<NoisePattern>('POST', '/noise/patterns', { pattern }),
  deleteNoisePattern: (id: string) => req<unknown>('DELETE', `/noise/patterns/${id}`),

  // Match & Replace
  getReplace: () => req<{ enabled: boolean; rules: MatchReplaceRule[] }>('GET', '/replace'),
  setReplaceEnabled: (enabled: boolean) => req<unknown>('PUT', '/replace/enabled', { enabled }),
  addReplaceRule: (rule: Omit<MatchReplaceRule, 'id'>) => req<MatchReplaceRule>('POST', '/replace/rules', rule),
  deleteReplaceRule: (id: string) => req<unknown>('DELETE', `/replace/rules/${id}`),

  // Custom Data
  getCustomData: () => req<{ enabled: boolean; items: CustomAddition[] }>('GET', '/customdata'),
  setCustomDataEnabled: (enabled: boolean) => req<unknown>('PUT', '/customdata/enabled', { enabled }),
  addCustomDataItem: (item: Omit<CustomAddition, 'id'>) => req<CustomAddition>('POST', '/customdata/items', item),
  deleteCustomDataItem: (id: string) => req<unknown>('DELETE', `/customdata/items/${id}`),

  // WebSocket messages
  listWSMessages: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ items: CapturedWSMessage[]; total: number; offset: number; limit: number }>(
      'GET', `/ws/messages${qs ? `?${qs}` : ''}`
    )
  },
  clearWSMessages: () => req<unknown>('DELETE', '/ws/messages'),

  // Settings
  getSettings: () => req<unknown>('GET', '/settings'),
  updateSettings: (s: unknown) => req<unknown>('PUT', '/settings', s),

  // Config save/load
  listUserConfigs: () => req<{ configs: string[]; active: string }>('GET', '/configs/user'),
  saveUserConfig: (name: string, theme?: string, hiddenTabs?: string[], dashboardLayout?: unknown) => req<{ status: string; name: string }>('POST', '/configs/user', { name, theme, hiddenTabs, dashboardLayout }),
  loadUserConfig: (name: string) => req<unknown>('PUT', `/configs/user/${name}`),
  listProjectConfigs: () => req<{ configs: string[]; active: string; projects: ProjectMeta[] }>('GET', '/configs/project'),
  saveProjectConfig: (name: string) => req<{ status: string; name: string }>('POST', '/configs/project', { name }),
  loadProjectConfig: (name: string) => req<unknown>('PUT', `/configs/project/${name}`),
  deleteProjectConfig: (name: string) => req<unknown>('DELETE', `/configs/project/${name}`),
  switchProject: (name: string, opts?: { action?: 'save' | 'discard'; saveScratchAs?: string }) =>
    req<Record<string, unknown>>('POST', '/configs/project/switch', { name, ...(opts ?? {}) }),
  newProject: (name: string, opts: { empty: boolean; action?: 'save' | 'discard'; saveScratchAs?: string }) =>
    req<Record<string, unknown>>('POST', '/configs/project/new', { name, ...opts }),
  setProjectPrefs: (name: string, prefs: { autoSave?: boolean; saveHistory?: boolean }) =>
    req<{ ok: boolean; autoSave: boolean; saveHistory: boolean }>('POST', '/configs/project/prefs', { name, ...prefs }),

  // Certs
  caCertURL: () => `${BASE}/certs/ca.crt`,

  // Managed testing browser
  browserStatus: () => req<{ available: boolean; browser: string }>('GET', '/browser/status'),
  launchBrowser: (opts?: { url?: string }) =>
    req<{ status: string; browser: string; profile: string }>('POST', '/browser/launch', opts ?? {}),
  clearBrowserCookies: () =>
    req<{ status: string; profile: string }>('POST', '/browser/clear-cookies', {}),

  // Health check (first-run wizard)
  healthCheck: () =>
    req<{ proxyPort: number; uiPort: number; bindAddr: string; caPresent: boolean; browserAvailable: boolean; browserName: string; requestCount: number; activeProject: string }>(
      'GET', '/system/healthcheck'
    ),

  // System info
  systemInfo: () => req<{ hostname: string; ip: string }>('GET', '/system/info'),

  // Version / Update
  versionInfo: () => req<VersionInfo>('GET', '/system/version'),
  checkForUpdate: () => req<VersionInfo>('POST', '/system/check-update'),
  performUpdate: () => req<{ status: string }>('POST', '/system/update'),
  restart: () => req<{ status: string }>('POST', '/system/restart'),

  // Sliver C2
  sliverStatus: () => req<{ connected: boolean; lhost?: string; lport?: number; sessionId?: string; sessionName?: string }>('GET', '/sliver/status'),
  sliverConnect: (config: { operator: string; lhost: string; lport: number; ca_certificate: string; certificate: string; private_key: string }) =>
    req<{ connected: boolean }>('POST', '/sliver/connect', config),
  sliverDisconnect: () =>
    req<{ connected: boolean }>('POST', '/sliver/disconnect'),
  sliverSessions: () =>
    req<{ sessions: { id: string; name: string; hostname: string; os: string; arch: string; remoteAddress: string; transport: string; username: string; version: string }[]; beacons: { id: string; name: string; hostname: string; os: string; arch: string; remoteAddress: string; transport: string; username: string }[] }>('GET', '/sliver/sessions'),
  sliverExecute: (sessionId: string, command: string, args: string[]) =>
    req<{ output: string; error: string }>('POST', '/sliver/execute', { sessionId, command, args }),
  sliverCommand: (input: string) =>
    req<{ output: string; error: string; downloadId?: string; filename?: string; sessionChanged?: boolean; sessionId?: string; sessionName?: string; disconnected?: boolean }>('POST', '/sliver/command', { input }),
  sliverUpload: async (remotePath: string, file: File) => {
    const form = new FormData()
    form.append('file', file)
    form.append('remotePath', remotePath)
    const res = await fetch(`${BASE}/sliver/upload`, { method: 'POST', body: form })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error((err as { error: string }).error || res.statusText)
    }
    return res.json() as Promise<{ path: string }>
  },

  // Mythic C2
  mythicStatus: () => req<{ connected: boolean; url?: string; callbackId?: number; callbackName?: string }>('GET', '/mythic/status'),
  mythicConnect: (config: { url: string; username?: string; password?: string; apiToken?: string }) =>
    req<{ connected: boolean }>('POST', '/mythic/connect', config),
  mythicDisconnect: () =>
    req<{ connected: boolean }>('POST', '/mythic/disconnect'),
  mythicCallbacks: () =>
    req<{ callbacks: { id: number; display_id: number; user: string; host: string; pid: number; ip: string; os: string; architecture: string; last_checkin: string; description: string; payload_type: string }[] }>('GET', '/mythic/callbacks'),
  mythicCommand: (input: string) =>
    req<{ output: string; error: string; downloadId?: string; filename?: string; callbackChanged?: boolean; callbackId?: number; callbackName?: string; disconnected?: boolean }>('POST', '/mythic/command', { input }),
  mythicUpload: async (remotePath: string, file: File) => {
    const form = new FormData()
    form.append('file', file)
    form.append('remotePath', remotePath)
    const res = await fetch(`${BASE}/mythic/upload`, { method: 'POST', body: form })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error((err as { error: string }).error || res.statusText)
    }
    return res.json() as Promise<{ path: string }>
  },

  // Notes
  listNoteHosts: () => req<string[]>('GET', '/notes/hosts'),
  listNotes: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ items: Note[]; total: number; offset: number; limit: number }>(
      'GET', `/notes${qs ? `?${qs}` : ''}`
    )
  },
  createNote: (host: string, content: string, author?: string) =>
    req<Note>('POST', '/notes', { host, content, ...(author ? { author } : {}) }),
  updateNote: (id: string, content: string) => req<Note>('PUT', `/notes/${id}`, { content }),
  deleteNote: (id: string) => req<unknown>('DELETE', `/notes/${id}`),

  // Mode
  getMode: () => req<{ mode: string; sessionId: string }>('GET', '/mode'),

  // Callbacks
  listTokens: () => req<CallbackToken[]>('GET', '/callbacks/tokens', undefined, TEAM_POLL_TIMEOUT),
  createToken: (note: string) => req<CallbackToken>('POST', '/callbacks/tokens', { note }),
  deleteToken: (id: string) => req<unknown>('DELETE', `/callbacks/tokens/${id}`),
  listInteractions: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ items: CallbackInteraction[]; total: number; offset: number; limit: number }>(
      'GET', `/callbacks/interactions${qs ? `?${qs}` : ''}`, undefined, TEAM_POLL_TIMEOUT
    )
  },
  clearInteractions: (tokenId?: string) =>
    req<unknown>('DELETE', `/callbacks/interactions${tokenId ? `?token_id=${tokenId}` : ''}`),
  getCallbackConfig: () => req<{ domain: string; responseIp: string }>('GET', '/callbacks/config'),
  updateCallbackConfig: (cfg: { domain: string; responseIp: string }) =>
    req<{ domain: string; responseIp: string }>('PUT', '/callbacks/config', cfg),

  // XSS Hunter
  listProbes: () => req<XSSProbe[]>('GET', '/xss/probes', undefined, TEAM_POLL_TIMEOUT),
  createProbe: (name: string) => req<XSSProbe>('POST', '/xss/probes', { name }),
  deleteProbe: (id: string) => req<unknown>('DELETE', `/xss/probes/${id}`),
  getPayloads: (id: string) => req<PayloadVariant[]>('GET', `/xss/probes/${id}/payloads`),
  listFires: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ items: XSSFire[]; total: number; offset: number; limit: number }>(
      'GET', `/xss/fires${qs ? `?${qs}` : ''}`, undefined, TEAM_POLL_TIMEOUT
    )
  },
  getFire: (id: string) => req<XSSFire>('GET', `/xss/fires/${id}`),
  deleteFire: (id: string) => req<unknown>('DELETE', `/xss/fires/${id}`),
  clearFires: (probeId?: string) =>
    req<unknown>('DELETE', `/xss/fires${probeId ? `?probe_id=${probeId}` : ''}`),
  updateProbe: (id: string, body: { collectPages: string[]; chainloadUri: string }) =>
    req<XSSProbe>('PUT', `/xss/probes/${id}`, body),
  listCollectedPages: (fireId: string) =>
    req<CollectedPageSummary[]>('GET', `/xss/fires/${fireId}/pages`),
  getCollectedPage: (id: string) =>
    req<CollectedPage>('GET', `/xss/pages/${id}`),
  getXSSConfig: () => req<XSSConfig>('GET', '/xss/config'),
  updateXSSConfig: (cfg: XSSConfig) => req<XSSConfig>('PUT', '/xss/config', cfg),

  // Team
  listChatMessages: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ items: ChatMessage[]; total: number; offset: number; limit: number }>(
      'GET', `/team/chat${qs ? `?${qs}` : ''}`, undefined, TEAM_POLL_TIMEOUT
    )
  },
  sendChatMessage: (text: string, refType?: 'action') =>
    req<ChatMessage>('POST', '/team/chat', { text, ...(refType ? { refType } : {}) }),
  listActiveUsers: () => req<ActiveUser[]>('GET', '/team/users', undefined, TEAM_POLL_TIMEOUT),
  updatePresence: (payload: { status: string; project: string }) =>
    req<{ status: string }>('POST', '/team/presence', payload),
  listTeamNoteHosts: () => req<string[]>('GET', '/team/notes/hosts', undefined, TEAM_POLL_TIMEOUT),
  listTeamNotes: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ items: Note[]; total: number; offset: number; limit: number }>(
      'GET', `/team/notes${qs ? `?${qs}` : ''}`, undefined, TEAM_POLL_TIMEOUT
    )
  },
  createTeamNote: (host: string, content: string) =>
    req<Note>('POST', '/team/notes', { host, content }),
  updateTeamNote: (id: string, content: string) => req<Note>('PUT', `/team/notes/${id}`, { content }),
  deleteTeamNote: (id: string) => req<unknown>('DELETE', `/team/notes/${id}`),
  flagRequest: (payload: {
    host: string
    method: string
    url: string
    status: number
    reqRaw: string
    respRaw: string
    note?: string
  }) => req<FlaggedSummary>('POST', '/team/flagged', payload),
  listFlagged: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ items: FlaggedSummary[]; total: number; offset: number; limit: number }>(
      'GET', `/team/flagged${qs ? `?${qs}` : ''}`, undefined, TEAM_POLL_TIMEOUT
    )
  },
  getFlagged: (id: string) => req<FlaggedRequest>('GET', `/team/flagged/${id}`),
  deleteFlagged: (id: string) => req<unknown>('DELETE', `/team/flagged/${id}`),

  // Shared project configs (Feature A) + collaboration (Feature B)
  exportProjectConfig: () => req<{ config: string }>('GET', '/configs/export'),
  importProjectConfig: (name: string, config: string) =>
    req<Record<string, unknown>>('POST', '/configs/import', { name, config }),
  applySharedConfig: (config: SharedConfigPayload, mode: 'replace' | 'merge') =>
    req<Record<string, unknown>>('POST', '/configs/apply-shared', { config, mode }),
  publishConfig: (payload: { name: string; project: string; config: string }) =>
    req<SharedConfigSummary>('POST', '/team/configs', payload),
  listSharedConfigs: () => req<{ items: SharedConfigSummary[] }>('GET', '/team/configs', undefined, TEAM_POLL_TIMEOUT),
  getSharedConfig: (id: string) => req<SharedConfig>('GET', `/team/configs/${id}`),
  deleteSharedConfig: (id: string) => req<unknown>('DELETE', `/team/configs/${id}`),
  requestCollab: (payload: { project: string; note: string; config: string }) =>
    req<CollabRequest>('POST', '/team/collab', payload),
  getCollab: (id: string) => req<CollabRequest>('GET', `/team/collab/${id}`),
  acceptCollab: (id: string) => req<{ status: string }>('POST', `/team/collab/${id}/accept`, {}),
  gatherCurrentRules: async (): Promise<SharedConfigPayload> => {
    const [scope, replace, custom, detect] = await Promise.all([
      api.getScope(),
      api.getReplace(),
      api.getCustomData(),
      // Detection is unavailable in listener mode, so a failure here must not
      // block the bundle.
      api.listDetectRules().catch(() => null),
    ])
    return {
      scopeEnabled: scope.enabled,
      scopeRules: scope.rules.map(({ pattern, methods, path, include }) => ({ pattern, methods, path, include })),
      replaceEnabled: replace.enabled,
      replaceRules: replace.rules.map(({ target, matchType, match, replace }) => ({ target, matchType, match, replace })),
      customDataEnabled: custom.enabled,
      customDataItems: custom.items.map(({ type, name, value }) => ({ type, name, value })),
      // Only custom rules travel; built-ins exist on every install.
      detectRules: (detect?.rules ?? [])
        .filter((r) => !r.builtin)
        .map((r) => ({ ...r, id: undefined })),
    }
  },

  // Interact plugins
  listInteractProviders: () => req<InteractProviderMeta[]>('GET', '/plugins/interact-providers'),
  listInteractInstances: (plugin: string) =>
    req<InteractInstance[]>('GET', `/plugin/${plugin}/interact/instances`),
  createInteractInstance: (plugin: string, config: Record<string, string>) =>
    req<InteractInstance>('POST', `/plugin/${plugin}/interact/instances`, config),
  deleteInteractInstance: (plugin: string, id: string) =>
    req<unknown>('DELETE', `/plugin/${plugin}/interact/instances/${id}`),
  setInteractInstanceEnabled: (plugin: string, id: string, enabled: boolean) =>
    req<unknown>('PUT', `/plugin/${plugin}/interact/instances/${id}/enabled`, { enabled }),
  listInteractInteractions: (plugin: string, params?: { instanceId?: string; limit?: number; offset?: number }) => {
    const qs = new URLSearchParams()
    if (params?.instanceId) qs.set('instance_id', params.instanceId)
    if (params?.limit) qs.set('limit', String(params.limit))
    if (params?.offset) qs.set('offset', String(params.offset))
    const s = qs.toString()
    return req<{ items: InteractInteraction[]; total: number; offset: number; limit: number }>(
      'GET', `/plugin/${plugin}/interact/interactions${s ? `?${s}` : ''}`
    )
  },
  clearInteractInteractions: (plugin: string, instanceId?: string) => {
    const qs = instanceId ? `?instance_id=${encodeURIComponent(instanceId)}` : ''
    return req<unknown>('DELETE', `/plugin/${plugin}/interact/interactions${qs}`)
  },

  // Detect (passive vulnerability detection)
  getDetect: () =>
    req<{
      enabled: boolean
      config: DetectConfig
      summary: DetectSummary
      scan: ScanState
      cursor: number
      ruleCount: number
      activeRules: number
    }>('GET', '/detect'),
  setDetectEnabled: (enabled: boolean) =>
    req<{ enabled: boolean }>('PUT', '/detect/enabled', { enabled }),
  getDetectConfig: () => req<DetectConfig>('GET', '/detect/config'),
  updateDetectConfig: (patch: Partial<DetectConfig>) =>
    req<DetectConfig>('PUT', '/detect/config', patch),

  listFindings: (params: Record<string, string | number>) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== 0)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<{ items: Finding[]; total: number; offset: number; limit: number }>(
      'GET',
      `/detect/findings${qs ? `?${qs}` : ''}`
    )
  },
  getFinding: (id: string) =>
    req<{
      finding: Finding
      notes: string
      occurrences: FindingOccurrence[]
      rule: DetectRule | null
    }>('GET', `/detect/findings/${id}`),
  updateFinding: (
    id: string,
    patch: { falsePositive?: boolean; notes?: string; severity?: string }
  ) => req<Finding>('PUT', `/detect/findings/${id}`, patch),
  deleteFinding: (id: string) => req<unknown>('DELETE', `/detect/findings/${id}`),
  clearFindings: (onlyFalsePositives = false) =>
    req<{ deleted: number }>(
      'DELETE',
      `/detect/findings${onlyFalsePositives ? '?fp=true' : ''}`
    ),

  listDetectRules: () =>
    req<{
      rules: DetectRule[]
      builtinCount: number
      userCount: number
      activeCount: number
      categories: string[]
      postFilters: string[]
    }>('GET', '/detect/rules'),
  addDetectRule: (rule: Partial<DetectRule>) =>
    req<DetectRule>('POST', '/detect/rules', rule),
  updateDetectRule: (id: string, rule: Partial<DetectRule>) =>
    req<DetectRule>('PUT', `/detect/rules/${id}`, rule),
  deleteDetectRule: (id: string) => req<unknown>('DELETE', `/detect/rules/${id}`),
  setDetectRuleEnabled: (id: string, enabled: boolean) =>
    req<unknown>('PUT', `/detect/rules/${id}/enabled`, { enabled }),
  setDetectRuleSeverity: (id: string, severity: string) =>
    req<unknown>('PUT', `/detect/rules/${id}/severity`, { severity }),
  resetDetectRule: (id: string) => req<DetectRule>('POST', `/detect/rules/${id}/reset`),
  testDetectRule: (body: {
    pattern: string
    sample: string
    captureGroup?: number
    minEntropy?: number
    minLength?: number
  }) =>
    req<{
      valid: boolean
      error?: string
      groups?: number
      truncated?: boolean
      matches?: {
        match: string
        redacted: string
        offset: number
        length: number
        entropy: number
        passes: boolean
      }[]
    }>('POST', '/detect/rules/test', body),

  startDetectScan: (opts?: { scope?: string; host?: string; purge?: boolean }) =>
    req<ScanState>('POST', '/detect/scan', opts ?? {}),
  getDetectScan: () => req<ScanState>('GET', '/detect/scan'),
  cancelDetectScan: () => req<{ status: string }>('POST', '/detect/scan/cancel'),

  // Highlights
  getHighlights: () => req<{ highlights: Record<string, string> }>('GET', '/highlights'),
  setHighlight: (id: string, color: string) => req<unknown>('PUT', `/highlights/${id}`, { color }),
  clearHighlights: () => req<unknown>('DELETE', '/highlights'),

  // Plugins
  listPlugins: () => req<PluginInfo[]>('GET', '/plugins'),
  uploadPlugin: async (file: File): Promise<{ filename: string; message: string }> => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`${BASE}/plugins/upload`, { method: 'POST', body: form })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error((err as { error: string }).error || res.statusText)
    }
    return res.json() as Promise<{ filename: string; message: string }>
  },
  deletePlugin: (filename: string) =>
    req<{ filename: string; message: string }>('DELETE', `/plugins/${encodeURIComponent(filename)}`),
  listExecProviders: () => req<ExecProviderInfo[]>('GET', '/plugins/exec-providers'),
  pluginGraph: () => req<Record<string, PluginGraphInfo>>('GET', '/plugins/graph'),
  pluginConnect: (name: string, config: Record<string, string>) =>
    req<{ connected: boolean }>('POST', `/plugin/${name}/connect`, config),
  pluginDisconnect: (name: string) =>
    req<{ connected: boolean }>('POST', `/plugin/${name}/disconnect`),
  pluginStatus: (name: string) =>
    req<PluginProviderStatus>('GET', `/plugin/${name}/status`),
  pluginCommand: (name: string, input: string) =>
    req<PluginCommandResult>('POST', `/plugin/${name}/command`, { input }),

  // Automation. These are UI-only by design: an automation client reaches Joro on
  // the separate MCP port, whose mux has no /api/v1 routes, so no bearer token can
  // reach token or grant management. They 404 with a JSON body when automation is
  // disabled (--no-automation), which callers should treat as "feature absent"
  // rather than an error worth surfacing.
  listAutomationTokens: () =>
    req<{ tokens: AutomationToken[] }>('GET', '/automation/tokens'),
  createAutomationToken: (body: AutomationTokenInput) =>
    req<{ token: AutomationToken; secret: string }>('POST', '/automation/tokens', body),
  updateAutomationToken: (id: string, body: Partial<AutomationTokenInput>) =>
    req<{ token: AutomationToken }>('PUT', `/automation/tokens/${id}`, body),
  rotateAutomationToken: (id: string) =>
    req<{ token: AutomationToken; secret: string }>('POST', `/automation/tokens/${id}/rotate`),
  setAutomationTokenEnabled: (id: string, enabled: boolean) =>
    req<{ token: AutomationToken }>('PUT', `/automation/tokens/${id}/enabled`, { enabled }),
  reviewAutomationToken: (id: string) =>
    req<{ token: AutomationToken }>('POST', `/automation/tokens/${id}/reviewed`),
  revokeAutomationToken: (id: string) =>
    req<{ status: string }>('DELETE', `/automation/tokens/${id}`),
  listCapabilities: () =>
    req<{
      capabilities: Capability[]
      fingerprint: string
      classes: string[]
      profiles: AutomationProfile[]
    }>('GET', '/automation/capabilities'),
  listScriptRuns: (params: { limit?: number } = {}) =>
    req<{ runs: ScriptRun[]; total: number; offset: number; limit: number }>(
      'GET',
      `/automation/runs${params.limit ? `?limit=${params.limit}` : ''}`
    ),
  getScriptRun: (id: string) => req<ScriptRun>('GET', `/automation/runs/${id}`),
  clearScriptRuns: () => req<{ deleted: number }>('DELETE', '/automation/runs'),

  listScripts: () =>
    req<{ scripts: AutomationSummary[]; triggers: string[]; bundle: string }>(
      'GET',
      '/automation/scripts'
    ),
  getScript: (id: string) => req<AutomationPackage>('GET', `/automation/scripts/${id}`),
  installScript: (manifest: AutomationManifest, source: string) =>
    req<AutomationPackage>('POST', '/automation/scripts', { manifest, source }),
  updateScript: (id: string, manifest: AutomationManifest, source: string, expectedHash?: string) =>
    req<AutomationPackage>('PUT', `/automation/scripts/${id}`, { manifest, source, expectedHash }),
  deleteScript: (id: string) => req<{ status: string }>('DELETE', `/automation/scripts/${id}`),
  setScriptEnabled: (id: string, enabled: boolean) =>
    req<AutomationSummary>('PUT', `/automation/scripts/${id}/enabled`, { enabled }),
  setScriptPrefs: (
    id: string,
    prefs: {
      limits?: AutomationLimits
      triggersDisabled?: Record<string, boolean>
      hostAllow?: string[]
      lensLabel?: string
      lensPart?: string
      lensOrder?: number
    }
  ) =>
    req<AutomationSummary>('PUT', `/automation/scripts/${id}/prefs`, prefs),
  // No client timeout below the server's: a run may legitimately last as long as the
  // operator's wall-clock budget allows, and aborting here would leave them with no
  // report while the run carried on. Keep this above jsruntime.CapTimeout (10 minutes),
  // which is the longest wall clock the budget can be set to.
  runScript: (body: {
    scriptId?: string
    source?: string
    input?: unknown
    /** Labels the run in the log; 'lens' also strips the send capabilities. */
    trigger?: string
    timeoutMs?: number
  }) => req<ScriptRun>('POST', '/automation/runs', body, 630_000),
  getScriptSdk: () =>
    req<{
      bundle: string
      methods: SdkMethod[]
      storage: { js: string; description: string }[]
      globals: { js: string; description: string }[]
      triggers: string[]
    }>('GET', '/automation/sdk'),
  getAutomationLimits: () => req<AutomationBudget>('GET', '/automation/limits'),
  setAutomationLimits: (policy: AutomationPolicy) =>
    req<AutomationBudget>('PUT', '/automation/limits', { policy }),
  getMcpState: () => req<McpState>('GET', '/automation/mcp'),
  setMcpState: (body: { enabled?: boolean; port?: number }) =>
    req<McpState>('PUT', '/automation/mcp', body),
  listAutomationAudit: (params: { tokenId?: string; result?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== '' && v !== undefined)
        .map(([k, v]) => [k, String(v)])
    ).toString()
    return req<AutomationAudit>('GET', `/automation/audit${qs ? `?${qs}` : ''}`)
  },
  clearAutomationAudit: () => req<{ deleted: number }>('DELETE', '/automation/audit'),
}
