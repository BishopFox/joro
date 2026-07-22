import type { CallbackInteraction, CallbackToken } from '../stores/callbackStore'
import type { ChatMessage, ActiveUser } from '../stores/teamStore'
import type { FlaggedSummary, FlaggedRequest } from '../stores/teamFlaggedStore'
import type { SharedConfigSummary, SharedConfig, SharedConfigPayload } from '../stores/teamSharedConfigStore'

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
  getSitemap: () => req<{ hosts: SitemapHost[] }>('GET', '/sitemap'),

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
  getIntercept: () => req<{ enabled: boolean; items: unknown[] }>('GET', '/intercept'),
  setInterceptEnabled: (enabled: boolean) => req<unknown>('PUT', '/intercept/enabled', { enabled }),
  forwardRequest: (id: string, reqRaw?: string) =>
    req<unknown>('POST', `/intercept/${id}/forward`, reqRaw ? { reqRaw } : {}),
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
  saveUserConfig: (name: string, theme?: string, hiddenTabs?: string[]) => req<{ status: string; name: string }>('POST', '/configs/user', { name, theme, hiddenTabs }),
  loadUserConfig: (name: string) => req<unknown>('PUT', `/configs/user/${name}`),
  deleteUserConfig: (name: string) => req<unknown>('DELETE', `/configs/user/${name}`),
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
    const [scope, replace, custom] = await Promise.all([
      api.getScope(),
      api.getReplace(),
      api.getCustomData(),
    ])
    return {
      scopeEnabled: scope.enabled,
      scopeRules: scope.rules.map(({ pattern, methods, path, include }) => ({ pattern, methods, path, include })),
      replaceEnabled: replace.enabled,
      replaceRules: replace.rules.map(({ target, matchType, match, replace }) => ({ target, matchType, match, replace })),
      customDataEnabled: custom.enabled,
      customDataItems: custom.items.map(({ type, name, value }) => ({ type, name, value })),
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
}
