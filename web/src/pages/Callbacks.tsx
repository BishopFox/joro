import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { api, type InteractInteraction, type InteractInstance, type InteractProviderMeta } from '../lib/api'
import { useCallbackStore, type CallbackInteraction } from '../stores/callbackStore'
import { useXSSHunterStore, type XSSFire, type CollectedPageSummary, type CollectedPage } from '../stores/xssHunterStore'
import { useSettingsStore, type Settings } from '../stores/settingsStore'
import { onPluginEvent } from '../lib/ws'

function b64Decode(s: string) {
  try { return atob(s) } catch { return s }
}

function copy(text: string) { navigator.clipboard.writeText(text) }

type UnifiedEvent = {
  id: string
  kind: string
  hex: string
  sourceIp: string
  detail: string
  timestamp: string
  interaction?: CallbackInteraction
  fire?: XSSFire
}

export default function Callbacks() {
  // Callback store
  const {
    tokens, interactions, interactionsTotal,
    selectedInteraction,
    setTokens, setInteractions, clearInteractions,
    addToken, removeToken, setSelectedInteraction,
  } = useCallbackStore()

  // XSS store
  const {
    probes, fires, firesTotal,
    selectedFire, payloads,
    setProbes, addProbe, removeProbe,
    setFires, clearFires,
    setSelectedFire, setPayloads,
  } = useXSSHunterStore()

  const { setSettings } = useSettingsStore()

  // Interact plugins (providers + their instances + creation-form state)
  const [providers, setProviders] = useState<InteractProviderMeta[]>([])
  const providersRef = useRef<InteractProviderMeta[]>([])
  providersRef.current = providers
  const [pluginInstances, setPluginInstances] = useState<Record<string, InteractInstance[]>>({})
  const [pluginValues, setPluginValues] = useState<Record<string, Record<string, string>>>({})
  const [pluginLoading, setPluginLoading] = useState<Record<string, boolean>>({})
  const [pluginError, setPluginError] = useState<Record<string, string>>({})

  // Config state
  const [listenerUrl, setListenerUrl] = useState('')
  const [listenerSaved, setListenerSaved] = useState(false)
  const [listenerError, setListenerError] = useState('')
  const [callbackDomain, setCallbackDomain] = useState('')

  // Token creation state
  const [tokenNote, setTokenNote] = useState('')
  const [tokenLoading, setTokenLoading] = useState(false)
  const [tokenError, setTokenError] = useState('')
  const [tokenCreated, setTokenCreated] = useState(false)

  // Probe creation state
  const [probeName, setProbeName] = useState('')
  const [probeLoading, setProbeLoading] = useState(false)
  const [probeError, setProbeError] = useState('')

  // Detail state
  const [fireDetail, setFireDetail] = useState<XSSFire | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Sidebar probe expansion (show payloads inline)
  const [expandedProbe, setExpandedProbe] = useState<string | null>(null)

  // Probe config editing state
  const [probeCollectPages, setProbeCollectPages] = useState('')
  const [probeChainloadUri, setProbeChainloadUri] = useState('')
  const [probeConfigSaved, setProbeConfigSaved] = useState(false)

  // Collected pages state
  const [collectedPages, setCollectedPages] = useState<CollectedPageSummary[]>([])
  const [selectedPage, setSelectedPage] = useState<CollectedPage | null>(null)

  // Load initial data + poll tokens, probes, interactions, fires every 15s
  useEffect(() => {
    api.getSettings().then((s) => {
      const st = s as Settings
      setSettings(st)
      setListenerUrl(st.listenerUrl || '')
    })
    api.listTokens().then(setTokens)
    api.listProbes().then(setProbes).catch(() => {})
    api.getCallbackConfig().then((cfg) => {
      setCallbackDomain(cfg.domain || '')
    }).catch(() => {})
    loadInteractProviders().then(() => {
      loadInteractions()
    })
    loadFires()

    const interval = setInterval(() => {
      api.listTokens().then(setTokens)
      api.listProbes().then(setProbes).catch(() => {})
      loadPluginInstances(providersRef.current)
      loadInteractions()
      loadFires()
    }, 15000)
    return () => clearInterval(interval)
  }, []) // eslint-disable-line

  // Stream live plugin interactions into the event feed without waiting for the
  // 15s poll. The plugin broadcasts `plugin.{name}.interaction` on its scoped
  // channel; ws.ts dispatches it to our onPluginEvent subscription.
  useEffect(() => {
    const unsub = onPluginEvent((msg) => {
      const m = /^plugin\.([^.]+)\.interaction$/.exec(msg.type)
      if (!m) return
      const ix = msg.data as InteractInteraction
      const ci = mapPluginInteractionToCallback(m[1], ix)
      useCallbackStore.getState().addInteraction(ci)
    })
    return unsub
  }, [])

  async function loadInteractProviders() {
    try {
      const ps = await api.listInteractProviders()
      setProviders(ps)
      await loadPluginInstances(ps)
    } catch {
      setProviders([])
    }
  }

  async function loadPluginInstances(ps: InteractProviderMeta[]) {
    if (ps.length === 0) {
      setPluginInstances({})
      return
    }
    const entries = await Promise.all(
      ps.map((p) =>
        api.listInteractInstances(p.name)
          .then((list) => [p.name, list] as const)
          .catch(() => [p.name, [] as InteractInstance[]] as const)
      )
    )
    setPluginInstances(Object.fromEntries(entries))
  }

  function mapPluginInteractionToCallback(provider: string, ix: InteractInteraction): CallbackInteraction {
    const proto = ix.protocol.toLowerCase()
    const ci: CallbackInteraction = {
      id: ix.id,
      tokenId: ix.instanceId,
      token: ix.hex,
      type: proto,
      sourceIp: ix.sourceIp,
      timestamp: ix.timestamp,
      source: `plugin:${provider}`,
    }
    if (proto === 'dns') {
      ci.queryName = ix.queryName
      ci.queryType = ix.queryType
    } else if (proto === 'http') {
      if (ix.method) ci.method = ix.method
      if (ix.path) ci.path = ix.path
      if (ix.rawRequest) ci.rawRequest = ix.rawRequest
    } else if (ix.rawRequest) {
      ci.rawRequest = ix.rawRequest
    }
    return ci
  }

  async function loadInteractions() {
    const ps = providersRef.current
    const [cbData, ...perPlugin] = await Promise.all([
      api.listInteractions({ limit: 200 }),
      ...ps.map((p) =>
        api.listInteractInteractions(p.name, { limit: 200 })
          .then((d) => ({ provider: p.name, items: d.items || [], total: d.total }))
          .catch(() => ({ provider: p.name, items: [] as InteractInteraction[], total: 0 }))
      ),
    ])
    const pluginMapped = perPlugin.flatMap((x) =>
      x.items.map((ix) => mapPluginInteractionToCallback(x.provider, ix))
    )
    const pluginTotal = perPlugin.reduce((s, x) => s + x.total, 0)
    const merged = [...cbData.items, ...pluginMapped]
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 200)
    setInteractions(merged, cbData.total + pluginTotal)
  }

  async function loadFires() {
    const data = await api.listFires({ limit: 200 }).catch(() => null)
    if (data) setFires(data.items, data.total)
  }

  // Load full fire detail and collected pages when selected fire changes
  useEffect(() => {
    if (selectedFire) {
      api.getFire(selectedFire.id).then(setFireDetail).catch(() => setFireDetail(null))
      api.listCollectedPages(selectedFire.id).then(setCollectedPages).catch(() => setCollectedPages([]))
      setSelectedPage(null)
    } else {
      setFireDetail(null)
      setCollectedPages([])
      setSelectedPage(null)
    }
  }, [selectedFire]) // eslint-disable-line

  // Load payloads and probe config when a probe is expanded
  useEffect(() => {
    if (expandedProbe) {
      api.getPayloads(expandedProbe).then(setPayloads).catch(() => setPayloads([]))
      const probe = probes.find((p) => p.id === expandedProbe)
      if (probe) {
        let pages: string[] = []
        try { pages = JSON.parse(probe.collectPages || '[]') } catch { /* ignore */ }
        setProbeCollectPages(pages.join('\n'))
        setProbeChainloadUri(probe.chainloadUri || '')
      }
    } else {
      setPayloads([])
    }
  }, [expandedProbe]) // eslint-disable-line

  // Unified event feed
  const events = useMemo<UnifiedEvent[]>(() => {
    const items: UnifiedEvent[] = []
    for (const i of interactions) {
      items.push({
        id: i.id,
        kind: i.type,
        hex: i.token,
        sourceIp: i.sourceIp,
        detail: i.type === 'dns' ? `${i.queryType} ${i.queryName}` : i.type === 'http' ? `${i.method} ${i.path}` : i.token,
        timestamp: i.timestamp,
        interaction: i,
      })
    }
    for (const f of fires) {
      items.push({
        id: f.id,
        kind: 'xss',
        hex: f.probeToken,
        sourceIp: f.sourceIp,
        detail: f.pageTitle ? `${f.url} — ${f.pageTitle}` : f.url,
        timestamp: f.firedAt,
        fire: f,
      })
    }
    items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    return items
  }, [interactions, fires])

  // Handlers
  const domain = callbackDomain

  function payloadUrl(tokenHex: string) {
    const host = domain ? `${tokenHex}.${domain}` : `${tokenHex}.<not configured>`
    return `http://${host}`
  }

  async function handleSaveConfig() {
    setListenerError('')
    try {
      const updated = await api.updateSettings({ listenerUrl })
      setSettings(updated as Settings)
      setListenerSaved(true)
      window.setTimeout(() => setListenerSaved((s) => s ? false : s), 3000)
    } catch (e) {
      setListenerError(e instanceof Error ? e.message : String(e))
    }
  }

  async function handleCreateToken() {
    setTokenLoading(true)
    setTokenError('')
    setTokenCreated(false)
    try {
      const token = await api.createToken(tokenNote.trim())
      addToken(token)
      setTokenNote('')
      copy(payloadUrl(token.token))
      setTokenCreated(true)
      window.setTimeout(() => setTokenCreated((s) => s ? false : s), 2000)
    } catch (e) {
      setTokenError(e instanceof Error ? e.message : String(e))
    } finally {
      setTokenLoading(false)
    }
  }

  async function handleDeleteToken(id: string) {
    await api.deleteToken(id)
    removeToken(id)
  }

  async function handleAddPluginInstance(plugin: string) {
    const config = pluginValues[plugin] || {}
    setPluginLoading((m) => ({ ...m, [plugin]: true }))
    setPluginError((m) => ({ ...m, [plugin]: '' }))
    try {
      const inst = await api.createInteractInstance(plugin, config)
      setPluginInstances((m) => ({ ...m, [plugin]: [...(m[plugin] || []), inst] }))
      setPluginValues((m) => ({ ...m, [plugin]: {} }))
    } catch (e) {
      setPluginError((m) => ({ ...m, [plugin]: e instanceof Error ? e.message : String(e) }))
    } finally {
      setPluginLoading((m) => ({ ...m, [plugin]: false }))
    }
  }

  async function handleDeletePluginInstance(plugin: string, id: string) {
    try {
      await api.deleteInteractInstance(plugin, id)
      setPluginInstances((m) => ({ ...m, [plugin]: (m[plugin] || []).filter((i) => i.id !== id) }))
    } catch { /* ignore */ }
  }

  async function handleTogglePluginInstance(plugin: string, id: string, enabled: boolean) {
    try {
      await api.setInteractInstanceEnabled(plugin, id, enabled)
      const list = await api.listInteractInstances(plugin).catch(() => null)
      if (list) setPluginInstances((m) => ({ ...m, [plugin]: list }))
    } catch { /* ignore */ }
  }

  function setPluginValue(plugin: string, field: string, value: string) {
    setPluginValues((m) => ({ ...m, [plugin]: { ...(m[plugin] || {}), [field]: value } }))
  }

  async function handleCreateProbe() {
    setProbeLoading(true)
    setProbeError('')
    try {
      const probe = await api.createProbe(probeName.trim())
      addProbe(probe)
      setProbeName('')
      setExpandedProbe(probe.id)
    } catch (e) {
      setProbeError(e instanceof Error ? e.message : String(e))
    } finally {
      setProbeLoading(false)
    }
  }

  async function handleDeleteProbe(id: string) {
    await api.deleteProbe(id)
    removeProbe(id)
    if (expandedProbe === id) setExpandedProbe(null)
  }

  async function handleSaveProbeConfig(probeId: string) {
    const pages = probeCollectPages.split('\n').map((s) => s.trim()).filter(Boolean)
    try {
      const updated = await api.updateProbe(probeId, { collectPages: pages, chainloadUri: probeChainloadUri })
      setProbes(probes.map((p) => p.id === probeId ? updated : p))
      setProbeConfigSaved(true)
      setTimeout(() => setProbeConfigSaved(false), 2000)
    } catch { /* ignore */ }
  }

  async function handleViewCollectedPage(pageId: string) {
    try {
      const page = await api.getCollectedPage(pageId)
      setSelectedPage(page)
    } catch { /* ignore */ }
  }

  async function handleClearAll() {
    // Every backend clear is wrapped in .catch because the built-in callback
    // and XSS fire endpoints 503 when no listener URL is configured — an
    // unrelated error must not block plugin clears or the local UI reset.
    await Promise.all([
      api.clearInteractions().catch(() => undefined),
      api.clearFires().catch(() => undefined),
      ...providersRef.current.map((p) => api.clearInteractInteractions(p.name).catch(() => undefined)),
    ])
    clearInteractions()
    clearFires()
  }

  function handleCopyPayload(payload: string, name: string) {
    copy(payload)
    setCopiedId(name)
    setTimeout(() => setCopiedId((s) => s === name ? null : s), 1500)
  }

  function selectEvent(ev: UnifiedEvent) {
    if (ev.interaction) {
      setSelectedInteraction(ev.interaction)
      setSelectedFire(null)
      setFireDetail(null)
    } else if (ev.fire) {
      setSelectedFire(ev.fire)
      setSelectedInteraction(null)
    }
  }

  const selectedId = selectedInteraction?.id ?? selectedFire?.id ?? null

  function typeBadge(kind: string) {
    const colors: Record<string, string> = {
      dns: 'text-semantic-info',
      http: 'text-semantic-warning',
      xss: 'text-semantic-special',
      smtp: 'text-accent-tertiary',
      ftp: 'text-accent-tertiary',
      ldap: 'text-accent-tertiary',
      smb: 'text-accent-tertiary',
    }
    const color = colors[kind] || 'text-content-secondary'
    return <span className={`font-bold uppercase ${color}`}>{kind}</span>
  }

  function renderInteractionDetail(item: CallbackInteraction) {
    const sourceBadge = item.source?.startsWith('plugin:') ? (
      <span className="text-[10px] font-semibold text-semantic-info bg-surface-input px-1.5 py-0.5 rounded">
        via {item.source.slice('plugin:'.length)}
      </span>
    ) : null

    if (item.type === 'dns') {
      return (
        <div className="space-y-3">
          {sourceBadge}
          <DetailField label="Query Name" value={item.queryName || ''} />
          <DetailField label="Query Type" value={item.queryType || ''} />
          <DetailField label="Source IP" value={item.sourceIp} />
        </div>
      )
    }
    if (item.type === 'http') {
      let headers: Record<string, string[]> = {}
      try { headers = JSON.parse(item.headers || '{}') } catch { /* ignore */ }
      return (
        <div className="space-y-3">
          {sourceBadge}
          <DetailField label="Method & Path" value={`${item.method} ${item.path}`} />
          <DetailField label="Source IP" value={item.sourceIp} />
          {Object.keys(headers).length > 0 && (
            <div>
              <div className="text-xs text-content-muted uppercase mb-1">Headers</div>
              <pre className="text-xs text-content-secondary overflow-auto max-h-40 whitespace-pre-wrap">
                {Object.entries(headers).map(([k, v]) => `${k}: ${(v as string[]).join(', ')}`).join('\n')}
              </pre>
            </div>
          )}
          {item.body && (
            <div>
              <div className="text-xs text-content-muted uppercase mb-1">Body</div>
              <pre className="text-xs text-content-secondary overflow-auto max-h-40 whitespace-pre-wrap">
                {b64Decode(item.body)}
              </pre>
            </div>
          )}
          {item.rawRequest && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-content-muted uppercase">Raw Request</span>
                <button onClick={() => copy(b64Decode(item.rawRequest!))} className="text-xs text-accent-secondary hover:text-accent-secondary-hover">
                  Copy
                </button>
              </div>
              <pre className="text-xs text-content-secondary overflow-auto max-h-64 whitespace-pre-wrap bg-surface-terminal p-2 rounded">
                {b64Decode(item.rawRequest)}
              </pre>
            </div>
          )}
        </div>
      )
    }
    // Generic handler for SMTP, FTP, LDAP, SMB, etc.
    return (
      <div className="space-y-3">
        {sourceBadge}
        <DetailField label="Protocol" value={item.type.toUpperCase()} />
        <DetailField label="Source IP" value={item.sourceIp} />
        {item.rawRequest && (
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-content-muted uppercase">Raw Request</span>
              <button onClick={() => copy(b64Decode(item.rawRequest!))} className="text-xs text-accent-secondary hover:text-accent-secondary-hover">
                Copy
              </button>
            </div>
            <pre className="text-xs text-content-secondary overflow-auto max-h-64 whitespace-pre-wrap bg-surface-terminal p-2 rounded">
              {b64Decode(item.rawRequest)}
            </pre>
          </div>
        )}
      </div>
    )
  }

  function renderFireDetail(fire: XSSFire) {
    return (
      <div className="space-y-3">
        {fire.screenshot && (
          <div>
            <div className="text-xs text-content-muted uppercase mb-1">Screenshot</div>
            <img
              src={fire.screenshot}
              alt="XSS fire screenshot"
              className="w-full rounded border border-border cursor-pointer"
              onClick={() => {
                const w = window.open()
                if (w) {
                  w.document.write(`<img src="${fire.screenshot}" style="max-width:100%">`)
                  w.document.title = 'XSS Screenshot'
                }
              }}
            />
          </div>
        )}
        <DetailField label="URL" value={fire.url} copyable />
        <DetailField label="Origin" value={fire.origin} />
        <DetailField label="Referrer" value={fire.referrer} />
        <DetailField label="User Agent" value={fire.userAgent} />
        <DetailField label="Cookies" value={fire.cookies} copyable />
        <DetailField label="Page Title" value={fire.pageTitle} />
        <DetailField label="Source IP" value={fire.sourceIp} />
        <DetailField label="In Iframe" value={fire.inIframe ? 'Yes' : 'No'} />
        {fire.injectionKey && <DetailField label="Injection Key" value={fire.injectionKey} />}
        <DetailField label="Browser Time" value={fire.browserTime} />
        <DetailField label="Fired At" value={new Date(fire.firedAt).toLocaleString('en-US', { timeZone: 'UTC' }) + ' UTC'} />
        {fire.pageText && (
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-content-muted uppercase">Page Text</span>
              <button onClick={() => copy(fire.pageText!)} className="text-xs text-accent-secondary hover:text-accent-secondary-hover">
                Copy
              </button>
            </div>
            <pre className="text-xs text-content-secondary overflow-auto max-h-48 whitespace-pre-wrap bg-surface-terminal p-2 rounded">
              {fire.pageText.length > 10000 ? fire.pageText.substring(0, 10000) + '\n...(truncated)' : fire.pageText}
            </pre>
          </div>
        )}
        {fire.dom && (
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-content-muted uppercase">DOM Snapshot</span>
              <button onClick={() => copy(fire.dom!)} className="text-xs text-accent-secondary hover:text-accent-secondary-hover">
                Copy
              </button>
            </div>
            <pre className="text-xs text-content-secondary overflow-auto max-h-64 whitespace-pre-wrap bg-surface-terminal p-2 rounded">
              {fire.dom.length > 10000 ? fire.dom.substring(0, 10000) + '\n...(truncated)' : fire.dom}
            </pre>
          </div>
        )}
        {collectedPages.length > 0 && (
          <div>
            <div className="text-xs text-content-muted uppercase mb-1">Collected Pages ({collectedPages.length})</div>
            <div className="space-y-1">
              {collectedPages.map((cp) => (
                <div
                  key={cp.id}
                  className="flex items-center justify-between bg-surface-input px-2 py-1 rounded cursor-pointer hover:bg-surface-hover"
                  onClick={() => handleViewCollectedPage(cp.id)}
                >
                  <code className="text-[10px] text-accent-secondary truncate">{cp.url}</code>
                  <span className="text-[10px] text-content-muted shrink-0 ml-2">
                    {new Date(cp.collectedAt).toLocaleTimeString('en-US', { timeZone: 'UTC' }) + ' UTC'}
                  </span>
                </div>
              ))}
            </div>
            {selectedPage && (
              <div className="mt-2">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-content-muted uppercase truncate">{selectedPage.url}</span>
                  <button onClick={() => copy(selectedPage.html || '')} className="text-xs text-accent-secondary hover:text-accent-secondary-hover shrink-0">
                    Copy
                  </button>
                </div>
                <pre className="text-xs text-content-secondary overflow-auto max-h-64 whitespace-pre-wrap bg-surface-terminal p-2 rounded">
                  {(selectedPage.html || '').length > 10000
                    ? (selectedPage.html || '').substring(0, 10000) + '\n...(truncated)'
                    : selectedPage.html}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {/* Top: Config + Creation Bar (single row) */}
      <div className="flex flex-wrap items-center gap-2 lg:gap-3 px-3 py-2 border-b border-border bg-surface-card shrink-0">
        {/* Listener config group */}
        <div className="flex items-center gap-2">
          <input
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-40 lg:w-52"
            placeholder="Listener URL"
            value={listenerUrl}
            onChange={(e) => setListenerUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSaveConfig()}
          />
          <input
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-36 lg:w-44"
            placeholder="Callback domain"
            value={callbackDomain}
            onChange={(e) => setCallbackDomain(e.target.value)}
          />
          <button
            onClick={handleSaveConfig}
            className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold shrink-0"
          >
            Save
          </button>
          {listenerSaved && <span className="text-xs text-semantic-success shrink-0">Saved!</span>}
          {listenerError && <span className="text-xs text-semantic-error shrink-0">{listenerError}</span>}
        </div>

        <div className="w-px h-6 bg-border shrink-0 hidden lg:block" />

        {/* SSRF token group */}
        <div className="flex items-center gap-2">
          <input
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-28 lg:w-36"
            placeholder="SSRF token note"
            value={tokenNote}
            onChange={(e) => setTokenNote(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCreateToken()}
          />
          <button
            onClick={handleCreateToken}
            disabled={tokenLoading}
            className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50 shrink-0"
          >
            {tokenLoading ? '...' : 'Generate SSRF Token'}
          </button>
          {tokenCreated && <span className="text-xs text-semantic-success shrink-0">Copied!</span>}
          {tokenError && <span className="text-xs text-semantic-error shrink-0">{tokenError}</span>}
        </div>

        <div className="w-px h-6 bg-border shrink-0 hidden lg:block" />

        {/* XSS probe group */}
        <div className="flex items-center gap-2">
          <input
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-28 lg:w-36"
            placeholder="XSS probe name"
            value={probeName}
            onChange={(e) => setProbeName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCreateProbe()}
          />
          <button
            onClick={handleCreateProbe}
            disabled={probeLoading}
            className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50 shrink-0"
          >
            {probeLoading ? '...' : 'Create XSS Probe'}
          </button>
          {probeError && <span className="text-xs text-semantic-error shrink-0">{probeError}</span>}
        </div>

      </div>

      {/* Plugin row — one input-group per loaded InteractProvider, flex-wrapped */}
      {providers.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 lg:gap-3 px-3 py-2 border-b border-border bg-surface-card shrink-0">
          {providers.map((p, i) => {
            const vals = pluginValues[p.name] || {}
            const hasRequired = p.configSchema
              .filter((f) => f.required)
              .every((f) => (vals[f.name] || '').trim() !== '')
            return (
              <Fragment key={p.name}>
                {i > 0 && <div className="w-px h-6 bg-border shrink-0 hidden lg:block" />}
                <div className="flex items-center gap-2">
                  <span
                    className="text-xs font-semibold text-content-secondary shrink-0"
                    title={p.info.helpText}
                  >
                    {p.info.label}:
                  </span>
                  {p.configSchema.map((f) => (
                    f.type === 'checkbox' ? (
                      <label
                        key={f.name}
                        className="flex items-center gap-1.5 text-xs text-content-secondary shrink-0 cursor-pointer"
                        title={f.helpText}
                      >
                        <input
                          type="checkbox"
                          checked={vals[f.name] === 'true'}
                          onChange={(e) => setPluginValue(p.name, f.name, e.target.checked ? 'true' : 'false')}
                        />
                        {f.label}
                      </label>
                    ) : (
                      <input
                        key={f.name}
                        type={f.type === 'password' ? 'password' : 'text'}
                        className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-32 lg:w-40"
                        placeholder={f.placeholder || f.label}
                        value={vals[f.name] || ''}
                        onChange={(e) => setPluginValue(p.name, f.name, e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && hasRequired && handleAddPluginInstance(p.name)}
                      />
                    )
                  ))}
                  <button
                    onClick={() => handleAddPluginInstance(p.name)}
                    disabled={pluginLoading[p.name] || !hasRequired}
                    className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50 shrink-0"
                  >
                    {pluginLoading[p.name] ? '...' : p.info.buttonLabel}
                  </button>
                  {pluginError[p.name] && (
                    <span className="text-xs text-semantic-error shrink-0 max-w-xs truncate" title={pluginError[p.name]}>
                      {pluginError[p.name]}
                    </span>
                  )}
                </div>
              </Fragment>
            )
          })}
        </div>
      )}

      {/* Bottom: Three-column layout */}
      <div className="flex flex-1 min-h-0">
        {/* Left: Token + Probe list */}
        <div className="w-56 lg:w-72 border-r border-border flex flex-col min-h-0">
          <div className="px-2 py-1.5 bg-surface-card border-b border-border shrink-0">
            <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">Tokens & Probes</span>
          </div>
          <div className="flex-1 overflow-auto min-h-0">
            {/* Tokens */}
            {tokens.map((t) => (
              <div
                key={`token-${t.id}`}
                className="px-3 py-2 border-b border-border-subtle hover:bg-surface-hover"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold uppercase text-semantic-info bg-surface-input px-1.5 py-0.5 rounded">Token</span>
                    <code className="text-xs text-accent-secondary">{t.token}</code>
                  </div>
                  <button
                    onClick={() => handleDeleteToken(t.id)}
                    className="text-xs text-semantic-error hover:text-semantic-error opacity-60 hover:opacity-100"
                  >
                    x
                  </button>
                </div>
                {t.note && <div className="text-xs text-content-secondary truncate mt-1">{t.note}</div>}
                <div className="flex items-center justify-between mt-1">
                  <span className="text-xs text-content-muted">{t.hitCount} hit{t.hitCount !== 1 ? 's' : ''}</span>
                  <button
                    onClick={() => copy(payloadUrl(t.token))}
                    className="text-xs text-accent-secondary hover:text-accent-secondary-hover"
                  >
                    Copy URL
                  </button>
                </div>
              </div>
            ))}

            {/* Probes */}
            {probes.map((p) => (
              <div key={`probe-${p.id}`}>
                <div
                  className="px-3 py-2 border-b border-border-subtle hover:bg-surface-hover cursor-pointer"
                  onClick={() => setExpandedProbe(expandedProbe === p.id ? null : p.id)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-bold uppercase text-semantic-special bg-surface-input px-1.5 py-0.5 rounded">XSS</span>
                      <code className="text-xs text-accent-secondary">{p.probeId}</code>
                    </div>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleDeleteProbe(p.id) }}
                      className="text-xs text-semantic-error hover:text-semantic-error opacity-60 hover:opacity-100"
                    >
                      x
                    </button>
                  </div>
                  {p.name && <div className="text-xs text-content-secondary truncate mt-1">{p.name}</div>}
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-xs text-content-muted">{p.fireCount} fire{p.fireCount !== 1 ? 's' : ''}</span>
                    <span className="text-xs text-content-muted">{new Date(p.createdAt).toLocaleDateString('en-US', { timeZone: 'UTC' })}</span>
                  </div>
                </div>
                {/* Expanded payloads */}
                {expandedProbe === p.id && payloads.length > 0 && (
                  <div className="bg-surface-body border-b border-border-subtle px-3 py-2 space-y-1.5">
                    <div className="text-[10px] font-semibold text-content-muted uppercase tracking-wide">Payloads</div>
                    {payloads.map((v) => (
                      <div key={v.name} className="flex items-start gap-2">
                        <div className="flex-1 min-w-0">
                          <div className="text-[10px] text-content-muted mb-0.5">
                            {v.name}
                            <span className="ml-1 text-accent-secondary font-mono">#{v.injectionKey}</span>
                          </div>
                          <code className="text-[10px] text-content-secondary break-all block bg-surface-terminal px-1.5 py-1 rounded">
                            {v.payload}
                          </code>
                        </div>
                        <button
                          onClick={() => handleCopyPayload(v.payload, v.name)}
                          className="text-[10px] text-accent-secondary hover:text-accent-secondary-hover shrink-0 mt-3"
                        >
                          {copiedId === v.name ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    ))}

                    {/* Probe config */}
                    <div className="mt-3 pt-2 border-t border-border-subtle space-y-1.5">
                      <div className="text-[10px] font-semibold text-content-muted uppercase tracking-wide">Probe Config</div>
                      <div>
                        <label className="text-[10px] text-content-muted">Collect Pages (one path per line)</label>
                        <textarea
                          className="w-full bg-surface-input text-[10px] text-content-primary px-1.5 py-1 rounded border border-border mt-0.5 resize-y"
                          rows={3}
                          placeholder="/admin&#10;/api/keys&#10;/settings"
                          value={probeCollectPages}
                          onChange={(e) => setProbeCollectPages(e.target.value)}
                        />
                      </div>
                      <div>
                        <label className="text-[10px] text-content-muted">Chainload URI</label>
                        <input
                          className="w-full bg-surface-input text-[10px] text-content-primary px-1.5 py-1 rounded border border-border mt-0.5"
                          placeholder="https://attacker.com/payload.js"
                          value={probeChainloadUri}
                          onChange={(e) => setProbeChainloadUri(e.target.value)}
                        />
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleSaveProbeConfig(p.id)}
                          className="px-2 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-[10px] font-semibold"
                        >
                          Save Config
                        </button>
                        {probeConfigSaved && <span className="text-[10px] text-semantic-success">Saved!</span>}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}

            {/* Plugin instances — one section per loaded InteractProvider */}
            {providers.map((p) => {
              const instances = pluginInstances[p.name] || []
              if (instances.length === 0) return null
              return (
                <Fragment key={`plugin-section-${p.name}`}>
                  <div className="px-2 py-1.5 bg-surface-card border-b border-border border-t">
                    <span className="text-[10px] font-semibold text-content-muted uppercase tracking-wide">
                      {p.info.label}
                    </span>
                  </div>
                  {instances.map((inst) => (
                    <div
                      key={`inst-${p.name}-${inst.id}`}
                      className="px-3 py-2 border-b border-border-subtle hover:bg-surface-hover"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className={`inline-block w-2 h-2 rounded-full shrink-0 ${
                            inst.status === 'connected' ? 'bg-semantic-success' :
                            inst.status === 'connecting' ? 'bg-semantic-warning' :
                            inst.status === 'error' ? 'bg-semantic-error' : 'bg-content-muted'
                          }`} />
                          <code className="text-xs text-content-primary truncate">{inst.label}</code>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <button
                            onClick={() => handleTogglePluginInstance(p.name, inst.id, !inst.enabled)}
                            className={`text-[10px] px-1.5 py-0.5 rounded ${inst.enabled ? 'text-semantic-success bg-surface-input' : 'text-content-muted bg-surface-input'}`}
                          >
                            {inst.enabled ? 'ON' : 'OFF'}
                          </button>
                          <button
                            onClick={() => handleDeletePluginInstance(p.name, inst.id)}
                            className="text-xs text-semantic-error hover:text-semantic-error opacity-60 hover:opacity-100"
                          >
                            x
                          </button>
                        </div>
                      </div>
                      <div
                        className="text-[10px] text-content-muted mt-1 capitalize truncate"
                        title={inst.meta?.error}
                      >
                        {inst.status}{inst.meta?.error ? `: ${inst.meta.error}` : ''}
                      </div>
                      {inst.payloadUrl && (
                        <div className="flex items-center justify-between mt-1">
                          <code className="text-[10px] text-accent-secondary truncate">{inst.payloadUrl}</code>
                          <button
                            onClick={() => copy(inst.payloadUrl)}
                            className="text-[10px] text-accent-secondary hover:text-accent-secondary-hover shrink-0 ml-2"
                          >
                            Copy
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </Fragment>
              )
            })}

            {tokens.length === 0 && probes.length === 0 && Object.values(pluginInstances).every((arr) => arr.length === 0) && (
              <div className="text-content-muted text-xs p-3">No tokens, probes, or instances yet</div>
            )}
          </div>
        </div>

        {/* Center: Unified event feed */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
            <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">Events</span>
            <span className="text-xs text-content-muted">
              {interactionsTotal + firesTotal} total
            </span>
            <button
              onClick={handleClearAll}
              className="ml-auto text-xs px-3 py-1 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold"
            >
              Clear
            </button>
          </div>
          <div className="flex-1 overflow-auto min-h-0">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-surface-card text-content-muted uppercase">
                <tr>
                  <th className="px-2 py-1 text-left w-12">Type</th>
                  <th className="px-2 py-1 text-left w-28">Token</th>
                  <th className="px-2 py-1 text-left w-28">Source</th>
                  <th className="px-2 py-1 text-left">Detail</th>
                  <th className="px-2 py-1 text-right w-36">Time</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr
                    key={ev.id}
                    className={`border-b border-border-subtle cursor-pointer hover:bg-surface-hover ${
                      selectedId === ev.id ? 'bg-surface-hover' : ''
                    }`}
                    onClick={() => selectEvent(ev)}
                  >
                    <td className="px-2 py-1">{typeBadge(ev.kind)}</td>
                    <td className="px-2 py-1 text-accent-secondary font-mono">{ev.hex}</td>
                    <td className="px-2 py-1 text-content-secondary">{ev.sourceIp}</td>
                    <td className="px-2 py-1 text-content-secondary truncate max-w-xs">{ev.detail}</td>
                    <td className="px-2 py-1 text-right text-content-muted">
                      {new Date(ev.timestamp).toLocaleTimeString('en-US', { timeZone: 'UTC' }) + ' UTC'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {events.length === 0 && (
              <div className="text-content-muted text-xs p-4">No events recorded yet</div>
            )}
          </div>
        </div>

        {/* Right: Detail panel */}
        <div className="w-72 lg:w-96 border-l border-border overflow-auto min-h-0">
          {selectedInteraction ? (
            <div className="p-3">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">Detail</span>
                  {selectedInteraction.source?.startsWith('plugin:') && (
                    <span className="text-[10px] text-semantic-info bg-surface-input px-1.5 py-0.5 rounded font-semibold">
                      {selectedInteraction.source.slice('plugin:'.length)}
                    </span>
                  )}
                </div>
                {typeBadge(selectedInteraction.type)}
              </div>
              <div className="mb-3">
                <div className="text-xs text-content-muted uppercase mb-1">Timestamp</div>
                <code className="text-xs text-content-primary">
                  {new Date(selectedInteraction.timestamp).toLocaleString('en-US', { timeZone: 'UTC' }) + ' UTC'}
                </code>
              </div>
              {renderInteractionDetail(selectedInteraction)}
            </div>
          ) : fireDetail ? (
            <div className="p-3">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">XSS Fire Detail</span>
                {typeBadge('xss')}
              </div>
              {renderFireDetail(fireDetail)}
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-content-muted text-sm h-full p-4">
              Select an event to view details
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function DetailField({ label, value, copyable }: { label: string; value: string; copyable?: boolean }) {
  if (!value) return null
  return (
    <div>
      <div className="flex items-center justify-between mb-0.5">
        <span className="text-xs text-content-muted uppercase">{label}</span>
        {copyable && (
          <button
            onClick={() => copy(value)}
            className="text-xs text-accent-secondary hover:text-accent-secondary-hover"
          >
            Copy
          </button>
        )}
      </div>
      <code className="text-xs text-content-primary break-all">{value}</code>
    </div>
  )
}
