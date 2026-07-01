import { useEffect, useState } from 'react'
import { api, CustomAddition, MatchReplaceRule, NoisePattern, ScopeRule } from '../lib/api'
import { useRequestStore } from '../stores/requestStore'
import { Settings, useSettingsStore } from '../stores/settingsStore'
import { useUpdateStore } from '../stores/updateStore'
import { useHiddenTabsStore } from '../stores/hiddenTabsStore'
import { useTeamSharedConfigStore } from '../stores/teamSharedConfigStore'
import { NAV } from '../lib/nav'

const THEMES = [
  { value: 'aomori', label: 'Aomori' },
  { value: 'bishop-fox', label: 'Bishop Fox' },
  { value: 'earth', label: 'Earth' },
  { value: 'fukuoka', label: 'Fukuoka' },
  { value: 'hirosaki', label: 'Hirosaki' },
  { value: 'hotdogstand', label: 'Hot Dog Stand' },
  { value: 'miami', label: 'Miami' },
  { value: 'midori', label: 'Midori' },
  { value: 'mirai', label: 'Mirai' },
  { value: 'morioka', label: 'Morioka' },
  { value: 'nagoya', label: 'Nagoya' },
  { value: 'nambu', label: 'Nambu' },
  { value: 'okinawa', label: 'Okinawa' },
  { value: 'osaka', label: 'Osaka' },
  { value: 'purple', label: 'Purple' },
  { value: 'sendai', label: 'Sendai' },
  { value: 'takara', label: 'Takara' },
  { value: 'tokyo', label: 'Tokyo' },
]

type FilterTab = 'scope' | 'noise' | 'replace'

interface SettingsPageProps {
  onTeamSettingsChanged?: () => void
}

export default function SettingsPage({ onTeamSettingsChanged }: SettingsPageProps) {
  const { settings, setSettings } = useSettingsStore()
  const { info: updateInfo, setInfo: setUpdateInfo } = useUpdateStore()
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  // Update check state
  const [checking, setChecking] = useState(false)
  const [checkError, setCheckError] = useState('')
  const [justChecked, setJustChecked] = useState(false)

  // SOCKS proxy state
  const [socksHost, setSocksHost] = useState('')
  const [socksPort, setSocksPort] = useState('')
  const [socksUsername, setSocksUsername] = useState('')
  const [socksPassword, setSocksPassword] = useState('')
  const [socksDns, setSocksDns] = useState(false)
  const [socksSaved, setSocksSaved] = useState(false)

  // Team server state
  const [listenerUrl, setListenerUrl] = useState('')
  const [teamToken, setTeamToken] = useState('')
  const [teamNickname, setTeamNickname] = useState('')
  const [teamSaved, setTeamSaved] = useState(false)
  const [teamError, setTeamError] = useState('')
  const [teamLoading, setTeamLoading] = useState(false)

  // Project ID + shared configs
  const [projectId, setProjectId] = useState('')
  const [projectIdSaved, setProjectIdSaved] = useState(false)

  // Local draft for editable fields
  const [interceptTimeout, setInterceptTimeout] = useState(60)
  const [maxRequests, setMaxRequests] = useState(5000)
  const [unknownPluginStatesNotice, setUnknownPluginStatesNotice] = useState<string[]>([])
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('joro-theme') || document.documentElement.getAttribute('data-theme') || 'bishop-fox'
  })
  const hiddenTabs = useHiddenTabsStore((s) => s.hiddenTabs)
  const toggleTab = useHiddenTabsStore((s) => s.toggleTab)
  const [pluginTabs, setPluginTabs] = useState<Array<{ to: string; label: string }>>([])

  // Filter tab
  const [filterTab, setFilterTab] = useState<FilterTab>('scope')

  // Noise filter state
  const [noiseEnabled, setNoiseEnabled] = useState(true)
  const [noisePatterns, setNoisePatterns] = useState<NoisePattern[]>([])
  const [newNoisePattern, setNewNoisePattern] = useState('')

  // Scope state
  const [scopeEnabled, setScopeEnabled] = useState(false)
  const [scopeRules, setScopeRules] = useState<ScopeRule[]>([])
  const [newPattern, setNewPattern] = useState('')
  const [newMethods, setNewMethods] = useState('')
  const [newPath, setNewPath] = useState('')
  const [newInclude, setNewInclude] = useState(true)

  // Match & Replace state
  const [replaceEnabled, setReplaceEnabled] = useState(false)
  const [replaceRules, setReplaceRules] = useState<MatchReplaceRule[]>([])
  const [newRuleTarget, setNewRuleTarget] = useState('request_header')
  const [newRuleMatchType, setNewRuleMatchType] = useState('string')
  const [newRuleMatch, setNewRuleMatch] = useState('')
  const [newRuleReplace, setNewRuleReplace] = useState('')

  // Custom Data state
  const [customDataEnabled, setCustomDataEnabled] = useState(false)
  const [customDataItems, setCustomDataItems] = useState<CustomAddition[]>([])
  const [newItemType, setNewItemType] = useState('header')
  const [newItemName, setNewItemName] = useState('')
  const [newItemValue, setNewItemValue] = useState('')

  useEffect(() => {
    api.getSettings().then((s) => {
      const st = s as Settings
      setSettings(st)
      setInterceptTimeout(st.interceptTimeout)
      setMaxRequests(st.maxRequests || 5000)
      setSocksHost(st.socksHost || '')
      setSocksPort(st.socksPort ? String(st.socksPort) : '')
      setSocksUsername(st.socksUsername || '')
      setSocksPassword(st.socksPassword || '')
      setSocksDns(st.socksDns || false)
      setListenerUrl(st.listenerUrl || '')
      setTeamToken(st.teamToken || '')
      setTeamNickname(st.teamNickname || '')
      setProjectId(st.projectId || '')
    })
    api.getNoise().then((n) => {
      setNoiseEnabled(n.enabled)
      setNoisePatterns(n.patterns)
    }).catch(() => {})
    api.getScope().then((s) => {
      setScopeEnabled(s.enabled)
      setScopeRules(s.rules)
    })
    api.getReplace().then((r) => {
      setReplaceEnabled(r.enabled)
      setReplaceRules(r.rules)
    }).catch(() => {})
    api.getCustomData().then((cd) => {
      setCustomDataEnabled(cd.enabled)
      setCustomDataItems(cd.items)
    }).catch(() => {})
    api.listPlugins().then((plugs) => {
      setPluginTabs(
        plugs
          .filter((p) => p.type === 'tab' && p.status === 'loaded')
          .map((p) => ({ to: `/plugin/${p.name}`, label: p.tabLabel || p.name }))
      )
    }).catch(() => {})
  }, []) // eslint-disable-line

  async function save() {
    setError('')
    try {
      const updated = await api.updateSettings({ interceptTimeout, maxRequests })
      setSettings(updated as Settings)
      setSaved(true)
      window.setTimeout(() => setSaved(false), 3000)
    } catch (e) {
      setError(String(e))
    }
  }

  // Apply a loaded/imported project config response to the live UI state.
  const applyProjectResp = (p: unknown) => {
    const proj = p as {
      listenerUrl?: string; teamToken?: string; teamNickname?: string; projectId?: string
      scopeEnabled: boolean; scopeRules: ScopeRule[]
      noiseEnabled: boolean; noisePatterns: NoisePattern[]
      replaceEnabled: boolean; replaceRules: MatchReplaceRule[]
      customDataEnabled: boolean; customDataItems: CustomAddition[]
      unknownPluginStates?: string[]
    }
    setScopeEnabled(proj.scopeEnabled)
    setScopeRules(proj.scopeRules || [])
    setNoiseEnabled(proj.noiseEnabled)
    setNoisePatterns(proj.noisePatterns || [])
    setReplaceEnabled(proj.replaceEnabled)
    setReplaceRules(proj.replaceRules || [])
    setCustomDataEnabled(proj.customDataEnabled)
    setCustomDataItems(proj.customDataItems || [])
    if (proj.listenerUrl !== undefined) {
      setListenerUrl(proj.listenerUrl || '')
      setTeamToken(proj.teamToken || '')
      setTeamNickname(proj.teamNickname || '')
    }
    if (proj.projectId !== undefined) setProjectId(proj.projectId || '')
    setUnknownPluginStatesNotice(proj.unknownPluginStates || [])
    useRequestStore.getState().invalidate()
    api.getSettings().then((s) => setSettings(s as Settings))
    if (onTeamSettingsChanged) onTeamSettingsChanged()
  }

  return (
    <div className="p-4 overflow-y-auto flex-1 min-h-0">
      <h2 className="text-sm font-semibold uppercase tracking-wide mb-4">Settings</h2>

      {settings && (
        <div className="space-y-4">
          {/* Top row: Server Info, Appearance, Intercept, CA Cert */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
            {/* Server Info */}
            <div className="bg-surface-card rounded border border-border p-3 space-y-3">
              <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">Server Info</h3>
              <Row label="Proxy Port" value={`:${settings.proxyPort}`} />
              <Row label="UI Port" value={`:${settings.uiPort}`} />
              {updateInfo && (
                <div className="text-xs text-content-secondary">
                  <span className="text-content-muted">Version:</span>{' '}
                  <span className="text-content-primary">{updateInfo.version}</span>{' '}
                  <span className="text-content-muted">({updateInfo.commit})</span>
                </div>
              )}
              <div className="flex items-center justify-between">
                <label className="text-sm text-content-secondary">Update Checks</label>
                <select
                  value={settings.disableUpdateChecks ? 'disabled' : 'enabled'}
                  onChange={async (e) => {
                    const next = e.target.value === 'disabled'
                    const updated = await api.updateSettings({ disableUpdateChecks: next })
                    setSettings(updated as Settings)
                  }}
                  className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                >
                  <option value="enabled">Enabled</option>
                  <option value="disabled">Disabled</option>
                </select>
              </div>
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  onClick={async () => {
                    setCheckError('')
                    setJustChecked(false)
                    setChecking(true)
                    try {
                      const result = await api.checkForUpdate()
                      setUpdateInfo(result)
                      setJustChecked(true)
                      window.setTimeout(() => setJustChecked(false), 3000)
                    } catch (e) {
                      setCheckError(e instanceof Error ? e.message : String(e))
                    } finally {
                      setChecking(false)
                    }
                  }}
                  disabled={checking}
                  className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold disabled:opacity-60"
                >
                  {checking ? 'Checking...' : 'Check for Updates'}
                </button>
              </div>
              {justChecked && updateInfo && !updateInfo.updateAvailable && (
                <div className="text-xs text-semantic-success text-right">You're up to date.</div>
              )}
              {checkError && <div className="text-xs text-semantic-error text-right">{checkError}</div>}
            </div>

            {/* Theme */}
            <div className="bg-surface-card rounded border border-border p-3 space-y-3">
              <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">Appearance</h3>
              <div className="flex items-center justify-between">
                <label className="text-sm text-content-secondary">Theme</label>
                <select
                  value={theme}
                  onChange={(e) => {
                    const t = e.target.value
                    setTheme(t)
                    document.documentElement.setAttribute('data-theme', t)
                    localStorage.setItem('joro-theme', t)
                  }}
                  className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                >
                  {THEMES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>
              <div className="pt-2 border-t border-border-subtle">
                <div className="text-sm text-content-secondary mb-2">Visible Tabs</div>
                <div className="grid grid-cols-2 gap-x-2 gap-y-1">
                  {[...NAV.filter((n) => n.to !== '/settings'), ...pluginTabs].map((t) => (
                    <label key={t.to} className="flex items-center gap-1.5 text-xs text-content-secondary cursor-pointer">
                      <input
                        type="checkbox"
                        checked={!hiddenTabs.includes(t.to)}
                        onChange={() => toggleTab(t.to)}
                        className="accent-accent-secondary"
                      />
                      <span className="truncate">{t.label}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>

            {/* Intercept */}
            <div className="bg-surface-card rounded border border-border p-3 space-y-3">
              <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">Proxy</h3>
              <div className="flex items-center justify-between">
                <label className="text-sm text-content-secondary">Max requests</label>
                <input
                  type="number"
                  min={100}
                  max={100000}
                  value={maxRequests}
                  onChange={(e) => setMaxRequests(Number(e.target.value))}
                  className="w-20 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border text-right"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-sm text-content-secondary">Auto-forward timeout (s)</label>
                <input
                  type="number"
                  min={1}
                  value={interceptTimeout}
                  onChange={(e) => setInterceptTimeout(Number(e.target.value))}
                  className="w-20 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border text-right"
                />
              </div>
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  onClick={save}
                  className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
                >
                  Save
                </button>
                {saved && <span className="text-semantic-success text-xs">Saved!</span>}
              </div>
              {error && <div className="text-semantic-error text-xs mt-1">{error}</div>}
            </div>

            {/* Connection */}
            <div className="bg-surface-card rounded border border-border p-3 space-y-3">
              <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">Connection</h3>
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <label className="text-sm text-content-secondary">Default to HTTP/2</label>
                  <p className="text-[10px] text-content-muted mt-0.5">
                    Advertise h2 in browser-side ALPN and forward upstream as HTTP/2 when supported. Disable to force HTTP/1.1 everywhere. Takes effect on new connections.
                  </p>
                </div>
                <button
                  onClick={async () => {
                    const next = !settings.http2Enabled
                    const updated = await api.updateSettings({ http2Enabled: next })
                    setSettings(updated as Settings)
                  }}
                  className={`shrink-0 px-3 py-1.5 rounded-sm text-xs font-semibold transition-colors ${
                    settings.http2Enabled
                      ? 'bg-accent-tertiary hover:bg-accent-tertiary-hover text-black'
                      : 'bg-surface-input hover:bg-surface-hover border border-border text-content-secondary'
                  }`}
                >
                  {settings.http2Enabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-sm text-content-secondary">HTTP/1 Keep-Alive</label>
                <button
                  onClick={async () => {
                    const next = !settings.keepAliveEnabled
                    const updated = await api.updateSettings({ keepAliveEnabled: next })
                    setSettings(updated as Settings)
                  }}
                  className={`px-3 py-1.5 rounded-sm text-xs font-semibold transition-colors ${
                    settings.keepAliveEnabled
                      ? 'bg-accent-tertiary hover:bg-accent-tertiary-hover text-black'
                      : 'bg-surface-input hover:bg-surface-hover border border-border text-content-secondary'
                  }`}
                >
                  {settings.keepAliveEnabled ? 'Enabled' : 'Disabled'}
                </button>
              </div>
            </div>

            {/* SOCKS Proxy */}
            <div className="bg-surface-card rounded border border-border p-3 space-y-2">
              <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">SOCKS Proxy</h3>
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="block text-[10px] text-content-muted mb-0.5">Host</label>
                  <input
                    type="text"
                    placeholder="127.0.0.1"
                    value={socksHost}
                    onChange={(e) => setSocksHost(e.target.value)}
                    className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                  />
                </div>
                <div className="w-16">
                  <label className="block text-[10px] text-content-muted mb-0.5">Port</label>
                  <input
                    type="number"
                    placeholder="1080"
                    value={socksPort}
                    onChange={(e) => setSocksPort(e.target.value)}
                    className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <div className="flex-1">
                  <label className="block text-[10px] text-content-muted mb-0.5">Username</label>
                  <input
                    type="text"
                    placeholder="Optional"
                    value={socksUsername}
                    onChange={(e) => setSocksUsername(e.target.value)}
                    className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                  />
                </div>
                <div className="flex-1">
                  <label className="block text-[10px] text-content-muted mb-0.5">Password</label>
                  <input
                    type="password"
                    placeholder="Optional"
                    value={socksPassword}
                    onChange={(e) => setSocksPassword(e.target.value)}
                    className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                  />
                </div>
              </div>
              <div className="flex items-center justify-between">
                <label className="text-xs text-content-secondary">DNS over SOCKS</label>
                <button
                  onClick={() => setSocksDns(!socksDns)}
                  className={`px-3 py-1 rounded-sm text-xs font-semibold transition-colors ${
                    socksDns
                      ? 'bg-accent-tertiary hover:bg-accent-tertiary-hover text-black'
                      : 'bg-surface-input hover:bg-surface-hover border border-border text-content-secondary'
                  }`}
                >
                  {socksDns ? 'Enabled' : 'Disabled'}
                </button>
              </div>
              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  onClick={async () => {
                    try {
                      const updated = await api.updateSettings({
                        socksHost,
                        socksPort: socksPort ? Number(socksPort) : 0,
                        socksUsername,
                        socksPassword,
                        socksDns,
                      })
                      setSettings(updated as Settings)
                      setSocksSaved(true)
                      window.setTimeout(() => setSocksSaved(false), 3000)
                    } catch (e) {
                      setError(String(e))
                    }
                  }}
                  className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
                >
                  Save
                </button>
                {socksSaved && <span className="text-semantic-success text-xs">Saved!</span>}
              </div>
            </div>

            {/* CA Certificate */}
            <div className="bg-surface-card rounded border border-border p-3">
              <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">CA Certificate</h3>
              <p className="text-xs text-content-secondary mb-3">
                Import into your browser/OS trust store to avoid TLS warnings.
              </p>
              <a
                href={api.caCertURL()}
                download="joro-ca.crt"
                className="inline-block px-4 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
              >
                Download CA Cert
              </a>
            </div>
          </div>

          {/* Configurations */}
          {unknownPluginStatesNotice.length > 0 && (
            <div className="bg-surface-card rounded border border-border p-3 text-xs text-content-secondary">
              State preserved for: <span className="text-semantic-warning font-semibold">{unknownPluginStatesNotice.join(', ')}</span>
              {' '}&mdash; these plugins aren't installed on this system. The blobs round-trip on re-save.
            </div>
          )}
          <ConfigManager theme={theme} hiddenTabs={hiddenTabs} onSettingsLoaded={(s) => {
            const st = s as Settings & { theme?: string; hiddenTabs?: string[]; unknownPluginStates?: string[] }
            setSettings(st)
            setInterceptTimeout(st.interceptTimeout)
            setMaxRequests(st.maxRequests || 5000)
            setSocksHost(st.socksHost || '')
            setSocksPort(st.socksPort ? String(st.socksPort) : '')
            setSocksUsername(st.socksUsername || '')
            setSocksPassword(st.socksPassword || '')
            setSocksDns(st.socksDns || false)
            if (st.theme) {
              setTheme(st.theme)
              document.documentElement.setAttribute('data-theme', st.theme)
              localStorage.setItem('joro-theme', st.theme)
            }
            if (Array.isArray(st.hiddenTabs)) {
              useHiddenTabsStore.getState().setHiddenTabs(st.hiddenTabs)
            }
            setUnknownPluginStatesNotice(st.unknownPluginStates || [])
          }} onProjectLoaded={applyProjectResp} />

          {/* Team Server */}
          <div className="bg-surface-card rounded border border-border p-3 space-y-2">
            <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">Team Server</h3>
            <p className="text-xs text-content-muted mb-2">
              Connect to a remote team server for shared chat and notes.
            </p>
            <div>
              <label className="block text-[10px] text-content-muted mb-0.5">Listener URL</label>
              <input
                type="text"
                placeholder="http://teamserver:9090"
                value={listenerUrl}
                onChange={(e) => setListenerUrl(e.target.value)}
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              />
            </div>
            <div>
              <label className="block text-[10px] text-content-muted mb-0.5">Team Token</label>
              <input
                type="password"
                placeholder="Token from team server console"
                value={teamToken}
                onChange={(e) => setTeamToken(e.target.value)}
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              />
            </div>
            <div>
              <label className="block text-[10px] text-content-muted mb-0.5">Nickname</label>
              <input
                type="text"
                placeholder="Your display name"
                value={teamNickname}
                onChange={(e) => setTeamNickname(e.target.value)}
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              />
            </div>
            {teamError && (
              <p className="text-semantic-error text-xs">{teamError}</p>
            )}

            <div className="flex items-center justify-end gap-2 pt-1">
              {listenerUrl && (
                <button
                  onClick={async () => {
                    try {
                      const updated = await api.updateSettings({
                        listenerUrl: '',
                        teamToken: '',
                        teamNickname: '',
                      })
                      setSettings(updated as Settings)
                      setListenerUrl('')
                      setTeamToken('')
                      setTeamNickname('')
                      setTeamError('')
                      localStorage.setItem('joro-setup-mode', 'local')
                      onTeamSettingsChanged?.()
                    } catch (e) {
                      setTeamError(String(e))
                    }
                  }}
                  className="px-3 py-1.5 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary text-xs font-semibold"
                >
                  Disconnect
                </button>
              )}
              <button
                disabled={teamLoading}
                onClick={async () => {
                  setTeamError('')
                  setTeamLoading(true)
                  try {
                    const updated = await api.updateSettings({
                      listenerUrl,
                      teamToken,
                      teamNickname,
                    })
                    setSettings(updated as Settings)

                    // If a listener URL is set, validate the token works.
                    if (listenerUrl.trim()) {
                      await api.listTokens()
                      localStorage.setItem('joro-setup-mode', 'remote')
                    } else {
                      localStorage.setItem('joro-setup-mode', 'local')
                    }

                    setTeamSaved(true)
                    window.setTimeout(() => setTeamSaved(false), 3000)
                    onTeamSettingsChanged?.()
                  } catch {
                    setTeamError('Connection failed. Check the URL and auth token.')
                  } finally {
                    setTeamLoading(false)
                  }
                }}
                className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold disabled:opacity-50"
              >
                {teamLoading ? 'Validating...' : 'Save'}
              </button>
              {teamSaved && <span className="text-semantic-success text-xs">Saved!</span>}
            </div>
          </div>

          {/* Project */}
          <div className="bg-surface-card rounded border border-border p-3 space-y-2">
            <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">Project</h3>
            <div>
              <label className="block text-[10px] text-content-muted mb-0.5">Project ID (optional)</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="e.g. acme-q3-external"
                  value={projectId}
                  onChange={(e) => setProjectId(e.target.value)}
                  className="flex-1 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                />
                <button
                  onClick={async () => {
                    try {
                      const updated = await api.updateSettings({ projectId })
                      setSettings(updated as Settings)
                      setProjectIdSaved(true)
                      window.setTimeout(() => setProjectIdSaved(false), 3000)
                    } catch { /* ignore */ }
                  }}
                  className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
                >
                  Save
                </button>
                {projectIdSaved && <span className="text-semantic-success text-xs self-center">Saved!</span>}
              </div>
              <p className="text-[10px] text-content-muted mt-1">Labels this engagement; shared in published configs and collaboration requests.</p>
            </div>
          </div>

          {/* Team Configs (shared project configs) — team mode only */}
          {listenerUrl.trim() && (
            <TeamConfigsPanel projectId={projectId} onImported={applyProjectResp} />
          )}

          {/* Filtering - tabbed card */}
          <div className="bg-surface-card rounded border border-border">
            {/* Tab bar */}
            <div className="flex border-b border-border">
              <button
                onClick={() => setFilterTab('scope')}
                className={`px-4 py-2 text-xs font-semibold transition-colors ${
                  filterTab === 'scope'
                    ? 'text-accent border-b-2 border-accent'
                    : 'text-content-muted hover:text-content-secondary'
                }`}
              >
                Scope
              </button>
              <button
                onClick={() => setFilterTab('noise')}
                className={`px-4 py-2 text-xs font-semibold transition-colors ${
                  filterTab === 'noise'
                    ? 'text-accent border-b-2 border-accent'
                    : 'text-content-muted hover:text-content-secondary'
                }`}
              >
                Noise Filter
              </button>
              <button
                onClick={() => setFilterTab('replace')}
                className={`px-4 py-2 text-xs font-semibold transition-colors ${
                  filterTab === 'replace'
                    ? 'text-accent border-b-2 border-accent'
                    : 'text-content-muted hover:text-content-secondary'
                }`}
              >
                Customize Requests
              </button>
            </div>

            <div className="p-3 space-y-3">
              {/* Scope tab */}
              {filterTab === 'scope' && (
                <>
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-content-muted">
                      When enabled, only matching hosts are MITM'd and captured. Out-of-scope HTTPS is tunneled without TLS termination.
                    </p>
                    <button
                      onClick={async () => {
                        const next = !scopeEnabled
                        await api.setScopeEnabled(next)
                        setScopeEnabled(next)
                      }}
                      className={`ml-3 shrink-0 px-3 py-1.5 rounded-sm text-xs font-semibold transition-colors ${
                        scopeEnabled
                          ? 'bg-accent-tertiary hover:bg-accent-tertiary-hover text-black'
                          : 'bg-surface-input hover:bg-surface-hover border border-border text-content-secondary'
                      }`}
                    >
                      {scopeEnabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>

                  <div className="text-xs text-content-muted">
                    Rules (include evaluated first, exclude overrides):
                  </div>
                  {scopeRules.length === 0 ? (
                    <p className="text-xs text-content-muted italic">
                      No rules defined.{scopeEnabled ? ' All traffic will be blocked.' : ''}
                    </p>
                  ) : (
                    <div className="space-y-1">
                      {scopeRules.map((rule) => (
                        <div key={rule.id} className="flex items-center gap-2 text-xs py-1 border-b border-border-subtle">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${rule.include ? 'bg-accent-secondary text-black' : 'bg-semantic-error-bg text-black'}`}>
                            {rule.include ? 'Include' : 'Exclude'}
                          </span>
                          <span className="text-content-primary font-mono">{rule.pattern}</span>
                          <span className="text-content-muted">{rule.methods?.length ? rule.methods.join(',') : '*'}</span>
                          <span className="text-content-muted">{rule.path || '/*'}</span>
                          <button
                            onClick={async () => {
                              await api.deleteScopeRule(rule.id)
                              setScopeRules((prev) => prev.filter((r) => r.id !== rule.id))
                            }}
                            className="ml-auto text-content-muted hover:text-semantic-error"
                          >
                            x
                          </button>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="flex items-end gap-2">
                    <div className="flex-1">
                      <label className="block text-[10px] text-content-muted mb-0.5">Host pattern</label>
                      <input
                        type="text"
                        placeholder="*.target.com"
                        value={newPattern}
                        onChange={(e) => setNewPattern(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      />
                    </div>
                    <div className="w-24">
                      <label className="block text-[10px] text-content-muted mb-0.5">Methods</label>
                      <input
                        type="text"
                        placeholder="*"
                        value={newMethods}
                        onChange={(e) => setNewMethods(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      />
                    </div>
                    <div className="w-24">
                      <label className="block text-[10px] text-content-muted mb-0.5">Path</label>
                      <input
                        type="text"
                        placeholder="/*"
                        value={newPath}
                        onChange={(e) => setNewPath(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      />
                    </div>
                    <select
                      value={newInclude ? 'include' : 'exclude'}
                      onChange={(e) => setNewInclude(e.target.value === 'include')}
                      className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                    >
                      <option value="include">Include</option>
                      <option value="exclude">Exclude</option>
                    </select>
                    <button
                      onClick={async () => {
                        if (!newPattern.trim()) return
                        const methods = newMethods.trim()
                          ? newMethods.split(',').map((m) => m.trim().toUpperCase()).filter(Boolean)
                          : []
                        const rule = await api.addScopeRule({
                          pattern: newPattern.trim(),
                          methods,
                          path: newPath.trim(),
                          include: newInclude,
                        })
                        setScopeRules((prev) => [...prev, rule])
                        setNewPattern('')
                        setNewMethods('')
                        setNewPath('')
                      }}
                      className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold"
                    >
                      Add
                    </button>
                  </div>
                </>
              )}

              {/* Noise Filter tab */}
              {filterTab === 'noise' && (
                <>
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-content-muted">
                      Silently tunnels common browser background traffic (captive portal, telemetry, OCSP) without capture. Separate from scope.
                    </p>
                    <button
                      onClick={async () => {
                        const next = !noiseEnabled
                        await api.setNoiseEnabled(next)
                        setNoiseEnabled(next)
                      }}
                      className={`ml-3 shrink-0 px-3 py-1.5 rounded-sm text-xs font-semibold transition-colors ${
                        noiseEnabled
                          ? 'bg-accent-tertiary hover:bg-accent-tertiary-hover text-black'
                          : 'bg-surface-input hover:bg-surface-hover border border-border text-content-secondary'
                      }`}
                    >
                      {noiseEnabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>

                  {noisePatterns.length === 0 ? (
                    <p className="text-xs text-content-muted italic">No patterns defined.</p>
                  ) : (
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                      {noisePatterns.map((p) => (
                        <div key={p.id} className="flex items-center gap-2 text-xs py-1 border-b border-border-subtle">
                          <span className="text-content-primary font-mono">{p.pattern}</span>
                          <button
                            onClick={async () => {
                              await api.deleteNoisePattern(p.id)
                              setNoisePatterns((prev) => prev.filter((x) => x.id !== p.id))
                            }}
                            className="ml-auto text-content-muted hover:text-semantic-error"
                          >
                            x
                          </button>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="flex items-end gap-2">
                    <div className="flex-1">
                      <label className="block text-[10px] text-content-muted mb-0.5">Host pattern</label>
                      <input
                        type="text"
                        placeholder="example.com"
                        value={newNoisePattern}
                        onChange={(e) => setNewNoisePattern(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      />
                    </div>
                    <button
                      onClick={async () => {
                        if (!newNoisePattern.trim()) return
                        const p = await api.addNoisePattern(newNoisePattern.trim())
                        setNoisePatterns((prev) => [...prev, p])
                        setNewNoisePattern('')
                      }}
                      className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold"
                    >
                      Add
                    </button>
                  </div>
                </>
              )}

              {/* Customize Requests tab */}
              {filterTab === 'replace' && (
                <>
                  {/* Match & Replace section */}
                  <h4 className="text-xs font-semibold text-content-primary uppercase tracking-wide">Match &amp; Replace</h4>
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-content-muted">
                      Automatically modify request/response headers, bodies, and WebSocket messages as they flow through the proxy.
                    </p>
                    <button
                      onClick={async () => {
                        const next = !replaceEnabled
                        await api.setReplaceEnabled(next)
                        setReplaceEnabled(next)
                      }}
                      className={`ml-3 shrink-0 px-3 py-1.5 rounded-sm text-xs font-semibold transition-colors ${
                        replaceEnabled
                          ? 'bg-accent-tertiary hover:bg-accent-tertiary-hover text-black'
                          : 'bg-surface-input hover:bg-surface-hover border border-border text-content-secondary'
                      }`}
                    >
                      {replaceEnabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>

                  {replaceRules.length === 0 ? (
                    <p className="text-xs text-content-muted italic">No rules defined.</p>
                  ) : (
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                      {replaceRules.map((rule) => (
                        <div key={rule.id} className="flex items-center gap-2 text-xs py-1 border-b border-border-subtle">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-accent-secondary text-black">
                            {rule.target.replace('_', ' ')}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-surface-input text-content-secondary">
                            {rule.matchType}
                          </span>
                          <span className="text-content-primary font-mono truncate max-w-[12rem]">{rule.match}</span>
                          <span className="text-content-muted">&rarr;</span>
                          <span className="text-semantic-success font-mono truncate max-w-[12rem]">{rule.replace || '(empty)'}</span>
                          <button
                            onClick={async () => {
                              await api.deleteReplaceRule(rule.id)
                              setReplaceRules((prev) => prev.filter((r) => r.id !== rule.id))
                            }}
                            className="ml-auto text-content-muted hover:text-semantic-error"
                          >
                            x
                          </button>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="flex items-end gap-2">
                    <div className="w-32">
                      <label className="block text-[10px] text-content-muted mb-0.5">Target</label>
                      <select
                        value={newRuleTarget}
                        onChange={(e) => setNewRuleTarget(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      >
                        <option value="request_header">Request Header</option>
                        <option value="request_body">Request Body</option>
                        <option value="response_header">Response Header</option>
                        <option value="response_body">Response Body</option>
                        <option value="ws_message">WS Message</option>
                      </select>
                    </div>
                    <div className="w-20">
                      <label className="block text-[10px] text-content-muted mb-0.5">Type</label>
                      <select
                        value={newRuleMatchType}
                        onChange={(e) => setNewRuleMatchType(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      >
                        <option value="string">String</option>
                        <option value="regex">Regex</option>
                      </select>
                    </div>
                    <div className="flex-1">
                      <label className="block text-[10px] text-content-muted mb-0.5">Match</label>
                      <input
                        type="text"
                        placeholder="User-Agent: Mozilla..."
                        value={newRuleMatch}
                        onChange={(e) => setNewRuleMatch(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      />
                    </div>
                    <div className="flex-1">
                      <label className="block text-[10px] text-content-muted mb-0.5">Replace</label>
                      <input
                        type="text"
                        placeholder="User-Agent: JoroProxy"
                        value={newRuleReplace}
                        onChange={(e) => setNewRuleReplace(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      />
                    </div>
                    <button
                      onClick={async () => {
                        if (!newRuleMatch.trim()) return
                        const rule = await api.addReplaceRule({
                          target: newRuleTarget,
                          matchType: newRuleMatchType,
                          match: newRuleMatch,
                          replace: newRuleReplace,
                        })
                        setReplaceRules((prev) => [...prev, rule])
                        setNewRuleMatch('')
                        setNewRuleReplace('')
                      }}
                      className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold"
                    >
                      Add
                    </button>
                  </div>

                  {/* Divider */}
                  <div className="border-t border-border my-2" />

                  {/* Add Custom Data section */}
                  <h4 className="text-xs font-semibold text-content-primary uppercase tracking-wide">Add Custom Data</h4>
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-content-muted">
                      Automatically add headers, query parameters, or body data to in-scope requests.
                    </p>
                    <button
                      onClick={async () => {
                        const next = !customDataEnabled
                        await api.setCustomDataEnabled(next)
                        setCustomDataEnabled(next)
                      }}
                      className={`ml-3 shrink-0 px-3 py-1.5 rounded-sm text-xs font-semibold transition-colors ${
                        customDataEnabled
                          ? 'bg-accent-tertiary hover:bg-accent-tertiary-hover text-black'
                          : 'bg-surface-input hover:bg-surface-hover border border-border text-content-secondary'
                      }`}
                    >
                      {customDataEnabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>

                  {customDataItems.length === 0 ? (
                    <p className="text-xs text-content-muted italic">No items defined.</p>
                  ) : (
                    <div className="space-y-1 max-h-48 overflow-y-auto">
                      {customDataItems.map((item) => (
                        <div key={item.id} className="flex items-center gap-2 text-xs py-1 border-b border-border-subtle">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-accent-secondary text-black">
                            {item.type}
                          </span>
                          {item.name && <span className="text-content-primary font-mono">{item.name}</span>}
                          {item.name && <span className="text-content-muted">=</span>}
                          <span className="text-semantic-success font-mono truncate max-w-[20rem]">{item.value}</span>
                          <button
                            onClick={async () => {
                              await api.deleteCustomDataItem(item.id)
                              setCustomDataItems((prev) => prev.filter((i) => i.id !== item.id))
                            }}
                            className="ml-auto text-content-muted hover:text-semantic-error"
                          >
                            x
                          </button>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="flex items-end gap-2">
                    <div className="w-28">
                      <label className="block text-[10px] text-content-muted mb-0.5">Type</label>
                      <select
                        value={newItemType}
                        onChange={(e) => setNewItemType(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      >
                        <option value="header">Header</option>
                        <option value="query">Query Param</option>
                        <option value="body">Body</option>
                      </select>
                    </div>
                    {newItemType !== 'body' && (
                      <div className="flex-1">
                        <label className="block text-[10px] text-content-muted mb-0.5">Name</label>
                        <input
                          type="text"
                          placeholder={newItemType === 'header' ? 'X-Custom-Header' : 'param'}
                          value={newItemName}
                          onChange={(e) => setNewItemName(e.target.value)}
                          className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                        />
                      </div>
                    )}
                    <div className="flex-1">
                      <label className="block text-[10px] text-content-muted mb-0.5">Value</label>
                      <input
                        type="text"
                        placeholder={newItemType === 'body' ? 'data to append' : 'value'}
                        value={newItemValue}
                        onChange={(e) => setNewItemValue(e.target.value)}
                        className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                      />
                    </div>
                    <button
                      onClick={async () => {
                        if (!newItemValue.trim()) return
                        if (newItemType !== 'body' && !newItemName.trim()) return
                        const item = await api.addCustomDataItem({
                          type: newItemType,
                          name: newItemType === 'body' ? '' : newItemName.trim(),
                          value: newItemValue.trim(),
                        })
                        setCustomDataItems((prev) => [...prev, item])
                        setNewItemName('')
                        setNewItemValue('')
                      }}
                      className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold"
                    >
                      Add
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ConfigSection({ title, configs, active, onSave, onLoad, onDelete }: {
  title: string
  configs: string[]
  active: string
  onSave: (name: string) => Promise<void>
  onLoad: (name: string) => Promise<void>
  onDelete: (name: string) => Promise<void>
}) {
  const [selected, setSelected] = useState('')
  const [newName, setNewName] = useState('')
  const [saving, setSaving] = useState(false)
  const [loading, setLoading] = useState(false)
  const [msg, setMsg] = useState('')

  return (
    <div className="flex-1 space-y-2">
      <h4 className="text-xs font-semibold text-content-muted uppercase tracking-wide">{title}</h4>

      {/* Select existing */}
      <div className="flex items-center gap-2">
        <select
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          className="flex-1 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
        >
          <option value="">Select a config...</option>
          {configs.map((c) => (
            <option key={c} value={c}>{c}{c === active ? ' (active)' : ''}</option>
          ))}
        </select>
        <button
          disabled={!selected || loading}
          onClick={async () => {
            setLoading(true)
            setMsg('')
            try {
              await onLoad(selected)
              setMsg('Loaded!')
              window.setTimeout(() => setMsg(''), 3000)
            } catch (e) { setMsg(String(e)) }
            finally { setLoading(false) }
          }}
          className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold disabled:opacity-50"
        >
          {loading ? '...' : 'Load'}
        </button>
        <button
          disabled={!selected || saving}
          onClick={async () => {
            if (!confirm(`Are you sure you want to overwrite "${selected}"?`)) return
            setSaving(true)
            setMsg('')
            try {
              await onSave(selected)
              setMsg('Saved!')
              window.setTimeout(() => setMsg(''), 3000)
            } catch (e) { setMsg(String(e)) }
            finally { setSaving(false) }
          }}
          className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
        >
          {saving ? '...' : 'Save'}
        </button>
        <button
          disabled={!selected}
          onClick={async () => {
            if (!confirm(`Delete config "${selected}"?`)) return
            try {
              await onDelete(selected)
              setSelected('')
              setMsg('Deleted')
              window.setTimeout(() => setMsg(''), 3000)
            } catch (e) { setMsg(String(e)) }
          }}
          className="px-3 py-1.5 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary text-xs font-semibold disabled:opacity-50"
        >
          Delete
        </button>
      </div>

      {/* Save new */}
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="Config name"
          className="flex-1 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border placeholder:text-content-muted"
        />
        <button
          disabled={!newName.trim() || saving}
          onClick={async () => {
            setSaving(true)
            setMsg('')
            try {
              await onSave(newName.trim())
              setMsg('Saved!')
              setNewName('')
              window.setTimeout(() => setMsg(''), 3000)
            } catch (e) { setMsg(String(e)) }
            finally { setSaving(false) }
          }}
          className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
        >
          {saving ? '...' : 'Save New'}
        </button>
      </div>

      {msg && <p className={`text-xs ${msg.startsWith('Error') || msg.startsWith('config') ? 'text-semantic-error' : 'text-semantic-success'}`}>{msg}</p>}
    </div>
  )
}

function ConfigManager({ theme, hiddenTabs, onSettingsLoaded, onProjectLoaded }: {
  theme: string
  hiddenTabs: string[]
  onSettingsLoaded: (s: unknown) => void
  onProjectLoaded: (p: unknown) => void
}) {
  const [userConfigs, setUserConfigs] = useState<string[]>([])
  const [activeUser, setActiveUser] = useState('')
  const [projectConfigs, setProjectConfigs] = useState<string[]>([])
  const [activeProject, setActiveProject] = useState('')

  const refresh = async () => {
    try {
      const u = await api.listUserConfigs()
      setUserConfigs(u.configs)
      setActiveUser(u.active)
    } catch { /* empty */ }
    try {
      const p = await api.listProjectConfigs()
      setProjectConfigs(p.configs)
      setActiveProject(p.active)
    } catch { /* empty */ }
  }

  useEffect(() => { refresh() }, [])

  return (
    <div className="bg-surface-card rounded border border-border p-3">
      <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-3">Configurations</h3>
      <div className="flex gap-6">
        <ConfigSection
          title="User Config"
          configs={userConfigs}
          active={activeUser}
          onSave={async (name) => {
            await api.saveUserConfig(name, theme, hiddenTabs)
            await refresh()
          }}
          onLoad={async (name) => {
            const result = await api.loadUserConfig(name)
            onSettingsLoaded(result)
            await refresh()
          }}
          onDelete={async (name) => {
            await api.deleteUserConfig(name)
            await refresh()
          }}
        />
        <ConfigSection
          title="Project Config"
          configs={projectConfigs}
          active={activeProject}
          onSave={async (name) => {
            await api.saveProjectConfig(name)
            await refresh()
          }}
          onLoad={async (name) => {
            const result = await api.loadProjectConfig(name)
            onProjectLoaded(result)
            await refresh()
          }}
          onDelete={async (name) => {
            await api.deleteProjectConfig(name)
            await refresh()
          }}
        />
      </div>
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between text-sm">
      <span className="text-content-secondary">{label}</span>
      <code className="text-content-primary">{value}</code>
    </div>
  )
}

function TeamConfigsPanel({ projectId, onImported }: { projectId: string; onImported: (p: unknown) => void }) {
  const items = useTeamSharedConfigStore((s) => s.items)
  const setItems = useTeamSharedConfigStore((s) => s.setItems)
  const removeItem = useTeamSharedConfigStore((s) => s.removeItem)
  const [publishName, setPublishName] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.listSharedConfigs().then((r) => setItems(r.items || [])).catch(() => {})
  }, [setItems])

  async function publish() {
    if (!publishName.trim()) return
    setBusy(true)
    setMsg('')
    try {
      const exported = await api.exportProjectConfig()
      await api.publishConfig({ name: publishName.trim(), projectId, config: exported.config })
      setPublishName('')
      setMsg('Published!')
      window.setTimeout(() => setMsg(''), 3000)
    } catch (e) {
      setMsg(String(e))
    } finally {
      setBusy(false)
    }
  }

  async function load(id: string, name: string) {
    setMsg('')
    try {
      const cfg = await api.getSharedConfig(id)
      const resp = await api.importProjectConfig(name, cfg.config)
      onImported(resp)
      setMsg(`Loaded "${name}"`)
      window.setTimeout(() => setMsg(''), 3000)
    } catch (e) {
      setMsg(String(e))
    }
  }

  async function del(id: string) {
    removeItem(id)
    try {
      await api.deleteSharedConfig(id)
    } catch { /* ignore */ }
  }

  return (
    <div className="bg-surface-card rounded border border-border p-3 space-y-2">
      <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">Team Configs</h3>
      <p className="text-xs text-content-muted mb-2">
        Publish your current project config to the team, or load one a teammate shared.
      </p>
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Name to publish current config as"
          value={publishName}
          onChange={(e) => setPublishName(e.target.value)}
          className="flex-1 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
        />
        <button
          disabled={busy || !publishName.trim()}
          onClick={publish}
          className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold disabled:opacity-50"
        >
          Publish to team
        </button>
      </div>
      {msg && <p className="text-xs text-content-secondary">{msg}</p>}
      {items.length === 0 ? (
        <p className="text-[10px] text-content-muted italic">No published configs yet</p>
      ) : (
        <div className="divide-y divide-border-subtle">
          {items.map((c) => (
            <div key={c.id} className="flex items-center gap-2 py-1.5 text-xs">
              <span className="text-content-primary font-medium truncate">{c.name}</span>
              {c.projectId && <span className="text-content-muted">[{c.projectId}]</span>}
              <span className="text-content-muted truncate">by {c.author}</span>
              <div className="ml-auto flex gap-2">
                <button
                  onClick={() => load(c.id, c.name)}
                  className="text-accent-secondary hover:underline font-medium"
                >
                  Load
                </button>
                <button
                  onClick={() => del(c.id)}
                  className="text-content-muted hover:text-semantic-error"
                  title="Delete published config"
                >
                  ✕
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
