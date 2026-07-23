import { useCallback, useEffect, useState } from 'react'
import { ArrowRight, X } from 'lucide-react'
import { api, CustomAddition, MatchReplaceRule, NoisePattern, ScopeRule } from '../lib/api'
import { useRequestStore } from '../stores/requestStore'
import { Settings, useSettingsStore } from '../stores/settingsStore'
import { useTeamConnectionStore, type RelayState } from '../stores/teamConnectionStore'
import { useTeamSharedConfigStore } from '../stores/teamSharedConfigStore'
import { useProjectStore } from '../stores/projectStore'

type FilterTab = 'scope' | 'noise' | 'replace'

// teamStatus maps the relay connection state to the Team Server card's status row.
function teamStatus(state: RelayState): { dot: string; label: string } {
  switch (state) {
    case 'connected':
      return { dot: 'bg-semantic-success', label: 'Connected' }
    case 'connecting':
      return { dot: 'bg-semantic-warning', label: 'Connecting…' }
    case 'disconnected':
      return { dot: 'bg-semantic-error', label: 'Disconnected' }
    default:
      return { dot: 'bg-content-muted', label: 'Idle' }
  }
}

// ProjectSettings renders the settings that live in the active project's config:
// team server connection, shared team configs, and the scope / noise / match&replace
// / custom-data filtering rules. It hydrates from live state on mount and on
// `joro:project-changed` (fired by a project switch/import), and dispatches that
// same event after a team connect/disconnect so the app re-evaluates team mode.
export default function ProjectSettings() {
  const setSettings = useSettingsStore((s) => s.setSettings)
  const teamConn = useTeamConnectionStore((s) => s.state)
  const teamConnError = useTeamConnectionStore((s) => s.error)
  const teamConnHTTP = useTeamConnectionStore((s) => s.httpStatus)

  // Team server state — seed from the already-hydrated settings store so the
  // fields render immediately on mount, ahead of the getSettings() refresh below.
  const initialSettings = useSettingsStore.getState().settings
  const [listenerUrl, setListenerUrl] = useState(initialSettings?.listenerUrl || '')
  const [teamToken, setTeamToken] = useState(initialSettings?.teamToken || '')
  const [teamNickname, setTeamNickname] = useState(initialSettings?.teamNickname || '')
  const [teamSaved, setTeamSaved] = useState(false)
  const [teamError, setTeamError] = useState('')
  const [teamLoading, setTeamLoading] = useState(false)

  const [unknownPluginStatesNotice, setUnknownPluginStatesNotice] = useState<string[]>([])

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

  // refetchLive pulls the project's team fields + scope/noise/replace/customdata
  // into local state. Run on mount and on `joro:project-changed`.
  const refetchLive = useCallback(() => {
    api.getSettings().then((s) => {
      const st = s as Settings
      setSettings(st)
      setListenerUrl(st.listenerUrl || '')
      setTeamToken(st.teamToken || '')
      setTeamNickname(st.teamNickname || '')
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
  }, [setSettings])

  useEffect(() => {
    refetchLive()
    const onProjectChanged = () => refetchLive()
    window.addEventListener('joro:project-changed', onProjectChanged)
    return () => window.removeEventListener('joro:project-changed', onProjectChanged)
  }, [refetchLive])

  // Apply an imported project config (from the Team Configs panel) to live UI state.
  const applyProjectResp = (p: unknown) => {
    const proj = p as {
      listenerUrl?: string; teamToken?: string; teamNickname?: string
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
    setUnknownPluginStatesNotice(proj.unknownPluginStates || [])
    useRequestStore.getState().invalidate()
    api.getSettings().then((s) => setSettings(s as Settings))
    window.dispatchEvent(new CustomEvent('joro:project-changed'))
  }

  return (
    <div className="space-y-4">
      {unknownPluginStatesNotice.length > 0 && (
        <div className="bg-surface-card rounded border border-border p-3 text-xs text-content-secondary">
          State preserved for: <span className="text-semantic-warning font-semibold">{unknownPluginStatesNotice.join(', ')}</span>
          {' '}&mdash; these plugins aren't installed on this system. The blobs round-trip on re-save.
        </div>
      )}

      {/* Team Server */}
      <div className="bg-surface-card rounded border border-border p-3 space-y-2">
        <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wide mb-2">Team Server</h3>
        <p className="text-xs text-content-muted mb-2">
          Connect to a remote team server for shared chat and notes.
        </p>
        {listenerUrl && (
          <div className="flex items-center gap-1.5 text-xs mb-2">
            <span className={`w-2 h-2 rounded-full ${teamStatus(teamConn).dot}`} />
            <span className="text-content-secondary">{teamStatus(teamConn).label}</span>
            {teamConn === 'disconnected' && teamConnError && (
              <span className="text-content-muted truncate">
                — {teamConnError}{teamConnHTTP ? ` (HTTP ${teamConnHTTP})` : ''}
              </span>
            )}
          </div>
        )}
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
                  window.dispatchEvent(new CustomEvent('joro:project-changed'))
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
                window.dispatchEvent(new CustomEvent('joro:project-changed'))
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

      {/* Team Configs (shared project configs) — team mode only */}
      {listenerUrl.trim() && (
        <TeamConfigsPanel onImported={applyProjectResp} />
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
                      <span className="text-content-muted inline-flex items-center"><ArrowRight size={12} /></span>
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
  )
}

function TeamConfigsPanel({ onImported }: { onImported: (p: unknown) => void }) {
  const items = useTeamSharedConfigStore((s) => s.items)
  const setItems = useTeamSharedConfigStore((s) => s.setItems)
  const removeItem = useTeamSharedConfigStore((s) => s.removeItem)
  const activeProject = useProjectStore((s) => s.active)
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
      await api.publishConfig({ name: publishName.trim(), project: activeProject, config: exported.config })
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
              {c.project && <span className="text-content-muted">[{c.project}]</span>}
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
                  className="text-content-muted hover:text-semantic-error inline-flex items-center"
                  title="Delete published config"
                >
                  <X size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
