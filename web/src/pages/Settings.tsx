import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import ProjectBrowser from '../components/ProjectBrowser'
import { Settings, useSettingsStore } from '../stores/settingsStore'
import { useUpdateStore } from '../stores/updateStore'
import { useHiddenTabsStore } from '../stores/hiddenTabsStore'
import ConfirmModal from '../components/ConfirmModal'
import HealthCheck from '../components/HealthCheck'
import { useToastStore } from '../stores/toastStore'
import { getBrowserPrefs, setBrowserPrefs } from '../lib/browserPrefs'
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

type Category = 'project' | 'general' | 'appearance' | 'testing'

const CATEGORIES: { id: Category; label: string; icon: ReactNode }[] = [
  {
    id: 'general',
    label: 'General',
    icon: (
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="3" />
        <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M18.4 5.6L17 7M7 17l-1.4 1.4" />
      </svg>
    ),
  },
  {
    id: 'appearance',
    label: 'Appearance',
    icon: (
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="8.5" />
        <circle cx="8.5" cy="10" r="1" fill="currentColor" stroke="none" />
        <circle cx="12" cy="8" r="1" fill="currentColor" stroke="none" />
        <circle cx="15.5" cy="10" r="1" fill="currentColor" stroke="none" />
        <path d="M12 20.5c1.5 0 2-1 2-2s-1-1.5-1-2.5 1-1.5 2.5-1.5S20 12 20 10.5" />
      </svg>
    ),
  },
  {
    id: 'project',
    label: 'Project',
    icon: (
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
      </svg>
    ),
  },
  {
    id: 'testing',
    label: 'Testing Browser',
    icon: (
      <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <rect x="3" y="4" width="18" height="16" rx="2" />
        <path d="M3 8 H21" />
        <circle cx="6" cy="6" r="0.5" fill="currentColor" stroke="none" />
        <circle cx="8" cy="6" r="0.5" fill="currentColor" stroke="none" />
      </svg>
    ),
  },
]

export default function SettingsPage() {
  const { settings, setSettings } = useSettingsStore()
  const { info: updateInfo, setInfo: setUpdateInfo } = useUpdateStore()
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  const location = useLocation()
  const navigate = useNavigate()
  const [category, setCategory] = useState<Category>(
    () => ((location.state as { category?: Category } | null)?.category) || 'general'
  )

  // Deep-link from the header project dropdown ("Manage…"): open a specific
  // sub-menu, then clear the nav state so a reload/back doesn't re-pin it.
  useEffect(() => {
    const cat = (location.state as { category?: Category } | null)?.category
    if (cat) {
      setCategory(cat)
      navigate('/settings', { replace: true, state: {} })
    }
  }, [location.state, navigate])

  // Update check state
  const [checking, setChecking] = useState(false)
  const [checkError, setCheckError] = useState('')
  const [justChecked, setJustChecked] = useState(false)

  // Testing browser + health check state
  const addToast = useToastStore((s) => s.addToast)
  const [browserAvail, setBrowserAvail] = useState<{ available: boolean; browser: string } | null>(null)
  const [showHealthCheck, setShowHealthCheck] = useState(false)
  const [browserUrl, setBrowserUrl] = useState(() => getBrowserPrefs().url)
  const [clearingCookies, setClearingCookies] = useState(false)

  useEffect(() => {
    api.browserStatus().then(setBrowserAvail).catch(() => {})
  }, [])

  async function clearTestingBrowserCookies() {
    setClearingCookies(true)
    try {
      await api.clearBrowserCookies()
      addToast('Cleared testing browser cookies — relaunch it if open', 'info')
    } catch (e) {
      addToast(`Clear cookies failed: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setClearingCookies(false)
    }
  }

  // SOCKS proxy state
  const [socksHost, setSocksHost] = useState('')
  const [socksPort, setSocksPort] = useState('')
  const [socksUsername, setSocksUsername] = useState('')
  const [socksPassword, setSocksPassword] = useState('')
  const [socksDns, setSocksDns] = useState(false)

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

  // refetchLive pulls the user/machine settings into local state on mount.
  const refetchLive = useCallback(() => {
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
    })
  }, [setSettings])

  useEffect(() => {
    refetchLive()
    api.listPlugins().then((plugs) => {
      setPluginTabs(
        plugs
          .filter((p) => p.type === 'tab' && p.status === 'loaded')
          .map((p) => ({ to: `/plugin/${p.name}`, label: p.tabLabel || p.name }))
      )
    }).catch(() => {})
  }, [refetchLive])

  // save persists the General → Proxy group: intercept/max-requests + SOCKS.
  async function save() {
    setError('')
    try {
      const updated = await api.updateSettings({
        interceptTimeout,
        maxRequests,
        socksHost,
        socksPort: socksPort ? Number(socksPort) : 0,
        socksUsername,
        socksPassword,
        socksDns,
      })
      setSettings(updated as Settings)
      setSaved(true)
      window.setTimeout(() => setSaved(false), 3000)
    } catch (e) {
      setError(String(e))
    }
  }

  const inputCls = 'bg-surface-input text-xs px-2 py-1 rounded-sm border border-border'

  return (
    <div className="h-full flex gap-4 p-4 min-h-0">
      {/* Sidebar */}
      <nav className="w-44 shrink-0 flex flex-col gap-0.5">
        <h2 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-muted px-3 pt-1 pb-2">Settings</h2>
        {CATEGORIES.map((c) => {
          const active = category === c.id
          return (
            <button
              key={c.id}
              onClick={() => setCategory(c.id)}
              className={`flex items-center gap-2.5 px-3 py-2 rounded-md text-xs text-left border-l-2 transition-colors ${
                active
                  ? 'bg-surface-card text-content-primary border-accent-secondary font-medium'
                  : 'text-content-secondary hover:text-content-primary hover:bg-surface-hover border-transparent'
              }`}
            >
              <span className="shrink-0">{c.icon}</span>
              <span className="truncate">{c.label}</span>
            </button>
          )
        })}
      </nav>

      {/* Content pane */}
      <div className="flex-1 min-h-0">
        <div className="h-full overflow-y-auto bg-surface-card rounded-lg p-5 shadow-sm">
          {category === 'project' && <ProjectBrowser />}

          {settings && category === 'general' && (
            <div className="grid grid-cols-1 lg:grid-cols-2">
              {/* Column A */}
              <div className="divide-y divide-border lg:pr-8">
                <Group title="Proxy">
                  <Rows>
                    <Row label="Max requests" title="Capacity of the in-memory capture history buffer.">
                      <input
                        type="number"
                        min={100}
                        max={100000}
                        value={maxRequests}
                        onChange={(e) => setMaxRequests(Number(e.target.value))}
                        className={`w-24 text-right ${inputCls}`}
                      />
                    </Row>
                    <Row label="Auto-forward (s)" title="Seconds an intercepted request waits before auto-forwarding.">
                      <input
                        type="number"
                        min={1}
                        value={interceptTimeout}
                        onChange={(e) => setInterceptTimeout(Number(e.target.value))}
                        className={`w-24 text-right ${inputCls}`}
                      />
                    </Row>
                  </Rows>
                  <SubLabel>SOCKS upstream</SubLabel>
                  <div className="space-y-1.5">
                    <div className="flex gap-1.5">
                      <input type="text" placeholder="Host" value={socksHost} onChange={(e) => setSocksHost(e.target.value)} className={`flex-1 min-w-0 ${inputCls}`} />
                      <input type="number" placeholder="Port" value={socksPort} onChange={(e) => setSocksPort(e.target.value)} className={`w-20 ${inputCls}`} />
                    </div>
                    <div className="flex gap-1.5">
                      <input type="text" placeholder="User" value={socksUsername} onChange={(e) => setSocksUsername(e.target.value)} className={`flex-1 min-w-0 ${inputCls}`} />
                      <input type="password" placeholder="Password" value={socksPassword} onChange={(e) => setSocksPassword(e.target.value)} className={`flex-1 min-w-0 ${inputCls}`} />
                    </div>
                  </div>
                  <div className="divide-y divide-border-subtle mt-1">
                    <Row label="DNS over SOCKS" title="Resolve hostnames through the SOCKS proxy instead of locally.">
                      <Switch checked={socksDns} onChange={setSocksDns} />
                    </Row>
                  </div>
                  <div className="flex items-center justify-end gap-2 pt-2.5">
                    {error && <span className="text-semantic-error text-[11px] mr-auto truncate">{error}</span>}
                    {saved && <span className="text-semantic-success text-[11px]">Saved!</span>}
                    <button
                      onClick={save}
                      className="px-2.5 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-[11px] font-semibold"
                    >
                      Save
                    </button>
                  </div>
                </Group>

                <Group title="Connection">
                  <Rows>
                    <Row
                      label="Default to HTTP/2"
                      title="Advertise h2 in browser-side ALPN and forward upstream as HTTP/2 when supported. Disable to force HTTP/1.1 everywhere. Takes effect on new connections."
                    >
                      <Switch
                        checked={!!settings.http2Enabled}
                        onChange={async (v) => {
                          const updated = await api.updateSettings({ http2Enabled: v })
                          setSettings(updated as Settings)
                        }}
                      />
                    </Row>
                    <Row label="HTTP/1 keep-alive" title="Reuse upstream HTTP/1.1 connections across requests.">
                      <Switch
                        checked={!!settings.keepAliveEnabled}
                        onChange={async (v) => {
                          const updated = await api.updateSettings({ keepAliveEnabled: v })
                          setSettings(updated as Settings)
                        }}
                      />
                    </Row>
                  </Rows>
                </Group>
              </div>

              {/* Column B */}
              <div className="divide-y divide-border border-t border-border pt-5 lg:pt-0 lg:border-t-0 lg:pl-8 lg:border-l lg:border-border">
                <Group title="Server">
                  <Rows>
                    <Row label="Proxy port"><ValueChip>{`:${settings.proxyPort}`}</ValueChip></Row>
                    <Row label="UI port"><ValueChip>{`:${settings.uiPort}`}</ValueChip></Row>
                    {updateInfo && (
                      <Row label="Version">
                        <ValueChip>{updateInfo.version}{updateInfo.commit ? ` · ${updateInfo.commit}` : ''}</ValueChip>
                      </Row>
                    )}
                    <Row label="Update checks" title="Periodically check GitHub for a newer Joro release.">
                      <Switch
                        checked={!settings.disableUpdateChecks}
                        onChange={async (v) => {
                          const updated = await api.updateSettings({ disableUpdateChecks: !v })
                          setSettings(updated as Settings)
                        }}
                      />
                    </Row>
                    <Row
                      label={
                        <span>
                          Software updates
                          {checkError && <span className="text-semantic-error"> · {checkError}</span>}
                          {justChecked && updateInfo && !updateInfo.updateAvailable && <span className="text-semantic-success"> · up to date</span>}
                        </span>
                      }
                    >
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
                        className="px-2.5 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-[11px] font-semibold disabled:opacity-60"
                      >
                        {checking ? 'Checking…' : 'Check now'}
                      </button>
                    </Row>
                  </Rows>
                </Group>

                <Group title="User Config">
                  <p className="text-[11px] text-content-muted leading-relaxed mb-2">
                    Save and restore machine-level preferences (SOCKS, HTTP/2, theme, hidden tabs) as named snapshots.
                  </p>
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
                  }} />
                  {unknownPluginStatesNotice.length > 0 && (
                    <div className="mt-2 border-l-2 border-semantic-warning pl-2.5 py-1 text-[10px] text-content-secondary leading-relaxed">
                      State preserved for <span className="text-semantic-warning font-semibold">{unknownPluginStatesNotice.join(', ')}</span> — not installed here; blobs round-trip on re-save.
                    </div>
                  )}
                </Group>
              </div>
            </div>
          )}

          {settings && category === 'appearance' && (
            <div className="max-w-xl divide-y divide-border">
              <Group title="Theme">
                <Row label="Theme">
                  <select
                    value={theme}
                    onChange={(e) => {
                      const t = e.target.value
                      setTheme(t)
                      document.documentElement.setAttribute('data-theme', t)
                      localStorage.setItem('joro-theme', t)
                    }}
                    className={inputCls}
                  >
                    {THEMES.map((t) => (
                      <option key={t.value} value={t.value}>{t.label}</option>
                    ))}
                  </select>
                </Row>
              </Group>

              <Group title="Visible tabs">
                <p className="text-[11px] text-content-muted mb-2">Hide tabs you don't use from the header nav.</p>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-4 gap-y-1.5">
                  {[...NAV.filter((n) => n.to !== '/settings'), ...pluginTabs].map((t) => (
                    <label key={t.to} className="flex items-center gap-1.5 text-[11px] text-content-secondary cursor-pointer">
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
              </Group>
            </div>
          )}

          {settings && category === 'testing' && (
            <div className="max-w-xl">
              <Group title="Testing Browser">
                <p className="text-[11px] text-content-muted leading-relaxed mb-3">
                  Opens a browser routed through the proxy with the CA trusted, using a separate profile per
                  project. With no project loaded, the profile is temporary and cleared when the browser closes.
                  Launch it from the browser icon in the header (top-right).
                </p>
                <div className="mb-3">
                  <label className="block text-[10px] text-content-muted mb-0.5">Landing URL (optional)</label>
                  <input
                    type="text"
                    value={browserUrl}
                    onChange={(e) => {
                      setBrowserUrl(e.target.value)
                      setBrowserPrefs({ url: e.target.value })
                    }}
                    placeholder="about:blank"
                    className={`w-full ${inputCls}`}
                  />
                </div>
                <div className="flex flex-wrap gap-1.5 mb-2">
                  <button
                    onClick={clearTestingBrowserCookies}
                    disabled={clearingCookies}
                    title="Clears cookies for this project's testing-browser profile only. Close the browser first."
                    className="px-2.5 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-[11px] font-semibold disabled:opacity-50"
                  >
                    {clearingCookies ? 'Clearing…' : 'Clear Cookies'}
                  </button>
                  <button
                    onClick={() => setShowHealthCheck(true)}
                    className="px-2.5 py-1 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-[11px] font-semibold"
                  >
                    Setup Check
                  </button>
                  <a
                    href={api.caCertURL()}
                    download="joro-ca.crt"
                    title="Import into your own browser/OS trust store to avoid TLS warnings."
                    className="px-2.5 py-1 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-[11px] font-semibold"
                  >
                    Download CA
                  </a>
                </div>
                <p className="text-[10px] text-content-muted">
                  {browserAvail && !browserAvail.available
                    ? <span className="text-semantic-warning">No supported browser detected (Chrome, Chromium, Edge, or Brave).</span>
                    : browserAvail?.available
                      ? <>Detected {browserAvail.browser}.</>
                      : null}
                </p>
              </Group>
            </div>
          )}
        </div>
      </div>

      {showHealthCheck && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
          onMouseDown={() => setShowHealthCheck(false)}
        >
          <div onMouseDown={(e) => e.stopPropagation()}>
            <HealthCheck onFinish={() => setShowHealthCheck(false)} />
          </div>
        </div>
      )}
    </div>
  )
}

// --- Presentational helpers ---

// Group is a borderless titled sub-section rendered inside the content card.
function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="py-5 first:pt-0 last:pb-0">
      <div className="flex items-center gap-2 mb-2">
        <span className="w-1 h-3 rounded-full bg-accent-secondary shrink-0" />
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.14em] text-content-muted">{title}</h3>
      </div>
      {children}
    </section>
  )
}

function Rows({ children }: { children: ReactNode }) {
  return <div className="divide-y divide-border-subtle">{children}</div>
}

function Row({ label, title, children }: { label: ReactNode; title?: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5" title={title}>
      <span className="text-xs text-content-secondary min-w-0 truncate">{label}</span>
      <div className="shrink-0 flex items-center gap-2">{children}</div>
    </div>
  )
}

function SubLabel({ children }: { children: ReactNode }) {
  return <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-content-muted mt-2.5 mb-1.5">{children}</div>
}

function Switch({ checked, onChange, title }: { checked: boolean; onChange: (v: boolean) => void; title?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      title={title}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-4 w-8 shrink-0 items-center rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-secondary ${
        checked ? 'bg-accent-secondary' : 'bg-surface-input border border-border'
      }`}
    >
      <span className={`inline-block h-3 w-3 rounded-full bg-content-primary transition-transform ${checked ? 'translate-x-4' : 'translate-x-0.5'}`} />
    </button>
  )
}

function ValueChip({ children }: { children: ReactNode }) {
  return <code className="font-mono text-[11px] bg-surface-input text-content-primary px-1.5 py-0.5 rounded-sm">{children}</code>
}

function ConfigSection({ configs, active, onSave, onLoad, onDelete }: {
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
  const [confirmState, setConfirmState] = useState<{
    message: string
    confirmLabel: string
    danger: boolean
    onConfirm: () => void
  } | null>(null)

  const btn = 'px-2 py-1 rounded-sm text-[11px] font-semibold disabled:opacity-50'

  return (
    <div className="space-y-1.5">
      <select
        value={selected}
        onChange={(e) => setSelected(e.target.value)}
        className="w-full bg-surface-input text-xs px-2 py-1 rounded-sm border border-border"
      >
        <option value="">Select a config…</option>
        {configs.map((c) => (
          <option key={c} value={c}>{c}{c === active ? ' (active)' : ''}</option>
        ))}
      </select>

      <div className="flex gap-1.5">
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
          className={`${btn} bg-accent-secondary hover:bg-accent-secondary-hover text-black`}
        >
          {loading ? '…' : 'Load'}
        </button>
        <button
          disabled={!selected || saving}
          onClick={() => setConfirmState({
            message: `Are you sure you want to overwrite "${selected}"?`,
            confirmLabel: 'Overwrite',
            danger: false,
            onConfirm: async () => {
              setSaving(true)
              setMsg('')
              try {
                await onSave(selected)
                setMsg('Saved!')
                window.setTimeout(() => setMsg(''), 3000)
              } catch (e) { setMsg(String(e)) }
              finally { setSaving(false) }
            },
          })}
          className={`${btn} bg-accent-tertiary hover:bg-accent-tertiary-hover text-black`}
        >
          {saving ? '…' : 'Save'}
        </button>
        <button
          disabled={!selected}
          onClick={() => setConfirmState({
            message: `Delete config "${selected}"?`,
            confirmLabel: 'Delete',
            danger: true,
            onConfirm: async () => {
              try {
                await onDelete(selected)
                setSelected('')
                setMsg('Deleted')
                window.setTimeout(() => setMsg(''), 3000)
              } catch (e) { setMsg(String(e)) }
            },
          })}
          className={`${btn} bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary`}
        >
          Delete
        </button>
      </div>

      <div className="flex gap-1.5">
        <input
          type="text"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="Save as new…"
          className="flex-1 min-w-0 bg-surface-input text-xs px-2 py-1 rounded-sm border border-border placeholder:text-content-muted"
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
          className={`${btn} bg-accent-tertiary hover:bg-accent-tertiary-hover text-black`}
        >
          {saving ? '…' : 'Save'}
        </button>
      </div>

      {msg && <p className={`text-[11px] ${msg.startsWith('Error') || msg.startsWith('config') ? 'text-semantic-error' : 'text-semantic-success'}`}>{msg}</p>}

      {confirmState && (
        <ConfirmModal
          message={confirmState.message}
          confirmLabel={confirmState.confirmLabel}
          danger={confirmState.danger}
          onConfirm={() => {
            const fn = confirmState.onConfirm
            setConfirmState(null)
            fn()
          }}
          onClose={() => setConfirmState(null)}
        />
      )}
    </div>
  )
}

function ConfigManager({ theme, hiddenTabs, onSettingsLoaded }: {
  theme: string
  hiddenTabs: string[]
  onSettingsLoaded: (s: unknown) => void
}) {
  const [userConfigs, setUserConfigs] = useState<string[]>([])
  const [activeUser, setActiveUser] = useState('')

  const refresh = async () => {
    try {
      const u = await api.listUserConfigs()
      setUserConfigs(u.configs)
      setActiveUser(u.active)
    } catch { /* empty */ }
  }

  useEffect(() => { refresh() }, [])

  return (
    <ConfigSection
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
  )
}
