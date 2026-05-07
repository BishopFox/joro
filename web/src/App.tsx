import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Toasts from './components/Toasts'
import UpdateBanner from './components/UpdateBanner'
import { Navigate, NavLink, Route, Routes } from 'react-router-dom'
import ContextMenu from './components/ContextMenu'
import { getSelectionMenuItems } from './lib/selectionMenu'
import { api } from './lib/api'
import { connectWS } from './lib/ws'
import { Settings, useSettingsStore } from './stores/settingsStore'
import { useHiddenTabsStore } from './stores/hiddenTabsStore'
import { NAV } from './lib/nav'
import { currentTheme } from './lib/theme'
import Callbacks from './pages/Callbacks'
import History from './pages/History'
import Intercept from './pages/Intercept'
import Manipulate from './pages/Manipulate'
import Fuzz from './pages/Fuzz'
import Generator from './pages/Generator'
import Executor from './pages/Executor'
import Transform from './pages/Transform'
import Dashboard from './pages/Dashboard'
import Map from './pages/Map'
import Login from './pages/Login'
import Notes from './pages/Notes'
import Setup from './pages/Setup'
import Plugins from './pages/Plugins'
import PluginTabPage from './pages/PluginTabPage'
import SettingsPage from './pages/Settings'

export default function App() {
  const navigate = useNavigate()
  const { settings, setSettings } = useSettingsStore()
  const [setupMode, setSetupMode] = useState<string | null>(
    () => localStorage.getItem('joro-setup-mode')
  )
  const [teamMode, setTeamMode] = useState(false)
  const [needsAuth, setNeedsAuth] = useState(false)
  const [pluginTabs, setPluginTabs] = useState<Array<{ to: string; label: string }>>([])
  const [dashboardPlugin, setDashboardPlugin] = useState<string | null>(null)
  const hiddenTabs = useHiddenTabsStore((s) => s.hiddenTabs)

  const checkTeamMode = useCallback(async () => {
    // Detect backend restart: if the session ID changed, clear setup state
    // so the user goes through the setup flow again.
    try {
      const { sessionId } = await api.getMode()
      const storedSession = localStorage.getItem('joro-session-id')
      if (storedSession !== sessionId) {
        localStorage.removeItem('joro-setup-mode')
        localStorage.setItem('joro-session-id', sessionId)
      }
    } catch {
      // Backend not reachable yet — leave setup state as-is.
    }

    const mode = localStorage.getItem('joro-setup-mode')
    setSetupMode(mode)
    if (!mode) return

    try {
      const s = await api.getSettings() as Settings
      setSettings(s)
      if (s.listenerUrl) {
        if (s.teamToken && s.teamNickname) {
          setTeamMode(true)
          setNeedsAuth(false)
        } else {
          // Listener URL is configured but no credentials — prompt for login.
          setNeedsAuth(true)
        }
      } else {
        setTeamMode(false)
        setNeedsAuth(false)
      }
    } catch {
      // ignore
    }
  }, [setSettings])

  useEffect(() => {
    connectWS()
    checkTeamMode()

    // Load plugin tabs.
    api.listPlugins().then((plugs) => {
      setPluginTabs(
        plugs
          .filter((e) => e.type === 'tab' && e.status === 'loaded')
          .map((e) => ({ to: `/plugin/${e.name}`, label: e.tabLabel || e.name }))
      )
      const dash = plugs.find((e) => e.type === 'dashboard' && e.status === 'loaded')
      if (dash) setDashboardPlugin(dash.name)
    }).catch(() => {})
  }, [checkTeamMode])

  const [globalCtxMenu, setGlobalCtxMenu] = useState<{ x: number; y: number } | null>(null)

  function handleGlobalContextMenu(e: React.MouseEvent) {
    if (e.defaultPrevented) return
    const items = getSelectionMenuItems(navigate)
    if (items.length === 0) return
    e.preventDefault()
    setGlobalCtxMenu({ x: e.clientX, y: e.clientY })
  }

  if (setupMode === null) {
    return <Setup onSetupComplete={(mode) => {
      localStorage.setItem('joro-setup-mode', mode)
      setSetupMode(mode)
      checkTeamMode()
    }} />
  }

  if (needsAuth) {
    return <Login onAuthenticated={() => { setNeedsAuth(false); setTeamMode(true); checkTeamMode() }} />
  }

  // Insert plugin top-level tabs between Plugins and Settings.
  const filteredNav = (() => {
    const nav = [...NAV]
    if (pluginTabs.length > 0) {
      const settingsIdx = nav.findIndex((n) => n.to === '/settings')
      if (settingsIdx !== -1) {
        nav.splice(settingsIdx, 0, ...pluginTabs)
      }
    }
    return nav.filter((n) => n.to === '/settings' || !hiddenTabs.includes(n.to))
  })()

  return (
    <div className="flex flex-col h-screen">
      <Toasts />
      <UpdateBanner />
      {/* Top nav */}
      <header className="flex items-center gap-0.5 px-2 lg:px-3 h-10 bg-surface-card border-b border-border shrink-0 overflow-x-auto">
        <span className="text-accent text-sm font-bold uppercase tracking-wider mr-3 lg:mr-6 shrink-0">Joro</span>
        {filteredNav.map(({ to, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `px-2 lg:px-3 py-1.5 rounded-sm text-xs tracking-wide transition-colors shrink-0 ${
                isActive
                  ? 'bg-accent text-content-primary'
                  : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
              }`
            }
          >
            {label}
          </NavLink>
        ))}
        {teamMode && settings?.teamNickname && (
          <span className="ml-auto flex items-center gap-1.5 text-xs text-content-secondary">
            <span className="w-2 h-2 rounded-full bg-semantic-success" />
            {settings.teamNickname}
          </span>
        )}
      </header>

      {/* Page content */}
      <main className="flex-1 min-h-0 overflow-hidden flex flex-col" onContextMenu={handleGlobalContextMenu}>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={
            dashboardPlugin
              ? <iframe src={`/plugin/${dashboardPlugin}/?theme=${currentTheme()}`} className="w-full h-full border-0" sandbox="allow-scripts allow-forms" title="Dashboard" />
              : <Dashboard teamMode={teamMode} />
          } />
          <Route path="/map" element={<Map />} />
          <Route path="/history" element={<History />} />
          <Route path="/intercept" element={<Intercept />} />
          <Route path="/manipulate" element={<Manipulate />} />
          <Route path="/fuzz" element={<Fuzz />} />
          <Route path="/generator" element={<Generator />} />
          <Route path="/executor" element={<Executor />} />
          <Route path="/callbacks" element={<Callbacks />} />
          <Route path="/notes" element={<Notes teamMode={teamMode} />} />
          <Route path="/transform" element={<Transform />} />
          <Route path="/plugins" element={<Plugins />} />
          <Route path="/plugin/:extName/*" element={<PluginTabPage />} />
          <Route path="/settings" element={<SettingsPage onTeamSettingsChanged={checkTeamMode} />} />
        </Routes>
      </main>

      {globalCtxMenu && (() => {
        const items = getSelectionMenuItems(navigate)
        return items.length > 0 ? (
          <ContextMenu
            x={globalCtxMenu.x}
            y={globalCtxMenu.y}
            onClose={() => setGlobalCtxMenu(null)}
            items={items}
          />
        ) : null
      })()}
    </div>
  )
}
