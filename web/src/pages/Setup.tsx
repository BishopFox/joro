import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { Settings, useSettingsStore } from '../stores/settingsStore'

interface Props {
  onSetupComplete: (mode: 'local' | 'remote') => void
}

export default function Setup({ onSetupComplete }: Props) {
  const { setSettings } = useSettingsStore()
  const [listenerUrl, setListenerUrl] = useState('')
  const [token, setToken] = useState('')
  const [nickname, setNickname] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  // Config loading state
  const [userConfigs, setUserConfigs] = useState<string[]>([])
  const [projectConfigs, setProjectConfigs] = useState<string[]>([])
  const [selectedUserConfig, setSelectedUserConfig] = useState('')
  const [selectedProjectConfig, setSelectedProjectConfig] = useState('')
  const [configLoading, setConfigLoading] = useState(false)
  const [configError, setConfigError] = useState('')

  useEffect(() => {
    api.listUserConfigs().then((r) => setUserConfigs(r.configs)).catch(() => {})
    api.listProjectConfigs().then((r) => setProjectConfigs(r.configs)).catch(() => {})
  }, [])

  async function handleRemote(e: React.FormEvent) {
    e.preventDefault()
    if (!listenerUrl.trim() || !token.trim() || !nickname.trim()) {
      setError('All fields are required')
      return
    }

    setLoading(true)
    setError('')

    try {
      const updated = await api.updateSettings({
        listenerUrl: listenerUrl.trim(),
        teamToken: token.trim(),
        teamNickname: nickname.trim(),
      })
      setSettings(updated as Settings)

      // Validate credentials by making an authenticated request to the listener.
      await api.listTokens()

      onSetupComplete('remote')
    } catch {
      setError('Connection failed. Check the URL and auth token.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex items-center justify-center h-screen bg-surface-body">
      <div className="space-y-6">
        <div className="text-center">
          <h1 className="text-accent text-2xl font-bold uppercase tracking-wider">Joro</h1>
          <p className="text-content-muted text-xs mt-1">Choose how to get started</p>
        </div>

        <div className="flex flex-wrap gap-4 justify-center">
          {/* Local Proxy */}
          <div className="w-72 max-w-full bg-surface-card border border-border rounded p-5 flex flex-col">
            <h2 className="text-sm font-semibold text-content-primary mb-1">Local Proxy</h2>
            <p className="text-xs text-content-muted mb-4 flex-1">
              Run Joro as a local intercepting proxy. No authentication required.
            </p>
            <button
              onClick={() => onSetupComplete('local')}
              className="w-full px-4 py-2 bg-accent-tertiary text-black text-xs font-semibold rounded hover:bg-accent-tertiary-hover"
            >
              Continue
            </button>
          </div>

          {/* Remote Listener */}
          <form
            onSubmit={handleRemote}
            className="w-72 max-w-full bg-surface-card border border-border rounded p-5 space-y-3"
          >
            <h2 className="text-sm font-semibold text-content-primary mb-1">Remote Listener</h2>
            <p className="text-xs text-content-muted">
              Connect to a remote listener or team server.
            </p>

            <div>
              <label className="block text-[10px] text-content-muted mb-0.5">Listener URL</label>
              <input
                type="text"
                value={listenerUrl}
                onChange={(e) => setListenerUrl(e.target.value)}
                placeholder="http://listener:9090"
                className="w-full bg-surface-input text-content-primary text-xs px-3 py-2 rounded border border-border placeholder:text-content-muted focus:outline-none focus:border-accent-secondary"
              />
            </div>

            <div>
              <label className="block text-[10px] text-content-muted mb-0.5">Auth Token</label>
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Paste the listener auth token"
                className="w-full bg-surface-input text-content-primary text-xs px-3 py-2 rounded border border-border placeholder:text-content-muted focus:outline-none focus:border-accent-secondary"
              />
            </div>

            <div>
              <label className="block text-[10px] text-content-muted mb-0.5">Nickname</label>
              <input
                type="text"
                value={nickname}
                onChange={(e) => setNickname(e.target.value)}
                placeholder="Your display name"
                className="w-full bg-surface-input text-content-primary text-xs px-3 py-2 rounded border border-border placeholder:text-content-muted focus:outline-none focus:border-accent-secondary"
              />
            </div>

            {error && (
              <p className="text-semantic-error text-xs">{error}</p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full px-4 py-2 bg-accent-secondary text-black text-xs font-semibold rounded hover:bg-accent-secondary-hover disabled:opacity-50"
            >
              {loading ? 'Connecting...' : 'Connect'}
            </button>
          </form>

          {/* Load Config */}
          <div className="w-72 max-w-full bg-surface-card border border-border rounded p-5 flex flex-col space-y-3">
            <h2 className="text-sm font-semibold text-content-primary mb-1">Load Config</h2>
            <p className="text-xs text-content-muted">
              Load saved user and/or project configurations.
            </p>

            <div>
              <label className="block text-[10px] text-content-muted mb-0.5">User Config</label>
              <select
                value={selectedUserConfig}
                onChange={(e) => setSelectedUserConfig(e.target.value)}
                className="w-full bg-surface-input text-content-primary text-xs px-3 py-2 rounded border border-border"
              >
                <option value="">None</option>
                {userConfigs.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[10px] text-content-muted mb-0.5">Project Config</label>
              <select
                value={selectedProjectConfig}
                onChange={(e) => setSelectedProjectConfig(e.target.value)}
                className="w-full bg-surface-input text-content-primary text-xs px-3 py-2 rounded border border-border"
              >
                <option value="">None</option>
                {projectConfigs.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>

            {configError && (
              <p className="text-semantic-error text-xs">{configError}</p>
            )}

            <div className="flex-1" />
            <button
              disabled={(!selectedUserConfig && !selectedProjectConfig) || configLoading}
              onClick={async () => {
                setConfigLoading(true)
                setConfigError('')
                try {
                  if (selectedUserConfig) {
                    const result = await api.loadUserConfig(selectedUserConfig) as Settings & { theme?: string }
                    setSettings(result)
                    if (result.theme) {
                      document.documentElement.setAttribute('data-theme', result.theme)
                      localStorage.setItem('joro-theme', result.theme)
                    }
                  }
                  if (selectedProjectConfig) {
                    await api.loadProjectConfig(selectedProjectConfig)
                  }
                  onSetupComplete('local')
                } catch (e) {
                  setConfigError(String(e))
                } finally {
                  setConfigLoading(false)
                }
              }}
              className="w-full px-4 py-2 bg-accent-tertiary text-black text-xs font-semibold rounded hover:bg-accent-tertiary-hover disabled:opacity-50"
            >
              {configLoading ? 'Loading...' : 'Load & Start'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
