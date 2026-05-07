import { useState } from 'react'
import { api } from '../lib/api'
import { Settings, useSettingsStore } from '../stores/settingsStore'

interface Props {
  onAuthenticated: () => void
}

export default function Login({ onAuthenticated }: Props) {
  const { setSettings } = useSettingsStore()
  const [nickname, setNickname] = useState('')
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!nickname.trim() || !token.trim()) {
      setError('Nickname and token are required')
      return
    }

    setLoading(true)
    setError('')

    try {
      // Save the token and nickname to enable authenticated API calls to the listener.
      const updated = await api.updateSettings({
        teamToken: token.trim(),
        teamNickname: nickname.trim(),
      })
      setSettings(updated as Settings)

      // Validate credentials by making an authenticated request to the listener.
      // listTokens is available in both plain listener and teamserver modes.
      await api.listTokens()

      onAuthenticated()
    } catch {
      setError('Authentication failed. Check token and listener URL.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex items-center justify-center h-screen bg-surface-body">
      <form
        onSubmit={handleSubmit}
        className="w-80 bg-surface-card border border-border rounded p-6 space-y-4"
      >
        <div className="text-center">
          <h1 className="text-accent text-lg font-bold uppercase tracking-wider">Joro</h1>
          <p className="text-content-muted text-xs mt-1">Listener Authentication</p>
        </div>

        <div>
          <label className="block text-xs text-content-secondary mb-1">Nickname</label>
          <input
            type="text"
            value={nickname}
            onChange={(e) => setNickname(e.target.value)}
            placeholder="Your display name"
            autoFocus
            className="w-full bg-surface-input text-content-primary text-xs px-3 py-2 rounded border border-border placeholder:text-content-muted focus:outline-none focus:border-accent-secondary"
          />
        </div>

        <div>
          <label className="block text-xs text-content-secondary mb-1">Auth Token</label>
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Paste the listener auth token"
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

        <button
          type="button"
          onClick={() => {
            localStorage.removeItem('joro-setup-mode')
            window.location.reload()
          }}
          className="w-full text-content-muted text-xs hover:text-content-secondary"
        >
          Back to setup
        </button>
      </form>
    </div>
  )
}
