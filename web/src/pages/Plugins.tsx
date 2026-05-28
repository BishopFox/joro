import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import type { PluginInfo } from '../lib/api'
import { useUpdateStore } from '../stores/updateStore'
import { currentTheme } from '../lib/theme'
import { Tooltip } from '../components/Tooltip'

const TYPE_LABELS: Record<string, string> = {
  exec_provider: 'Execution Provider',
  tab: 'Top-Level Tab',
  feature: 'Plugin Feature',
  proxy_hook: 'Proxy Hook',
  dashboard: 'Dashboard',
}

export default function Plugins() {
  const [pluginList, setPluginList] = useState<PluginInfo[]>([])
  const [features, setFeatures] = useState<PluginInfo[]>([])
  const [activeTab, setActiveTab] = useState('manage')

  const refresh = useCallback(() => {
    api.listPlugins().then((plugs) => {
      setPluginList(plugs)
      setFeatures(plugs.filter((e) => e.type === 'feature' && e.status === 'loaded'))
    }).catch(() => {})
  }, [])

  useEffect(() => { refresh() }, [refresh])

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {/* Sub-tab bar */}
      <div className="flex gap-1 px-3 pt-2 pb-0 bg-surface-card border-b border-border">
        <button
          onClick={() => setActiveTab('manage')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-t-sm border-b-2 transition-colors ${
            activeTab === 'manage'
              ? 'border-accent text-accent'
              : 'border-transparent text-content-secondary hover:text-content-primary'
          }`}
        >
          Manage
        </button>
        {features.map((f) => (
          <button
            key={f.name}
            onClick={() => setActiveTab(f.name)}
            className={`px-3 py-1.5 text-xs font-semibold rounded-t-sm border-b-2 transition-colors ${
              activeTab === f.name
                ? 'border-accent text-accent'
                : 'border-transparent text-content-secondary hover:text-content-primary'
            }`}
          >
            {f.tabLabel || f.name}
          </button>
        ))}
      </div>

      {/* Content */}
      {activeTab === 'manage' ? (
        <ManagePanel plugins={pluginList} onRefresh={refresh} />
      ) : (
        <iframe
          src={`/plugin/${activeTab}/?theme=${currentTheme()}`}
          className="flex-1 border-0"
          sandbox="allow-scripts allow-forms allow-same-origin"
          title={activeTab}
        />
      )}
    </div>
  )
}

function ManagePanel({ plugins, onRefresh }: { plugins: PluginInfo[]; onRefresh: () => void }) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null)
  const [restartPending, setRestartPending] = useState(false)

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    setMessage(null)
    try {
      const res = await api.uploadPlugin(file)
      setMessage({ text: res.message, type: 'success' })
      setRestartPending(true)
      onRefresh()
    } catch (err) {
      setMessage({ text: String(err), type: 'error' })
    } finally {
      setUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  async function handleDelete(filename: string) {
    setMessage(null)
    try {
      const res = await api.deletePlugin(filename)
      setMessage({ text: res.message, type: 'success' })
      setRestartPending(true)
      onRefresh()
    } catch (err) {
      setMessage({ text: String(err), type: 'error' })
    }
  }

  async function handleRestart() {
    useUpdateStore.getState().setUpdating(true)
    useUpdateStore.getState().setStatus('Restarting...')
    try {
      await api.restart()
    } catch {
      useUpdateStore.getState().setUpdating(false)
      useUpdateStore.getState().setStatus('')
    }
  }

  return (
    <div className="flex-1 overflow-auto p-3">
      <div className="bg-surface-card rounded border border-border">
        <div className="px-3 py-2 border-b border-border flex items-center justify-between">
          <h2 className="text-xs font-semibold text-content-primary uppercase tracking-wide">
            Loaded Plugins
          </h2>
          <label className={`px-3 py-1 rounded-sm text-xs font-semibold cursor-pointer ${
            uploading
              ? 'bg-surface-input text-content-muted'
              : 'bg-accent-secondary hover:bg-accent-secondary-hover text-black'
          }`}>
            {uploading ? 'Uploading...' : 'Upload Plugin'}
            <input
              ref={fileInputRef}
              type="file"
              accept=".so,.dylib"
              onChange={handleUpload}
              disabled={uploading}
              className="hidden"
            />
          </label>
        </div>

        {message && (
          <div className={`px-3 py-2 text-xs border-b border-border ${
            message.type === 'success' ? 'text-semantic-success' : 'text-semantic-error'
          }`}>
            {message.text}
          </div>
        )}

        {restartPending && (
          <div className="flex items-center justify-between px-3 py-2 border-b border-border bg-surface-input">
            <span className="text-xs text-content-secondary">
              Restart required to apply plugin changes.
            </span>
            <button
              onClick={handleRestart}
              className="px-3 py-1 rounded-sm text-xs font-semibold bg-accent-secondary hover:bg-accent-secondary-hover text-black"
            >
              Restart Now
            </button>
          </div>
        )}

        {plugins.length === 0 ? (
          <div className="p-6 text-center">
            <p className="text-sm text-content-secondary mb-3">No plugins loaded</p>
            <p className="text-xs text-content-muted">
              Upload a plugin above or place{' '}
              <code className="text-accent-secondary">.so</code> /{' '}
              <code className="text-accent-secondary">.dylib</code> files in{' '}
              <code className="text-accent-secondary">~/.joro/plugins/</code> and restart Joro.
            </p>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-content-secondary text-left">
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium">Version</th>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">File</th>
                <th className="px-3 py-2 font-medium w-16"></th>
              </tr>
            </thead>
            <tbody>
              {plugins.map((p) => (
                <tr key={p.name} className="border-t border-border-subtle hover:bg-surface-hover">
                  <td className="px-3 py-2 text-content-primary font-medium">{p.name}</td>
                  <td className="px-3 py-2 text-content-secondary">{p.version}</td>
                  <td className="px-3 py-2">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-accent-secondary/20 text-accent-secondary">
                      {TYPE_LABELS[p.type] || p.type}
                    </span>
                    {p.hasGraph && (
                      <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-accent-tertiary/20 text-accent-tertiary">
                        Graph
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {p.status === 'loaded' ? (
                      <span className="text-semantic-success font-semibold">Loaded</span>
                    ) : (
                      <Tooltip content={p.error || 'Error'}>
                        <span className="text-semantic-error font-semibold">
                          Error
                        </span>
                      </Tooltip>
                    )}
                  </td>
                  <td className="px-3 py-2 text-content-muted font-mono text-[11px]">
                    {p.filename}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <Tooltip content="Remove plugin file (restart required)">
                      <button
                        onClick={() => handleDelete(p.filename)}
                        className="px-2 py-0.5 rounded text-[10px] font-semibold text-semantic-error hover:bg-semantic-error-bg hover:text-content-primary transition-colors"
                      >
                        Delete
                      </button>
                    </Tooltip>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <p className="mt-2 px-1 text-[11px] text-content-muted">
        Plugins must be compiled with the same Go version as the Joro binary.
        Changes take effect after a restart. Only load plugins from trusted sources.
      </p>
    </div>
  )
}
