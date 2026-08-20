import { useMemo, useRef, useState } from 'react'
import { api } from '../lib/api'
import type { PluginInfo } from '../lib/api'
import { useUpdateStore } from '../stores/updateStore'
import { currentTheme } from '../lib/theme'
import { Tooltip } from './Tooltip'
import ConfirmModal from './ConfirmModal'

// errText unwraps a thrown Error to its message. String(err) would prefix it
// with "Error: ", which reads as noise in the status strip.
function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

const TYPE_LABELS: Record<string, string> = {
  exec_provider: 'Execution Provider',
  tab: 'Top-Level Tab',
  feature: 'Plugin Feature',
  proxy_hook: 'Proxy Hook',
  dashboard: 'Dashboard',
  interact_provider: 'Interact Provider',
}

// PluginSettings is the Settings → Plugins category. The plugin list is owned
// by the Settings page (which needs it for the Appearance → "Visible tabs"
// list too), so this takes it as a prop rather than fetching a second copy.
export default function PluginSettings({ plugins, onRefresh }: { plugins: PluginInfo[]; onRefresh: () => void }) {
  const [activeTab, setActiveTab] = useState('manage')

  const features = useMemo(
    () => plugins.filter((p) => p.type === 'feature' && p.status === 'loaded'),
    [plugins]
  )

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
        <ManagePanel plugins={plugins} onRefresh={onRefresh} />
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
  const [confirmDelete, setConfirmDelete] = useState<PluginInfo | null>(null)
  const [purgeData, setPurgeData] = useState(false)

  // A "removed" row is a plugin whose file is gone but whose code is still
  // loaded, so the prompt has to outlive this component's own state — deriving
  // it from the list is what makes it survive navigating away and back. Uploads
  // still need the local flag, since an uploaded plugin is not in the list yet.
  const needsRestart = restartPending || plugins.some((p) => p.status === 'removed')

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
      setMessage({ text: errText(err), type: 'error' })
    } finally {
      setUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  async function handleDelete(filename: string, alsoPurgeData: boolean) {
    setMessage(null)
    try {
      const res = await api.deletePlugin(filename, { purgeData: alsoPurgeData })
      setMessage({ text: res.message, type: 'success' })
      onRefresh()
    } catch (err) {
      setMessage({ text: errText(err), type: 'error' })
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
            Plugins
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

        {needsRestart && (
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
                <tr key={p.filename} className="border-t border-border-subtle hover:bg-surface-hover">
                  <td className="px-3 py-2 text-content-primary font-medium">{p.name || '—'}</td>
                  <td className="px-3 py-2 text-content-secondary">{p.version}</td>
                  <td className="px-3 py-2">
                    {/* No `/20` opacity here: Tailwind can't apply an opacity
                        modifier to a var()-backed color, so the utility is
                        never emitted and the chip renders with no background. */}
                    {p.type && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-surface-input text-accent-secondary">
                        {TYPE_LABELS[p.type] || p.type}
                      </span>
                    )}
                    {p.hasGraph && (
                      <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-surface-input text-accent-tertiary">
                        Graph
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {p.status === 'loaded' ? (
                      <span className="text-semantic-success font-semibold">Loaded</span>
                    ) : p.status === 'removed' ? (
                      <Tooltip content="File deleted. The plugin keeps running until you restart.">
                        <span className="text-semantic-warning font-semibold">Removed</span>
                      </Tooltip>
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
                    {p.status !== 'removed' && (
                      <Tooltip content="Remove plugin file (restart required)">
                        <button
                          onClick={() => { setPurgeData(false); setConfirmDelete(p) }}
                          className="px-2 py-0.5 rounded text-[10px] font-semibold text-semantic-error hover:bg-semantic-error-bg hover:text-content-primary transition-colors"
                        >
                          Delete
                        </button>
                      </Tooltip>
                    )}
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

      {confirmDelete && (
        <ConfirmModal
          title="Delete plugin"
          message={
            confirmDelete.status === 'error'
              ? `Delete ${confirmDelete.filename}? This file never loaded, so nothing is running and no restart is needed. This cannot be undone.`
              : `Delete ${confirmDelete.filename}? ${confirmDelete.name} keeps running until you restart Joro — its code, routes and hooks stay live. This cannot be undone.`
          }
          body={
            confirmDelete.name ? (
              <label className="flex items-start gap-2 text-xs text-content-secondary">
                <input
                  type="checkbox"
                  checked={purgeData}
                  onChange={(e) => setPurgeData(e.target.checked)}
                  className="mt-0.5"
                />
                <span>
                  Also delete its stored data{' '}
                  <code className="text-content-muted">
                    ~/.joro/plugin-data/{confirmDelete.name}/
                  </code>
                  . Plugin state saved in your user and project configs is kept either way.
                </span>
              </label>
            ) : undefined
          }
          confirmLabel="Delete"
          deliberate
          onConfirm={() => {
            const { filename } = confirmDelete
            const alsoPurge = purgeData
            setConfirmDelete(null)
            void handleDelete(filename, alsoPurge)
          }}
          onClose={() => setConfirmDelete(null)}
        />
      )}
    </div>
  )
}
