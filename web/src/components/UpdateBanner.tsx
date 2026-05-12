import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { useUpdateStore } from '../stores/updateStore'

const NEW_CONFIG = '__new__'

export default function UpdateBanner() {
  const { info, dismissed, updating, status, setInfo, dismiss, setUpdating, setStatus } = useUpdateStore()
  const [showModal, setShowModal] = useState(false)
  const [saveUser, setSaveUser] = useState(true)
  const [saveProject, setSaveProject] = useState(true)
  const [userConfigName, setUserConfigName] = useState('pre-update')
  const [projectConfigName, setProjectConfigName] = useState('pre-update')
  const [userSelected, setUserSelected] = useState(NEW_CONFIG)
  const [projectSelected, setProjectSelected] = useState(NEW_CONFIG)
  const [userConfigs, setUserConfigs] = useState<string[]>([])
  const [projectConfigs, setProjectConfigs] = useState<string[]>([])
  const [error, setError] = useState('')

  // Check for updates on mount + every 5 minutes.
  useEffect(() => {
    const check = () => { api.versionInfo().then(setInfo).catch(() => {}) }
    check()
    const id = setInterval(check, 5 * 60 * 1000)
    return () => clearInterval(id)
  }, [setInfo])

  // Fetch existing configs when modal opens.
  useEffect(() => {
    if (!showModal) return
    api.listUserConfigs().then((r) => {
      setUserConfigs(r.configs || [])
      // Pre-select "pre-update" if it exists, otherwise default to new.
      if ((r.configs || []).includes('pre-update')) {
        setUserSelected('pre-update')
      } else {
        setUserSelected(NEW_CONFIG)
      }
    }).catch(() => {})
    api.listProjectConfigs().then((r) => {
      setProjectConfigs(r.configs || [])
      if ((r.configs || []).includes('pre-update')) {
        setProjectSelected('pre-update')
      } else {
        setProjectSelected(NEW_CONFIG)
      }
    }).catch(() => {})
  }, [showModal])

  if (!info?.updateAvailable || dismissed) return null

  if (updating) {
    return (
      <div className="flex items-center px-3 py-1.5 bg-surface-input border-b border-border text-xs text-content-secondary">
        <span className="animate-pulse">{status || 'Updating...'}</span>
      </div>
    )
  }

  const resolveUserName = () => userSelected === NEW_CONFIG ? userConfigName.trim() : userSelected
  const resolveProjectName = () => projectSelected === NEW_CONFIG ? projectConfigName.trim() : projectSelected

  const changelogUrl = info.commit && info.commit !== 'dev'
    ? `https://github.com/BishopFox/joro/compare/${info.commit}...main`
    : 'https://github.com/BishopFox/joro/commits/main/'

  const handleUpdate = async () => {
    setError('')

    const uName = resolveUserName()
    const pName = resolveProjectName()
    if (saveUser && !uName) { setError('User config name is required.'); return }
    if (saveProject && !pName) { setError('Project config name is required.'); return }

    setUpdating(true)
    setStatus('Saving configuration...')
    setShowModal(false)

    try {
      if (saveUser) {
        await api.saveUserConfig(uName)
      }
      if (saveProject) {
        await api.saveProjectConfig(pName)
      }
    } catch (e) {
      setUpdating(false)
      setStatus('')
      setError(`Failed to save config: ${e instanceof Error ? e.message : String(e)}`)
      setShowModal(true)
      return
    }

    setStatus('Starting update...')
    try {
      await api.performUpdate()
    } catch (e) {
      setUpdating(false)
      setStatus('')
      setError(`Update failed: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  return (
    <>
      <div className="flex items-center justify-between px-3 py-1.5 bg-surface-input border-b border-accent/30 text-xs text-content-secondary">
        <span>
          A new version of Joro is available (latest: <code className="text-accent">{info.latestVersion}</code>).{' '}
          <a
            href={changelogUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent-secondary hover:text-accent-secondary-hover underline"
          >
            See changelog
          </a>
        </span>
        <div className="flex items-center gap-2 ml-4">
          <button
            onClick={() => setShowModal(true)}
            className="px-2 py-0.5 rounded text-xs bg-accent-secondary text-black hover:bg-accent-secondary-hover"
          >
            Update Now
          </button>
          <button
            onClick={dismiss}
            className="text-content-muted hover:text-content-primary text-xs"
          >
            Dismiss
          </button>
        </div>
      </div>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-surface-card border border-border rounded-lg p-4 w-[28rem] space-y-3">
            <h3 className="text-sm font-semibold text-content-primary">Update & Restart</h3>
            <p className="text-xs text-content-secondary">
              Joro will pull the latest changes, rebuild, and restart. Unsaved scope rules, noise
              patterns, match/replace rules, request history, and highlights will be lost.
            </p>

            <div className="space-y-2">
              {/* User config */}
              <label className="flex items-center gap-2 text-xs text-content-secondary">
                <input
                  type="checkbox"
                  checked={saveUser}
                  onChange={(e) => setSaveUser(e.target.checked)}
                  className="accent-accent-secondary"
                />
                Save user config as:
              </label>
              {saveUser && (
                <div className="flex items-center gap-2 ml-5">
                  <select
                    value={userSelected}
                    onChange={(e) => setUserSelected(e.target.value)}
                    className="flex-1 px-1.5 py-0.5 rounded text-xs bg-surface-input border border-border text-content-primary"
                  >
                    {userConfigs.map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                    <option value={NEW_CONFIG}>New config...</option>
                  </select>
                  {userSelected === NEW_CONFIG && (
                    <input
                      type="text"
                      value={userConfigName}
                      onChange={(e) => setUserConfigName(e.target.value)}
                      placeholder="Config name"
                      className="flex-1 px-1.5 py-0.5 rounded text-xs bg-surface-input border border-border text-content-primary placeholder:text-content-muted"
                    />
                  )}
                </div>
              )}

              {/* Project config */}
              <label className="flex items-center gap-2 text-xs text-content-secondary">
                <input
                  type="checkbox"
                  checked={saveProject}
                  onChange={(e) => setSaveProject(e.target.checked)}
                  className="accent-accent-secondary"
                />
                Save project config as:
              </label>
              {saveProject && (
                <div className="flex items-center gap-2 ml-5">
                  <select
                    value={projectSelected}
                    onChange={(e) => setProjectSelected(e.target.value)}
                    className="flex-1 px-1.5 py-0.5 rounded text-xs bg-surface-input border border-border text-content-primary"
                  >
                    {projectConfigs.map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                    <option value={NEW_CONFIG}>New config...</option>
                  </select>
                  {projectSelected === NEW_CONFIG && (
                    <input
                      type="text"
                      value={projectConfigName}
                      onChange={(e) => setProjectConfigName(e.target.value)}
                      placeholder="Config name"
                      className="flex-1 px-1.5 py-0.5 rounded text-xs bg-surface-input border border-border text-content-primary placeholder:text-content-muted"
                    />
                  )}
                </div>
              )}
            </div>

            {error && (
              <p className="text-xs text-semantic-error">{error}</p>
            )}

            <div className="flex justify-end gap-2 pt-1">
              <button
                onClick={() => setShowModal(false)}
                className="px-3 py-1 rounded text-xs text-content-secondary hover:text-content-primary hover:bg-surface-hover"
              >
                Cancel
              </button>
              <button
                onClick={handleUpdate}
                className="px-3 py-1 rounded text-xs bg-accent-secondary text-black hover:bg-accent-secondary-hover"
              >
                Update & Restart
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
