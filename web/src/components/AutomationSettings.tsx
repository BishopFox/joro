import { useEffect, useState } from 'react'
import type { AutomationToken, AutomationTokenInput } from '../lib/api'
import { useAutomationStore } from '../stores/automationStore'
import AutomationTokenModal from './AutomationTokenModal'
import AutomationSecretModal from './AutomationSecretModal'
import AutomationActivity from './AutomationActivity'
import ScriptRuns from './ScriptRuns'
import AutomationConfigPanel from './automation/AutomationConfigPanel'
import ScriptingPanel from './automation/ScriptingPanel'
import ConfirmModal from './ConfirmModal'
import { useToastStore } from '../stores/toastStore'

// Three surfaces that share a subject and nothing else: what is installed and what wakes
// it, how the surface is configured and who may reach it, and what has happened. Sub-tabs
// rather than one long panel, mirroring Settings -> Plugins — and the editor needs the full
// panel height regardless.
type SubTab = 'scripting' | 'settings' | 'activity'

export default function AutomationSettings() {
  const { capabilities, profiles, classes, mcp, available, refresh, create, update } =
    useAutomationStore()
  const addToast = useToastStore((s) => s.addToast)

  // Modal state lives here rather than in the sub-tab that opens it. A tab switch unmounts
  // the panel, and one of these is the only place in the whole API that shows a plaintext
  // secret — losing it to a stray click would mean rotating the token to see one again.
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<AutomationToken | null>(null)
  const [secret, setSecret] = useState<{ value: string; name: string } | null>(null)
  const [confirm, setConfirm] = useState<{ message: string; action: () => Promise<void> } | null>(null)
  const [subTab, setSubTab] = useState<SubTab>('scripting')

  useEffect(() => {
    refresh()
  }, [refresh])

  if (available === false) {
    return (
      <div className="p-5">
        <h2 className="text-sm font-semibold uppercase tracking-wide mb-3">Automation</h2>
        <p className="text-content-muted text-xs">
          Automation is disabled for this run (<code className="font-mono">--no-automation</code>). Restart Joro without
          that flag to issue tokens and run the MCP server.
        </p>
      </div>
    )
  }

  const handleCreate = async (body: AutomationTokenInput) => {
    const s = await create(body)
    setSecret({ value: s, name: body.name ?? 'token' })
  }

  const tab = (id: SubTab, label: string) => (
    <button
      key={id}
      onClick={() => setSubTab(id)}
      className={`px-3 py-1.5 text-xs font-semibold rounded-t-sm border-b-2 transition-colors ${
        subTab === id
          ? 'border-accent text-accent'
          : 'border-transparent text-content-secondary hover:text-content-primary'
      }`}
    >
      {label}
    </button>
  )

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="flex gap-1 px-3 pt-2 pb-0 bg-surface-card border-b border-border shrink-0">
        {tab('scripting', 'Scripting')}
        {tab('settings', 'Settings')}
        {tab('activity', 'Activity')}
      </div>

      {subTab === 'scripting' && <ScriptingPanel />}

      {subTab === 'settings' && (
        <AutomationConfigPanel
          onNewToken={() => setCreating(true)}
          onEditToken={setEditing}
          onConfirm={setConfirm}
          onSecret={setSecret}
        />
      )}

      {subTab === 'activity' && (
        <div className="flex-1 overflow-auto p-5 space-y-4">
          <AutomationActivity />
          <ScriptRuns />
        </div>
      )}

      {creating && (
        <AutomationTokenModal
          capabilities={capabilities}
          profiles={profiles}
          classes={classes}
          onSubmit={handleCreate}
          onClose={() => setCreating(false)}
        />
      )}
      {editing && (
        <AutomationTokenModal
          capabilities={capabilities}
          profiles={profiles}
          classes={classes}
          token={editing}
          onSubmit={(body) => update(editing.id, body)}
          onClose={() => setEditing(null)}
        />
      )}
      {secret && mcp && (
        <AutomationSecretModal
          secret={secret.value}
          tokenName={secret.name}
          endpoint={mcp.endpoint}
          onClose={() => setSecret(null)}
        />
      )}
      {confirm && (
        <ConfirmModal
          message={confirm.message}
          onConfirm={() => {
            const run = confirm.action
            setConfirm(null)
            run()
              .then(() => addToast('Done', 'info'))
              .catch((e) => addToast(String(e instanceof Error ? e.message : e), 'error'))
          }}
          onClose={() => setConfirm(null)}
        />
      )}
    </div>
  )
}
