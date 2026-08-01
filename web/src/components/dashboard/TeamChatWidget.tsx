import { useEffect, useRef, useState } from 'react'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import CollabSwapModal from '../CollabSwapModal'
import { useFlaggedModal } from './useFlaggedModal'
import { api } from '../../lib/api'
import { useTeamStore } from '../../stores/teamStore'
import { useProjectStore } from '../../stores/projectStore'
import { useRequestStore, type RequestDetail } from '../../stores/requestStore'
import { useSettingsStore, isTeamMode, type Settings } from '../../stores/settingsStore'

interface LocalChatMessage {
  id: number
  author: string
  text: string
  timestamp: number
}

const SLASH_HELP = [
  'Available slash commands:',
  '/me <text> — send an action message',
  '/slap <user> — slap someone with a large trout',
  '/nick <name> — change your nickname',
  '/flag <seq> [note] — flag a captured request (seq from History)',
  '/collab <note> — request collaboration (share scope / M&R / custom data)',
  '/help — show this help',
].join('\n')

export default function TeamChatWidget() {
  const settings = useSettingsStore((s) => s.settings)
  const setSettings = useSettingsStore((s) => s.setSettings)
  const teamMode = isTeamMode(settings)
  const activeProject = useProjectStore((s) => s.active)

  const teamMessages = useTeamStore((s) => s.messages)
  const addMessage = useTeamStore((s) => s.addMessage)
  const requestItems = useRequestStore((s) => s.items)

  const [localMessages, setLocalMessages] = useState<LocalChatMessage[]>([])
  const [draft, setDraft] = useState('')
  const [flagError, setFlagError] = useState('')
  const [collabId, setCollabId] = useState<string | null>(null)
  const chatEndRef = useRef<HTMLDivElement>(null)
  const nextId = useRef(1)

  const { openFlagged, error: flaggedError, clearError, modal } = useFlaggedModal()

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [teamMode ? teamMessages : localMessages])

  const sendMessage = async () => {
    const text = draft.trim()
    if (!text) return

    // Slash commands require a team server; hint instead of posting literal text.
    if (!teamMode && text.startsWith('/')) {
      const cmd = text.split(/\s+/)[0]
      if (['/collab', '/flag', '/slap', '/me', '/nick', '/help'].includes(cmd)) {
        setFlagError(`Connect to a team server to use ${cmd}`)
        return
      }
    }

    // /help — show contextual help locally (not sent to the team).
    if (teamMode && (text === '/help' || text.startsWith('/help '))) {
      setDraft('')
      setFlagError('')
      addMessage({
        id: `help-${crypto.randomUUID()}`,
        author: '*',
        text: SLASH_HELP,
        createdAt: new Date().toISOString(),
      })
      return
    }

    // /nick <new_nickname> — change your nickname.
    if (teamMode && (text === '/nick' || text.startsWith('/nick '))) {
      const newNick = text.replace(/^\/nick\s*/, '').trim()
      if (!newNick) {
        setFlagError('Usage: /nick <new_nickname>')
        return
      }
      setDraft('')
      setFlagError('')
      try {
        const updated = await api.updateSettings({ teamNickname: newNick })
        setSettings(updated as Settings)
      } catch {
        setFlagError(`Nickname "${newNick}" is already in use`)
      }
      return
    }

    // /me <text> and /slap <user> — IRC-style action messages (rendered italic,
    // attributed to the operator without a "name:" prefix).
    if (teamMode && (text === '/me' || text.startsWith('/me '))) {
      const action = text.replace(/^\/me\s*/, '').trim()
      if (!action) {
        setFlagError('Usage: /me <text>')
        return
      }
      setDraft('')
      setFlagError('')
      api.sendChatMessage(action, 'action').catch(() => {})
      return
    }
    if (teamMode && (text === '/slap' || text.startsWith('/slap '))) {
      const target = text.replace(/^\/slap\s*/, '').trim()
      if (!target) {
        setFlagError('Usage: /slap <user>')
        return
      }
      setDraft('')
      setFlagError('')
      api.sendChatMessage(`slaps ${target} around a bit with a large trout`, 'action').catch(() => {})
      return
    }

    // /collab <note> — request collaboration, sharing current scope/M&R/custom-data rules.
    if (teamMode && text.startsWith('/collab')) {
      const note = text.replace(/^\/collab\s*/, '').trim()
      setDraft('')
      setFlagError('')
      try {
        const config = await api.gatherCurrentRules()
        await api.requestCollab({
          project: activeProject,
          note,
          config: JSON.stringify(config),
        })
      } catch {
        setFlagError('Failed to request collaboration')
      }
      return
    }

    // /flag <seq> [note] — flag a locally-captured request into the team.
    if (teamMode && text.startsWith('/flag')) {
      const m = text.match(/^\/flag\s+(\d+)\s*(.*)$/)
      if (!m) {
        setFlagError('Usage: /flag <seq> [note]')
        return
      }
      const seq = parseInt(m[1], 10)
      const note = m[2].trim()
      const summary = requestItems.find((r) => r.seq === seq)
      if (!summary) {
        setFlagError(`Request #${seq} not in local history`)
        return
      }
      setDraft('')
      setFlagError('')
      try {
        const detail = (await api.getRequest(summary.id)) as RequestDetail
        await api.flagRequest({
          host: detail.host,
          method: detail.method,
          url: detail.url,
          status: detail.statusCode,
          reqRaw: detail.reqRaw,
          respRaw: detail.respRaw,
          note,
        })
      } catch {
        setFlagError('Failed to flag request')
      }
      return
    }

    setDraft('')
    if (teamMode) {
      try {
        await api.sendChatMessage(text)
      } catch {
        // ignore
      }
    } else {
      setLocalMessages((prev) => [
        ...prev,
        { id: nextId.current++, author: 'operator', text, timestamp: Date.now() },
      ])
    }
  }

  const error = flagError || flaggedError

  return (
    <DashboardPanel
      title="Team Chat"
      headerExtra={
        !teamMode ? <span className="ml-2 text-content-muted text-xs">(local only)</span> : undefined
      }
      bodyClassName="flex-1 min-h-0 flex flex-col"
    >
      <div className="flex-1 overflow-y-auto px-3 py-2 space-y-1">
        {teamMode ? (
          teamMessages.length === 0 ? (
            <EmptyPanelBody>No messages yet</EmptyPanelBody>
          ) : (
            teamMessages.map((m) => (
              <div key={m.id} className="text-xs">
                {m.author === '*' ? (
                  <span className="text-content-muted italic whitespace-pre-wrap">[*] {m.text}</span>
                ) : m.refType === 'action' ? (
                  <span className="text-content-secondary italic">* {m.author} {m.text}</span>
                ) : (
                  <>
                    <span className="text-accent-secondary font-medium">{m.author}</span>
                    <span className="text-content-muted ml-1.5">
                      {new Date(m.createdAt).toLocaleTimeString('en-US', { timeZone: 'UTC' }) + ' UTC'}
                    </span>
                    {m.refId && m.refType === 'flagged' ? (
                      <button
                        onClick={() => openFlagged(m.refId!)}
                        className="ml-2 text-accent-tertiary hover:underline font-medium text-left"
                        title="Review flagged request"
                      >
                        {m.text}
                      </button>
                    ) : m.refId && m.refType === 'collab' ? (
                      <button
                        onClick={() => setCollabId(m.refId!)}
                        className="ml-2 text-accent-tertiary hover:underline font-medium text-left"
                        title="Review collaboration request"
                      >
                        {m.text}
                      </button>
                    ) : (
                      <span className="text-content-terminal ml-2">{m.text}</span>
                    )}
                  </>
                )}
              </div>
            ))
          )
        ) : (
          <>
            {localMessages.length === 0 && <EmptyPanelBody>No messages yet</EmptyPanelBody>}
            {localMessages.map((m) => (
              <div key={m.id} className="text-xs">
                <span className="text-accent-secondary font-medium">{m.author}</span>
                <span className="text-content-muted ml-1.5">
                  {new Date(m.timestamp).toLocaleTimeString('en-US', { timeZone: 'UTC' }) + ' UTC'}
                </span>
                <span className="text-content-terminal ml-2">{m.text}</span>
              </div>
            ))}
          </>
        )}
        <div ref={chatEndRef} />
      </div>
      {error && (
        <div className="shrink-0 px-3 py-1 text-[10px] text-semantic-error border-t border-border">
          {error}
        </div>
      )}
      <div className="shrink-0 flex gap-2 px-3 py-2 border-t border-border">
        <input
          type="text"
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value)
            if (flagError) setFlagError('')
            if (flaggedError) clearError()
          }}
          onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
          placeholder={teamMode ? 'Type a message… (/flag <seq> to flag a request)' : 'Type a message...'}
          className="flex-1 bg-surface-input text-content-primary text-xs px-2 py-1.5 rounded border border-border placeholder:text-content-muted focus:outline-none focus:border-accent-secondary"
        />
        <button
          onClick={sendMessage}
          className="px-3 py-1.5 bg-accent-secondary text-black text-xs font-medium rounded hover:bg-accent-secondary-hover"
        >
          Send
        </button>
      </div>
      {modal}
      {collabId && (
        <CollabSwapModal
          collabId={collabId}
          onClose={() => setCollabId(null)}
          onApplied={() => {
            useRequestStore.getState().invalidate()
          }}
        />
      )}
    </DashboardPanel>
  )
}
