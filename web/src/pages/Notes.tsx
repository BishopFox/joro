import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { Note } from '../lib/api'
import { Tooltip } from '../components/Tooltip'

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

interface NotesProps {
  teamMode?: boolean
}

export default function Notes({ teamMode = false }: NotesProps) {
  const [noteHosts, setNoteHosts] = useState<string[]>([])
  const [selectedHost, setSelectedHost] = useState<string | null>(null)
  const [notes, setNotes] = useState<Note[]>([])
  const [noteDraft, setNoteDraft] = useState('')
  const [newHost, setNewHost] = useState('')
  const [tab, setTab] = useState<'local' | 'shared'>(teamMode ? 'shared' : 'local')

  const isShared = teamMode && tab === 'shared'

  const fetchHosts = useCallback(async () => {
    try {
      const hostsRes = isShared
        ? await api.listTeamNoteHosts()
        : await api.listNoteHosts()
      setNoteHosts(hostsRes || [])
    } catch {
      // silently ignore
    }
  }, [isShared])

  useEffect(() => {
    fetchHosts()
    const id = setInterval(fetchHosts, 5000)
    return () => clearInterval(id)
  }, [fetchHosts])

  const fetchNotes = useCallback(async (host: string) => {
    try {
      const res = isShared
        ? await api.listTeamNotes({ host, limit: 100 })
        : await api.listNotes({ host, limit: 100 })
      const items = res.items || []
      // Chronological order: oldest first, newest at bottom.
      setNotes([...items].reverse())
    } catch {
      setNotes([])
    }
  }, [isShared])

  useEffect(() => {
    if (selectedHost) {
      fetchNotes(selectedHost)
    } else {
      setNotes([])
    }
  }, [selectedHost, fetchNotes])

  // Reset selection when switching tabs.
  useEffect(() => {
    setSelectedHost(null)
    setNotes([])
  }, [tab])

  const addNote = async () => {
    const content = noteDraft.trim()
    if (!content || !selectedHost) return
    try {
      const note = isShared
        ? await api.createTeamNote(selectedHost, content)
        : await api.createNote(selectedHost, content)
      setNotes((prev) => [...prev, note])
      setNoteDraft('')
    } catch {
      // silently ignore
    }
  }

  const deleteNote = async (id: string) => {
    try {
      if (isShared) {
        await api.deleteTeamNote(id)
      } else {
        await api.deleteNote(id)
      }
      setNotes((prev) => prev.filter((n) => n.id !== id))
    } catch {
      // silently ignore
    }
  }

  const addHost = () => {
    const host = newHost.trim()
    if (!host) return
    setNewHost('')
    if (!noteHosts.includes(host)) {
      setNoteHosts((prev) => [...prev, host].sort())
    }
    setSelectedHost(host)
  }

  return (
    <div className="flex flex-col h-full p-2 gap-2">
      {/* Tab bar when in team mode */}
      {teamMode && (
        <div className="shrink-0 flex gap-1">
          <button
            onClick={() => setTab('local')}
            className={`px-3 py-1.5 rounded-sm text-xs font-semibold transition-colors ${
              tab === 'local'
                ? 'bg-accent text-content-primary'
                : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
            }`}
          >
            Local Notes
          </button>
          <button
            onClick={() => setTab('shared')}
            className={`px-3 py-1.5 rounded-sm text-xs font-semibold transition-colors ${
              tab === 'shared'
                ? 'bg-accent text-content-primary'
                : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
            }`}
          >
            Shared Notes
          </button>
        </div>
      )}
      <div className="flex-1 min-h-0 flex bg-surface-card border border-border rounded">
        {/* Host list */}
        <div className="w-36 lg:w-44 shrink-0 border-r border-border flex flex-col">
          <div className="shrink-0 px-3 py-2 border-b border-border">
            <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
              Hosts
            </span>
            {noteHosts.length > 0 && (
              <span className="ml-2 text-content-muted text-xs">{noteHosts.length}</span>
            )}
          </div>
          {/* New host input for shared notes */}
          {isShared && (
            <div className="shrink-0 flex gap-1 px-2 py-1.5 border-b border-border">
              <input
                type="text"
                value={newHost}
                onChange={(e) => setNewHost(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addHost()}
                placeholder="Add host..."
                className="flex-1 min-w-0 bg-surface-input text-content-primary text-xs px-2 py-1 rounded border border-border placeholder:text-content-muted focus:outline-none focus:border-accent-secondary"
              />
              <button
                onClick={addHost}
                className="px-2 py-1 bg-accent-secondary text-black text-xs font-medium rounded hover:bg-accent-secondary-hover"
              >
                +
              </button>
            </div>
          )}
          <div className="flex-1 overflow-y-auto">
            {noteHosts.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <span className="text-content-muted text-xs">No hosts yet</span>
              </div>
            ) : (
              noteHosts.map((h) => (
                <button
                  key={h}
                  onClick={() => setSelectedHost(selectedHost === h ? null : h)}
                  className={`w-full text-left px-3 py-1.5 text-xs truncate border-b border-border-subtle hover:bg-surface-hover ${
                    selectedHost === h ? 'bg-surface-hover text-accent' : 'text-content-primary'
                  }`}
                >
                  {h}
                </button>
              ))
            )}
          </div>
        </div>

        {/* Notes area */}
        <div className="flex-1 min-w-0 flex flex-col">
          <div className="shrink-0 px-3 py-2 border-b border-border">
            <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
              Notes
            </span>
            {selectedHost && (
              <span className="ml-2 text-content-muted text-xs">{selectedHost}</span>
            )}
          </div>
          {!selectedHost ? (
            <div className="flex-1 flex items-center justify-center">
              <span className="text-content-muted text-xs">Select a host to view notes</span>
            </div>
          ) : (
            <>
              <div className="flex-1 overflow-y-auto px-3 py-2 space-y-2">
                {notes.length === 0 ? (
                  <div className="flex items-center justify-center h-full">
                    <span className="text-content-muted text-xs">No notes for this host</span>
                  </div>
                ) : (
                  notes.map((n) => (
                    <div key={n.id} className="flex items-start gap-2 text-xs">
                      <div className="flex-1 min-w-0">
                        <span className="text-accent-secondary font-medium">{n.author}</span>
                        <span className="text-content-muted ml-1.5">{timeAgo(n.createdAt)}</span>
                        <p className="text-content-primary mt-0.5 whitespace-pre-wrap break-words">{n.content}</p>
                      </div>
                      <Tooltip content="Delete note">
                        <button
                          onClick={() => deleteNote(n.id)}
                          className="shrink-0 text-content-muted hover:text-semantic-error text-xs"
                        >
                          ✕
                        </button>
                      </Tooltip>
                    </div>
                  ))
                )}
              </div>
              <div className="shrink-0 flex gap-2 px-3 py-2 border-t border-border">
                <input
                  type="text"
                  value={noteDraft}
                  onChange={(e) => setNoteDraft(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addNote()}
                  placeholder="Add a note..."
                  className="flex-1 bg-surface-input text-content-primary text-xs px-2 py-1.5 rounded border border-border placeholder:text-content-muted focus:outline-none focus:border-accent-secondary"
                />
                <button
                  onClick={addNote}
                  className="px-3 py-1.5 bg-accent-secondary text-black text-xs font-medium rounded hover:bg-accent-secondary-hover"
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
