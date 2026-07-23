import { useState } from 'react'
import { X, Inbox } from 'lucide-react'
import FlaggedRequestModal from '../components/FlaggedRequestModal'
import type { FlaggedRequest } from '../stores/teamFlaggedStore'
import { StagedRequest, useDeadDropStore } from '../stores/deadDropStore'
import {
  DROP_TYPE,
  DROP_VERSION,
  DropBundle,
  DropItem,
  exportDrop,
  importDrop,
} from '../lib/deaddrop'
import { useSettingsStore } from '../stores/settingsStore'
import { useToastStore } from '../stores/toastStore'

function methodColor(method: string): string {
  const colors: Record<string, string> = {
    GET: 'text-semantic-success',
    POST: 'text-semantic-info',
    PUT: 'text-semantic-warning',
    DELETE: 'text-semantic-error',
    PATCH: 'text-semantic-special',
  }
  return colors[method] ?? 'text-content-secondary'
}

function statusColor(code: number): string {
  if (code === 0) return 'text-content-muted'
  return code < 300 ? 'text-semantic-success' : code < 400 ? 'text-semantic-warning' : 'text-semantic-error'
}

// Build the FlaggedRequest shape the shared viewer modal expects.
function toFlagged(
  item: { id: string } & DropItem,
  author: string,
  createdAt: string
): FlaggedRequest {
  return {
    id: item.id,
    host: item.host,
    method: item.method,
    url: item.url,
    status: item.status,
    truncated: item.truncated,
    note: item.note,
    author,
    createdAt,
    reqRaw: item.reqRaw,
    respRaw: item.respRaw,
  }
}

export default function DeadDrop() {
  const staged = useDeadDropStore((s) => s.staged)
  const remove = useDeadDropStore((s) => s.remove)
  const reorder = useDeadDropStore((s) => s.reorder)
  const setNote = useDeadDropStore((s) => s.setNote)
  const clear = useDeadDropStore((s) => s.clear)

  const settings = useSettingsStore((s) => s.settings)
  const addToast = useToastStore((s) => s.addToast)

  const [author, setAuthor] = useState(settings?.teamNickname ?? '')
  const [title, setTitle] = useState('')
  const [dropNote, setDropNote] = useState('')
  const [dragIndex, setDragIndex] = useState<number | null>(null)

  const [imported, setImported] = useState<DropBundle | null>(null)
  const [viewing, setViewing] = useState<{ flagged: FlaggedRequest; source: 'staged' | 'imported' } | null>(null)

  async function exportFile() {
    if (staged.length === 0) return
    const bundle: DropBundle = {
      type: DROP_TYPE,
      version: DROP_VERSION,
      exportedAt: new Date().toISOString(),
      author: author.trim(),
      title: title.trim(),
      note: dropNote.trim(),
      items: staged.map((s) => ({
        host: s.host,
        method: s.method,
        url: s.url,
        status: s.status,
        note: s.note,
        reqRaw: s.reqRaw,
        respRaw: s.respRaw,
        truncated: s.truncated,
      })),
    }
    try {
      const blob = await exportDrop(bundle)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
      a.download = `drop-${stamp}.jord`
      a.click()
      URL.revokeObjectURL(url)
      addToast(`Exported ${staged.length} request${staged.length === 1 ? '' : 's'}`, 'info')
    } catch {
      addToast('Failed to export Dead Drop')
    }
  }

  function importFile() {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.jord,application/gzip,application/json'
    input.onchange = async () => {
      const file = input.files?.[0]
      if (!file) return
      try {
        const bundle = await importDrop(file)
        setImported(bundle)
        addToast(`Loaded ${bundle.items.length} request${bundle.items.length === 1 ? '' : 's'}`, 'info')
      } catch (e) {
        addToast((e as Error)?.message || 'Failed to import file')
      }
    }
    input.click()
  }

  function viewStaged(s: StagedRequest) {
    setViewing({ flagged: toFlagged(s, author.trim(), ''), source: 'staged' })
  }

  function viewImported(item: DropItem, i: number) {
    if (!imported) return
    setViewing({
      flagged: toFlagged({ id: `imported-${i}`, ...item }, imported.author, imported.exportedAt),
      source: 'imported',
    })
  }

  return (
    <div className="flex flex-col flex-1 min-h-0 overflow-auto">
      <div className="px-4 py-3 border-b border-border shrink-0">
        <p className="text-xs text-content-muted">
          Stage requests from History, order them, and export a portable{' '}
          <code className="text-content-secondary">.jord</code> file to share — no team server required.
        </p>
      </div>

      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-2 gap-4 p-4">
        {/* Staged (outgoing) */}
        <section className="flex flex-col min-h-0 border border-border rounded bg-surface-card">
          <div className="shrink-0 px-3 py-2 border-b border-border">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
                Staged ({staged.length})
              </span>
              <div className="ml-auto flex items-center gap-1.5">
                <button
                  onClick={exportFile}
                  disabled={staged.length === 0}
                  className="px-3 py-1 bg-accent-tertiary text-black text-xs font-medium rounded hover:bg-accent-tertiary-hover disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Export .jord
                </button>
                <button
                  onClick={clear}
                  disabled={staged.length === 0}
                  className="px-2 py-1 text-content-secondary hover:text-semantic-error text-xs disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Clear
                </button>
              </div>
            </div>
            <div className="mt-2 grid grid-cols-1 sm:grid-cols-3 gap-2">
              <input
                value={author}
                onChange={(e) => setAuthor(e.target.value)}
                placeholder="Author / From"
                className="px-2 py-1 bg-surface-input border border-border rounded text-xs text-content-primary placeholder:text-content-muted"
              />
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Title (optional)"
                className="px-2 py-1 bg-surface-input border border-border rounded text-xs text-content-primary placeholder:text-content-muted"
              />
              <input
                value={dropNote}
                onChange={(e) => setDropNote(e.target.value)}
                placeholder="Note (optional)"
                className="px-2 py-1 bg-surface-input border border-border rounded text-xs text-content-primary placeholder:text-content-muted"
              />
            </div>
          </div>

          <div className="flex-1 min-h-0 overflow-auto">
            {staged.length === 0 ? (
              <div className="p-4 text-xs text-content-muted">
                Nothing staged yet. In <span className="text-content-secondary">History</span>, right-click a
                request and choose <span className="text-content-secondary">“Stage for Dead Drop”</span>.
              </div>
            ) : (
              <ul>
                {staged.map((s, i) => (
                  <li
                    key={s.id}
                    draggable
                    onDragStart={() => setDragIndex(i)}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={() => {
                      if (dragIndex !== null) reorder(dragIndex, i)
                      setDragIndex(null)
                    }}
                    onDragEnd={() => setDragIndex(null)}
                    className={`flex items-center gap-2 px-2 py-1.5 border-b border-border-subtle hover:bg-surface-hover ${
                      dragIndex === i ? 'opacity-50' : ''
                    }`}
                  >
                    <span className="cursor-move text-content-muted select-none" title="Drag to reorder">
                      ⠿
                    </span>
                    <span className="w-5 text-right text-content-muted text-xs">{i + 1}</span>
                    <button
                      onClick={() => viewStaged(s)}
                      className="flex items-center gap-2 min-w-0 flex-1 text-left"
                    >
                      <span className={`text-xs font-bold ${methodColor(s.method)}`}>{s.method}</span>
                      {s.status > 0 && (
                        <span className={`text-xs ${statusColor(s.status)}`}>{s.status}</span>
                      )}
                      <span className="text-xs text-content-secondary truncate">{s.url}</span>
                    </button>
                    <input
                      value={s.note}
                      onChange={(e) => setNote(s.id, e.target.value)}
                      placeholder="note"
                      className="w-28 shrink-0 px-1.5 py-0.5 bg-surface-input border border-border rounded text-[11px] text-content-primary placeholder:text-content-muted"
                    />
                    <button
                      onClick={() => remove(s.id)}
                      className="shrink-0 px-1.5 text-content-muted hover:text-semantic-error inline-flex items-center"
                      title="Remove"
                    >
                      <X size={14} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        {/* Imported (incoming) */}
        <section className="flex flex-col min-h-0 border border-border rounded bg-surface-card">
          <div className="shrink-0 px-3 py-2 border-b border-border flex items-center gap-2">
            <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">
              Imported{imported ? ` (${imported.items.length})` : ''}
            </span>
            <div className="ml-auto flex items-center gap-1.5">
              <button
                onClick={importFile}
                className="px-3 py-1 bg-accent-secondary text-black text-xs font-medium rounded hover:bg-accent-secondary-hover"
              >
                Import .jord
              </button>
              {imported && (
                <button
                  onClick={() => setImported(null)}
                  className="px-2 py-1 text-content-secondary hover:text-content-primary text-xs"
                >
                  Close
                </button>
              )}
            </div>
          </div>

          {imported && (imported.title || imported.author || imported.note || imported.exportedAt) && (
            <div className="shrink-0 px-3 py-1.5 border-b border-border-subtle text-[11px] text-content-muted flex flex-wrap gap-x-4 gap-y-0.5">
              {imported.title && <span className="text-content-secondary">{imported.title}</span>}
              {imported.author && (
                <span>
                  from <span className="text-content-secondary">{imported.author}</span>
                </span>
              )}
              {imported.exportedAt && (
                <span>{new Date(imported.exportedAt).toLocaleString('en-US', { timeZone: 'UTC' })} UTC</span>
              )}
              {imported.note && <span className="text-content-secondary">“{imported.note}”</span>}
            </div>
          )}

          <div className="flex-1 min-h-0 overflow-auto">
            {!imported ? (
              <div className="p-4 text-xs text-content-muted">
                Import a <code className="text-content-secondary">.jord</code> file shared by a teammate to view
                the raw requests and responses inside.
              </div>
            ) : imported.items.length === 0 ? (
              <div className="p-4 text-xs text-content-muted">This drop contains no requests.</div>
            ) : (
              <ul>
                {imported.items.map((item, i) => (
                  <li key={i} className="border-b border-border-subtle hover:bg-surface-hover">
                    <button
                      onClick={() => viewImported(item, i)}
                      className="flex items-center gap-2 w-full px-2 py-1.5 text-left"
                    >
                      <span className="w-5 text-right text-content-muted text-xs">{i + 1}</span>
                      <span className={`text-xs font-bold ${methodColor(item.method)}`}>{item.method}</span>
                      {item.status > 0 && (
                        <span className={`text-xs ${statusColor(item.status)}`}>{item.status}</span>
                      )}
                      <span className="text-xs text-content-secondary truncate flex-1">{item.url}</span>
                      {item.note && (
                        <span className="text-[11px] text-content-muted truncate max-w-[8rem]">
                          {item.note}
                        </span>
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      </div>

      {viewing && (
        <FlaggedRequestModal
          flagged={viewing.flagged}
          onClose={() => setViewing(null)}
          title="Dead Drop Request"
          icon={<Inbox size={13} aria-hidden="true" />}
          byline="shared by"
        />
      )}
    </div>
  )
}
