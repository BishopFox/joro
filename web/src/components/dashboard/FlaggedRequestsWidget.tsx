import { useCallback } from 'react'
import { X } from 'lucide-react'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import { useTeamFlaggedStore } from '../../stores/teamFlaggedStore'
import { useFlaggedModal } from './useFlaggedModal'
import { timeAgo } from '../../lib/timeAgo'
import { api } from '../../lib/api'

export default function FlaggedRequestsWidget() {
  const items = useTeamFlaggedStore((s) => s.items)
  const removeItem = useTeamFlaggedStore((s) => s.removeItem)
  const { openFlagged, error, modal } = useFlaggedModal()

  const deleteFlagged = useCallback(
    async (id: string) => {
      removeItem(id)
      try {
        await api.deleteFlagged(id)
      } catch {
        // ignore
      }
    },
    [removeItem]
  )

  return (
    <DashboardPanel
      title="Flagged Requests"
      count={items.length}
      bodyClassName="flex-1 min-h-0 flex flex-col"
    >
      <div className="flex-1 overflow-y-auto">
        {items.length === 0 ? (
          <EmptyPanelBody>No flagged requests yet</EmptyPanelBody>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-surface-card">
              <tr className="text-content-secondary text-left">
                <th className="px-3 py-1.5 font-medium">Method</th>
                <th className="px-3 py-1.5 font-medium">URL</th>
                <th className="px-3 py-1.5 font-medium">Status</th>
                <th className="px-3 py-1.5 font-medium">By</th>
                <th className="px-3 py-1.5 font-medium">Time</th>
                <th className="px-3 py-1.5 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {items.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => openFlagged(f.id)}
                  className="border-t border-border-subtle hover:bg-surface-hover cursor-pointer"
                >
                  <td className="px-3 py-1.5 font-bold text-accent-secondary">{f.method}</td>
                  <td
                    className="px-3 py-1.5 text-content-primary truncate max-w-[240px]"
                    title={f.note || f.url}
                  >
                    {f.url}
                  </td>
                  <td
                    className={`px-3 py-1.5 ${
                      f.status < 300
                        ? 'text-semantic-success'
                        : f.status < 400
                        ? 'text-semantic-warning'
                        : 'text-semantic-error'
                    }`}
                  >
                    {f.status || '-'}
                  </td>
                  <td className="px-3 py-1.5 text-content-secondary">{f.author}</td>
                  <td className="px-3 py-1.5 text-content-muted">{timeAgo(f.createdAt)}</td>
                  <td className="px-3 py-1.5 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        deleteFlagged(f.id)
                      }}
                      className="text-content-muted hover:text-semantic-error inline-flex items-center"
                      title="Delete flagged request"
                    >
                      <X size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {error && (
        <div className="shrink-0 px-3 py-1 text-[10px] text-semantic-error border-t border-border">
          {error}
        </div>
      )}
      {modal}
    </DashboardPanel>
  )
}
