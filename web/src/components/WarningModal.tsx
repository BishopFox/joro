import { useEffect } from 'react'
import { AlertTriangle } from 'lucide-react'

type Props = {
  title?: string
  message: string
  confirmLabel?: string
  onClose: () => void
}

/** A centered, single-button warning dialog for surfacing an error the operator
 *  must see — distinct from a transient toast. Mirrors ConfirmModal's overlay. */
export default function WarningModal({
  title = 'Warning',
  message,
  confirmLabel = 'Dismiss',
  onClose,
}: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === 'Enter') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-6"
      onMouseDown={onClose}
    >
      <div
        className="flex flex-col w-full max-w-md bg-surface-card border border-border rounded shadow-lg overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
          <AlertTriangle size={15} strokeWidth={2} className="text-semantic-warning shrink-0" aria-hidden="true" />
          <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">{title}</span>
        </div>
        <div className="px-4 py-4">
          <p className="text-sm text-content-primary break-words">{message}</p>
        </div>
        <div className="flex justify-end px-4 py-3 border-t border-border">
          <button
            onClick={onClose}
            autoFocus
            className="px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs font-semibold"
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
