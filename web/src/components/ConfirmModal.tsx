import { useEffect, type ReactNode } from 'react'

type Props = {
  title?: string
  message: string
  /** Extra detail below the message, for a confirmation that needs more than a line. */
  body?: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
  /** Must sit above the modal that opened it. Defaults to the standalone tier. */
  zIndexClass?: string
  /** Requires a deliberate click: the confirm button is not focused and Enter does
   *  not confirm. Escape still cancels. */
  deliberate?: boolean
  onConfirm: () => void
  onClose: () => void
}

export default function ConfirmModal({
  title = 'Confirm',
  message,
  body,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  danger = true,
  zIndexClass = 'z-50',
  deliberate = false,
  onConfirm,
  onClose,
}: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      if (e.key === 'Enter' && !deliberate) onConfirm()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, onConfirm, deliberate])

  return (
    <div
      className={`fixed inset-0 ${zIndexClass} flex items-center justify-center bg-black/60 p-6`}
      onMouseDown={onClose}
    >
      <div
        className={`flex flex-col w-full ${body ? 'max-w-md' : 'max-w-sm'} bg-surface-card border border-border rounded shadow-lg overflow-hidden`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-border">
          <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">{title}</span>
        </div>
        <div className="px-4 py-4 space-y-3">
          <p className="text-sm text-content-primary">{message}</p>
          {body}
        </div>
        <div className="flex justify-end gap-2 px-4 py-3 border-t border-border">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs font-semibold"
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            autoFocus={!deliberate}
            className={`px-3 py-1.5 rounded-sm text-xs font-semibold ${
              danger
                ? 'bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary'
                : 'bg-accent-secondary hover:bg-accent-secondary-hover text-black'
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
