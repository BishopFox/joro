import { useEffect } from 'react'

type Props = {
  title?: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
  onConfirm: () => void
  onClose: () => void
}

export default function ConfirmModal({
  title = 'Confirm',
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  danger = true,
  onConfirm,
  onClose,
}: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
      if (e.key === 'Enter') onConfirm()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, onConfirm])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6" onMouseDown={onClose}>
      <div
        className="flex flex-col w-full max-w-sm bg-surface-card border border-border rounded shadow-lg overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-border">
          <span className="text-xs font-semibold text-content-primary uppercase tracking-wide">{title}</span>
        </div>
        <p className="px-4 py-4 text-sm text-content-primary">{message}</p>
        <div className="flex justify-end gap-2 px-4 py-3 border-t border-border">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs font-semibold"
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            autoFocus
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
