import { useEffect } from 'react'
import { useToastStore } from '../stores/toastStore'

export default function Toasts() {
  const toasts = useToastStore((s) => s.toasts)
  const removeToast = useToastStore((s) => s.removeToast)

  return (
    <div className="fixed top-12 right-3 z-50 flex flex-col gap-2 max-w-sm">
      {toasts.map((t) => (
        <ToastItem key={t.id} id={t.id} message={t.message} onDismiss={removeToast} />
      ))}
    </div>
  )
}

function ToastItem({ id, message, onDismiss }: { id: string; message: string; onDismiss: (id: string) => void }) {
  useEffect(() => {
    const timer = setTimeout(() => onDismiss(id), 6000)
    return () => clearTimeout(timer)
  }, [id, onDismiss])

  return (
    <div
      className="px-3 py-2 rounded text-xs bg-semantic-error-bg text-content-primary border border-border shadow-lg cursor-pointer"
      onClick={() => onDismiss(id)}
    >
      {message}
    </div>
  )
}
