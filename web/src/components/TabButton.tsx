import type { ReactNode } from 'react'

/** One tab in a request/response detail strip: Raw, Render, or a lens. */
export default function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={`px-2 py-0.5 rounded-sm text-[10px] font-semibold transition-colors ${
        active
          ? 'bg-accent text-content-primary'
          : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
      }`}
    >
      {children}
    </button>
  )
}
