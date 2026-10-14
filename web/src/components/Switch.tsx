// Compact slider-style toggle switch, shared across settings panels.
export function Switch({ checked, onChange, title }: { checked: boolean; onChange: (v: boolean) => void; title?: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      title={title}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-4 w-8 shrink-0 items-center rounded-full transition-colors focus:outline-hidden focus-visible:ring-2 focus-visible:ring-accent-secondary ${
        checked ? 'bg-accent-secondary' : 'bg-surface-input border border-border'
      }`}
    >
      <span className={`inline-block h-3 w-3 rounded-full bg-content-primary transition-transform ${checked ? 'translate-x-4' : 'translate-x-0.5'}`} />
    </button>
  )
}
