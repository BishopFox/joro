import { createContext, useContext, type ReactNode } from 'react'

// DashboardPanel is the shared chrome for every dashboard widget: the outer
// container, the uppercase title bar with an optional count, and the body.
//
// A widget does not know which slot it lands in, so the chrome is supplied by
// the slot through context rather than by a prop. That is what lets the same
// widget render as a bordered card in a row slot and as a segment of the
// terminal-toned bottom bar without the widget knowing the difference.

export interface SlotChrome {
  /** Class list for the panel's outer element. Owns sizing and surface. */
  outer: string
  /** Class list for the title text (surface-dependent). */
  title: string
}

// Row slots are self-contained cards.
export const ROW_CHROME: SlotChrome = {
  outer: 'flex-1 min-w-0 min-h-0 flex flex-col bg-surface-card border border-border rounded',
  title: 'text-content-primary',
}

// The bottom bar supplies its own surface and border, so its two slots are
// bare flex children that only carry sizing.
export const BAR_MAIN_CHROME: SlotChrome = {
  outer: 'flex-1 min-w-0 flex flex-col',
  title: 'text-content-terminal',
}

export const BAR_ASIDE_CHROME: SlotChrome = {
  outer: 'w-52 shrink-0 flex flex-col border-l border-border',
  title: 'text-content-terminal',
}

const SlotChromeContext = createContext<SlotChrome>(ROW_CHROME)

export function SlotChromeProvider({
  chrome,
  children,
}: {
  chrome: SlotChrome
  children: ReactNode
}) {
  return <SlotChromeContext.Provider value={chrome}>{children}</SlotChromeContext.Provider>
}

interface DashboardPanelProps {
  title: string
  /** Rendered beside the title when greater than zero. */
  count?: number
  /** Extra header content, right of the title. */
  headerExtra?: ReactNode
  /** Defaults to a single scrolling region. */
  bodyClassName?: string
  children: ReactNode
}

export default function DashboardPanel({
  title,
  count,
  headerExtra,
  bodyClassName = 'flex-1 overflow-y-auto',
  children,
}: DashboardPanelProps) {
  const chrome = useContext(SlotChromeContext)
  return (
    <div className={chrome.outer}>
      <div className="shrink-0 px-3 py-2 border-b border-border">
        <span className={`text-xs font-semibold uppercase tracking-wide ${chrome.title}`}>
          {title}
        </span>
        {count !== undefined && count > 0 && (
          <span className="ml-2 text-content-muted text-xs">{count}</span>
        )}
        {headerExtra}
      </div>
      <div className={bodyClassName}>{children}</div>
    </div>
  )
}

// EmptyPanelBody centres a muted hint inside a panel body.
export function EmptyPanelBody({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center justify-center h-full">
      <span className="text-content-muted text-xs">{children}</span>
    </div>
  )
}
