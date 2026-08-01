import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import {
  SlotChromeProvider,
  ROW_CHROME,
  BAR_MAIN_CHROME,
  BAR_ASIDE_CHROME,
  type SlotChrome,
} from '../components/DashboardPanel'
import {
  WIDGET_BY_ID,
  NO_WIDGET,
  isAvailable,
  type AvailabilityCtx,
  type DataNeed,
  type WidgetDef,
} from '../lib/dashboardWidgets'
import { presetOrDefault } from '../lib/dashboardPresets'
import { useDashboardPolling } from '../lib/useDashboardPolling'
import {
  useDashboardLayoutStore,
  MIN_BAR_HEIGHT,
  MAX_BAR_HEIGHT,
} from '../stores/dashboardLayoutStore'
import { useDashboardDataStore } from '../stores/dashboardDataStore'

interface DashboardProps {
  teamMode?: boolean
}

// Dashboard is a frame, not a layout: it resolves the operator's stored layout
// for the current mode into widgets, then renders the preset's rows above a
// shared, resizable bottom bar. Everything visible comes from the widget
// catalog in lib/dashboardWidgets.tsx.
export default function Dashboard({ teamMode = false }: DashboardProps) {
  const mode = useDashboardDataStore((s) => s.mode)
  const layout = useDashboardLayoutStore((s) => s.layout)
  const setBarHeight = useDashboardLayoutStore((s) => s.setBarHeight)

  // Live height during a drag; committed to the store (and localStorage) once
  // on mouseup rather than on every mousemove.
  const [dragHeight, setDragHeight] = useState<number | null>(null)
  const barHeight = dragHeight ?? layout.barHeight

  const modeLayout = teamMode ? layout.team : layout.local
  const preset = presetOrDefault(modeLayout.preset, teamMode ? 'classic' : 'grid')

  const ctx: AvailabilityCtx = useMemo(() => ({ mode, teamMode }), [mode, teamMode])

  // A slot resolves to a widget only if the id is known AND available in this
  // session. Unresolved slots render nothing and collapse — flex siblings take
  // the space, which is how the pre-layout dashboard behaved when it hid the
  // network graph in listener mode or flagged requests when solo. The stored id
  // is never rewritten, so a team widget survives a trip through local mode.
  const resolve = useCallback(
    (slotKey: string): WidgetDef | null => {
      const id = modeLayout.slots[slotKey]
      if (!id || id === NO_WIDGET) return null
      const def = WIDGET_BY_ID.get(id)
      return def && isAvailable(def, ctx) ? def : null
    },
    [modeLayout, ctx]
  )

  // The poll loop fetches exactly what the resolved layout asks for.
  const needs = useMemo(() => {
    const set = new Set<DataNeed>()
    for (const key of Object.keys(modeLayout.slots)) {
      const id = modeLayout.slots[key]
      const def = id && id !== NO_WIDGET ? WIDGET_BY_ID.get(id) : undefined
      if (def && isAvailable(def, ctx)) def.needs.forEach((n) => set.add(n))
    }
    return set
  }, [modeLayout, ctx])

  useDashboardPolling(needs, teamMode)

  const handleDragStart = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault()
      const startY = e.clientY
      const startHeight = barHeight
      let latest = startHeight

      const onMouseMove = (ev: MouseEvent) => {
        latest = Math.min(MAX_BAR_HEIGHT, Math.max(MIN_BAR_HEIGHT, startHeight + (startY - ev.clientY)))
        setDragHeight(latest)
      }

      const onMouseUp = () => {
        document.removeEventListener('mousemove', onMouseMove)
        document.removeEventListener('mouseup', onMouseUp)
        document.body.style.cursor = ''
        document.body.style.userSelect = ''
        setDragHeight(null)
        setBarHeight(latest)
      }

      document.body.style.cursor = 'row-resize'
      document.body.style.userSelect = 'none'
      document.addEventListener('mousemove', onMouseMove)
      document.addEventListener('mouseup', onMouseUp)
    },
    [barHeight, setBarHeight]
  )

  const slot = useCallback(
    (key: string, chrome: SlotChrome): ReactNode => {
      const def = resolve(key)
      if (!def) return null
      return (
        <SlotChromeProvider key={def.id} chrome={chrome}>
          {def.render()}
        </SlotChromeProvider>
      )
    },
    [resolve]
  )

  const rowSlot = useCallback((key: string) => slot(key, ROW_CHROME), [slot])
  const barMain = slot('barMain', BAR_MAIN_CHROME)
  const barAside = slot('barAside', BAR_ASIDE_CHROME)
  const showBar = Boolean(barMain || barAside)
  const hasRowWidget = preset.slots.some((s) => resolve(s.key) !== null)

  return (
    <div className="flex flex-col h-full p-2 gap-2">
      {hasRowWidget ? (
        preset.renderRow(rowSlot)
      ) : (
        <div className="flex-1 min-h-0 flex items-center justify-center">
          <span className="text-content-muted text-xs">
            No widgets in this layout —{' '}
            <Link
              to="/settings"
              state={{ category: 'appearance' }}
              className="text-accent-secondary hover:underline"
            >
              configure the dashboard
            </Link>
          </span>
        </div>
      )}

      {showBar && (
        <>
          <div
            onMouseDown={handleDragStart}
            className="shrink-0 h-1.5 cursor-row-resize rounded-full bg-border hover:bg-accent-secondary transition-colors"
          />
          <div
            className="shrink-0 flex bg-surface-terminal border border-border rounded"
            style={{ height: barHeight }}
          >
            {barMain}
            {barAside}
          </div>
        </>
      )}
    </div>
  )
}
