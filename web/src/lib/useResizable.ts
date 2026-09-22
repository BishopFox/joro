import { useCallback, useRef, useState } from 'react'
import { beginPointerDrag } from './pointerDrag'

/** A divider between two panes, as a fraction of the container.
 *
 *  Spread `handleProps` onto the divider element; see pointerDrag.ts for why the
 *  gesture is a captured pointer drag and not mouse events on `document`. */
export function useResizable(
  direction: 'horizontal' | 'vertical',
  initialFraction = 0.5,
) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [fraction, setFraction] = useState(initialFraction)

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      if (e.button !== 0 || !e.isPrimary) return
      if (!containerRef.current) return

      beginPointerDrag(e, direction === 'horizontal' ? 'col-resize' : 'row-resize', (ev) => {
        const container = containerRef.current
        if (!container) return
        // Measured per frame, not once at pointerdown: a banner appearing or a
        // window resize during the drag moves the container out from under a
        // rect taken at the start. One read at the top of a frame, before any
        // write, so it does not thrash layout.
        const rect = container.getBoundingClientRect()
        const pos =
          direction === 'horizontal'
            ? (ev.clientX - rect.left) / rect.width
            : (ev.clientY - rect.top) / rect.height
        const next = Math.max(0.1, Math.min(0.9, pos))
        setFraction((prev) => (prev === next ? prev : next))
      })
    },
    [direction],
  )

  // Reset. Deliberately the native dblclick rather than a click count taken in
  // onPointerDown: the second press starts a drag of its own, whose first move
  // would recompute the fraction from the pointer's position on the old divider
  // and silently undo the reset. preventDefault on pointerdown suppresses the
  // compatibility mousedown/mouseup, not click or dblclick.
  const onDoubleClick = useCallback(() => setFraction(initialFraction), [initialFraction])

  return { containerRef, fraction, handleProps: { onPointerDown, onDoubleClick } }
}
