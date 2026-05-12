import { useCallback, useRef, useState } from 'react'

export function useResizable(
  direction: 'horizontal' | 'vertical',
  initialFraction = 0.5,
) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [fraction, setFraction] = useState(initialFraction)

  const onMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault()
      const container = containerRef.current
      if (!container) return
      const rect = container.getBoundingClientRect()

      function onMouseMove(ev: MouseEvent) {
        const pos =
          direction === 'horizontal'
            ? (ev.clientX - rect.left) / rect.width
            : (ev.clientY - rect.top) / rect.height
        setFraction(Math.max(0.1, Math.min(0.9, pos)))
      }

      function onMouseUp() {
        document.removeEventListener('mousemove', onMouseMove)
        document.removeEventListener('mouseup', onMouseUp)
        document.body.style.cursor = ''
        document.body.style.userSelect = ''
      }

      document.body.style.cursor =
        direction === 'horizontal' ? 'col-resize' : 'row-resize'
      document.body.style.userSelect = 'none'
      document.addEventListener('mousemove', onMouseMove)
      document.addEventListener('mouseup', onMouseUp)
    },
    [direction],
  )

  return { containerRef, fraction, onMouseDown }
}
