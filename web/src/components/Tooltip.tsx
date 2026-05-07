import { useState, useRef, useEffect, useLayoutEffect, ReactNode } from 'react'
import { createPortal } from 'react-dom'

const DEFAULT_DELAY_MS = 200
const GAP_PX = 6

type Placement = 'top' | 'bottom'

interface TooltipProps {
  content: string
  children: ReactNode
  delay?: number
  placement?: Placement
}

interface Position {
  left: number
  top: number
  ready: boolean
}

export function Tooltip({ content, children, delay = DEFAULT_DELAY_MS, placement = 'bottom' }: TooltipProps) {
  const [pos, setPos] = useState<Position | null>(null)
  const timerRef = useRef<number | null>(null)
  const wrapRef = useRef<HTMLSpanElement | null>(null)
  const tooltipRef = useRef<HTMLDivElement | null>(null)

  const clearTimer = () => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }

  const show = () => {
    clearTimer()
    timerRef.current = window.setTimeout(() => {
      setPos({ left: 0, top: 0, ready: false })
    }, delay)
  }

  const hide = () => {
    clearTimer()
    setPos(null)
  }

  useLayoutEffect(() => {
    if (!pos || pos.ready) return
    const wrap = wrapRef.current
    const tip = tooltipRef.current
    if (!wrap || !tip) return
    const range = document.createRange()
    range.selectNodeContents(wrap)
    const rect = range.getBoundingClientRect()
    if (rect.width === 0 && rect.height === 0) return
    const tipW = tip.offsetWidth
    const tipH = tip.offsetHeight
    const vw = window.innerWidth
    const vh = window.innerHeight

    let actual: Placement = placement
    if (placement === 'bottom' && rect.bottom + GAP_PX + tipH > vh && rect.top - GAP_PX - tipH >= 0) {
      actual = 'top'
    } else if (placement === 'top' && rect.top - GAP_PX - tipH < 0 && rect.bottom + GAP_PX + tipH <= vh) {
      actual = 'bottom'
    }

    const centerX = rect.left + rect.width / 2
    const left = Math.max(4, Math.min(centerX - tipW / 2, vw - tipW - 4))
    const top = actual === 'bottom' ? rect.bottom + GAP_PX : rect.top - GAP_PX - tipH

    setPos({ left, top, ready: true })
  }, [pos, placement])

  useEffect(() => () => clearTimer(), [])

  return (
    <>
      <span
        ref={wrapRef}
        className="contents"
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
      >
        {children}
      </span>
      {pos && createPortal(
        <div
          ref={tooltipRef}
          role="tooltip"
          className="fixed z-50 pointer-events-none px-2 py-1 rounded-sm bg-surface-card border border-border text-xs text-content-primary shadow-md max-w-xs whitespace-normal"
          style={{ left: pos.left, top: pos.top, visibility: pos.ready ? 'visible' : 'hidden' }}
        >
          {content}
        </div>,
        document.body
      )}
    </>
  )
}
