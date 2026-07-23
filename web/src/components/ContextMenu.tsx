import { useEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Check, ChevronRight } from 'lucide-react'

export interface MenuItem {
  label: string
  onClick?: () => void
  children?: MenuItem[]
  disabled?: boolean
  checked?: boolean
  icon?: ReactNode
}

interface ContextMenuProps {
  x: number
  y: number
  items: MenuItem[]
  onClose: () => void
}

function MenuList({ items, x, y, onClose, isSubmenu }: { items: MenuItem[]; x: number; y: number; onClose: () => void; isSubmenu?: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState({ x, y })
  const [openSub, setOpenSub] = useState<number | null>(null)
  const [subPos, setSubPos] = useState({ x: 0, y: 0 })
  const hoverTimer = useRef<ReturnType<typeof setTimeout>>()

  useEffect(() => {
    if (!ref.current) return
    const rect = ref.current.getBoundingClientRect()
    let nx = x, ny = y
    if (rect.right > window.innerWidth) nx = isSubmenu ? x - rect.width - (ref.current.parentElement?.getBoundingClientRect().width ?? 0) : window.innerWidth - rect.width - 4
    if (rect.bottom > window.innerHeight) ny = window.innerHeight - rect.height - 4
    if (nx < 0) nx = 4
    if (ny < 0) ny = 4
    if (nx !== x || ny !== y) setPos({ x: nx, y: ny })
  }, [x, y, isSubmenu])

  function handleItemHover(idx: number, el: HTMLDivElement) {
    clearTimeout(hoverTimer.current)
    if (items[idx].children) {
      hoverTimer.current = setTimeout(() => {
        const rect = el.getBoundingClientRect()
        setSubPos({ x: rect.right, y: rect.top })
        setOpenSub(idx)
      }, 120)
    } else {
      hoverTimer.current = setTimeout(() => setOpenSub(null), 200)
    }
  }

  function handleItemClick(item: MenuItem) {
    if (item.disabled || item.children) return
    item.onClick?.()
    onClose()
  }

  return (
    <div
      ref={ref}
      style={{
        position: 'fixed',
        left: pos.x,
        top: pos.y,
        zIndex: 9999,
        minWidth: 200,
        background: 'var(--color-surface-card)',
        border: '1px solid var(--color-border)',
        borderRadius: 4,
        boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
        padding: '4px 0',
        fontFamily: 'inherit',
        fontSize: 12,
      }}
      onMouseLeave={() => { clearTimeout(hoverTimer.current) }}
    >
      {items.map((item, idx) => (
        <div
          key={idx}
          onMouseEnter={(e) => handleItemHover(idx, e.currentTarget)}
          onClick={() => handleItemClick(item)}
          style={{
            display: 'flex',
            alignItems: 'center',
            padding: '6px 12px',
            cursor: item.disabled ? 'default' : 'pointer',
            color: item.disabled ? 'var(--color-content-muted)' : 'var(--color-content-primary)',
            background: 'transparent',
            transition: 'background 0.1s',
            userSelect: 'none',
          }}
          onMouseOver={(e) => {
            if (!item.disabled) (e.currentTarget as HTMLDivElement).style.background = 'var(--color-surface-hover)'
          }}
          onMouseOut={(e) => {
            (e.currentTarget as HTMLDivElement).style.background = 'transparent'
          }}
        >
          <span style={{ width: 18, flexShrink: 0, display: 'inline-flex', alignItems: 'center', color: 'var(--color-accent)' }}>
            {item.checked ? <Check size={12} /> : null}
          </span>
          {item.icon && <span style={{ marginRight: 8, display: 'inline-flex', alignItems: 'center' }}>{item.icon}</span>}
          <span style={{ flex: 1 }}>{item.label}</span>
          {item.children && <span style={{ marginLeft: 8, display: 'inline-flex', alignItems: 'center', color: 'var(--color-content-muted)' }}><ChevronRight size={12} /></span>}
        </div>
      ))}
      {openSub !== null && items[openSub].children && (
        <MenuList items={items[openSub].children!} x={subPos.x} y={subPos.y} onClose={onClose} isSubmenu />
      )}
    </div>
  )
}

export default function ContextMenu({ x, y, items, onClose }: ContextMenuProps) {
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      // Close if click is outside any menu
      const target = e.target as HTMLElement
      if (!target.closest('[data-ctx-menu]')) onClose()
    }
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('mousedown', handleClick, true)
    document.addEventListener('keydown', handleKey, true)
    return () => {
      document.removeEventListener('mousedown', handleClick, true)
      document.removeEventListener('keydown', handleKey, true)
    }
  }, [onClose])

  return createPortal(
    <div data-ctx-menu>
      <MenuList items={items} x={x} y={y} onClose={onClose} />
    </div>,
    document.body
  )
}
