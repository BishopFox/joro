import type { NavigateFunction } from 'react-router-dom'
import type { MenuItem } from '../components/ContextMenu'

export function getSelectionMenuItems(navigate: NavigateFunction): MenuItem[] {
  const text = window.getSelection()?.toString()
  const trimmed = text?.trim()
  if (!text || !trimmed) return []
  return [
    { label: 'Copy Text', onClick: () => { navigator.clipboard.writeText(text) } },
    { label: 'Transform', onClick: () => navigate('/transform', { state: { text: trimmed } }) },
  ]
}
