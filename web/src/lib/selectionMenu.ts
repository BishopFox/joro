import type { NavigateFunction } from 'react-router-dom'
import type { MenuItem } from '../components/ContextMenu'
import { copyText } from './clipboard'

export function getSelectionMenuItems(navigate: NavigateFunction): MenuItem[] {
  const text = window.getSelection()?.toString()
  const trimmed = text?.trim()
  if (!text || !trimmed) return []
  return [
    { label: 'Copy Text', onClick: () => copyText(text) },
    { label: 'Transform', onClick: () => navigate('/transform', { state: { text: trimmed } }) },
  ]
}
