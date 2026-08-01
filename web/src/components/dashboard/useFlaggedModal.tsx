import { useCallback, useState, type ReactNode } from 'react'
import { api } from '../../lib/api'
import FlaggedRequestModal from '../FlaggedRequestModal'
import type { FlaggedRequest } from '../../stores/teamFlaggedStore'

// useFlaggedModal fetches a flagged request and renders its viewer. Shared by
// the Flagged Requests widget and the chat chips that reference one, so the
// failure handling exists in a single place.
export function useFlaggedModal(): {
  openFlagged: (id: string) => Promise<void>
  error: string
  clearError: () => void
  modal: ReactNode
} {
  const [flagged, setFlagged] = useState<FlaggedRequest | null>(null)
  const [error, setError] = useState('')

  const openFlagged = useCallback(async (id: string) => {
    try {
      setFlagged(await api.getFlagged(id))
    } catch {
      // Surface the failure instead of a silent dead click (artifact may have
      // been deleted, or the proxied fetch to the team server timed out).
      setError('Failed to open flagged request')
    }
  }, [])

  return {
    openFlagged,
    error,
    clearError: useCallback(() => setError(''), []),
    modal: flagged ? (
      <FlaggedRequestModal flagged={flagged} onClose={() => setFlagged(null)} />
    ) : null,
  }
}
