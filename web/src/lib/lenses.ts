import { useMemo } from 'react'
import { useAutomationStore } from '../stores/automationStore'
import type { AutomationSummary } from './api'

/**
 * Bytes over this are truncated before a lens sees them. Base64 expansion has to leave
 * the body inside the automation control plane's 2 MB limit.
 */
export const MAX_LENS_BYTES = 512 * 1024

export type ViewerPart = 'request' | 'response'

/** The lenses that apply to one half of a transaction, in tab order. */
export function useLenses(part: ViewerPart): AutomationSummary[] {
  const scripts = useAutomationStore((s) => s.scripts)
  return useMemo(
    () =>
      scripts
        .filter((s) => s.enabled && s.lens && (s.lens.part === part || s.lens.part === 'both'))
        .sort(
          (a, b) =>
            (a.lensOrder ?? 0) - (b.lensOrder ?? 0) || a.lens!.label.localeCompare(b.lens!.label)
        ),
    [scripts, part]
  )
}
