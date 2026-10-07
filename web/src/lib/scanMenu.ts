import { api, ApiError } from './api'
import { useToastStore } from '../stores/toastStore'

// initiateScan starts an active scan from a context menu and surfaces the result
// as a toast. Progress and findings arrive over the activescan.* / detect.* WS
// events, so there is nothing to navigate to — findings land in the Detect tab.
export async function initiateScan(body: {
  scope: 'host' | 'request'
  origin?: string
  url?: string
  requestId?: string
  rules?: string[]
  tags?: string[]
  severity?: string[]
  ignoreFingerprint?: boolean
  oast?: boolean
}): Promise<void> {
  const addToast = useToastStore.getState().addToast
  try {
    const res = await api.startActiveScan(body)
    const skipped = res.skipped > 0 ? ` (${res.skipped} out of scope)` : ''
    addToast(`Active scan started — ${res.urls} URL${res.urls === 1 ? '' : 's'}${skipped}`, 'info')
  } catch (e) {
    const msg = e instanceof ApiError ? e.message : String((e as Error).message ?? e)
    addToast(msg, 'error')
  }
}

// fingerprintHosts re-fingerprints captured history — one host, or all when host
// is omitted — surfacing the result as a toast. Updates arrive over tech.* events.
export async function fingerprintHosts(host?: string): Promise<void> {
  const addToast = useToastStore.getState().addToast
  try {
    await api.techScan(host ? { scope: 'host', host } : { scope: 'all', clear: true })
    addToast(host ? `Fingerprinting ${host}…` : 'Re-fingerprinting all hosts…', 'info')
  } catch (e) {
    const msg = e instanceof ApiError ? e.message : String((e as Error).message ?? e)
    addToast(msg, 'error')
  }
}
