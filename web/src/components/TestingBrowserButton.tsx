import { useEffect, useState } from 'react'
import { AppWindow } from 'lucide-react'
import { api } from '../lib/api'
import { getBrowserPrefs } from '../lib/browserPrefs'
import { useToastStore } from '../stores/toastStore'

// TestingBrowserButton is the header quick-action that launches the managed
// testing browser (proxy-routed, CA-trusted) using the saved landing URL. It
// disables itself when no supported browser is detected. Full configuration
// (landing URL, clear cookies, setup check, CA download) lives in Settings.
export default function TestingBrowserButton() {
  const addToast = useToastStore((s) => s.addToast)
  const [avail, setAvail] = useState<{ available: boolean; browser: string } | null>(null)
  const [launching, setLaunching] = useState(false)

  useEffect(() => {
    api.browserStatus().then(setAvail).catch(() => {})
  }, [])

  const unavailable = avail !== null && !avail.available
  const title = unavailable
    ? 'No supported browser detected (Chrome, Chromium, Edge, or Brave)'
    : avail?.available
      ? `Launch testing browser (${avail.browser})`
      : 'Launch testing browser'

  async function launch() {
    if (launching || unavailable) return
    setLaunching(true)
    try {
      const res = await api.launchBrowser({ url: getBrowserPrefs().url })
      addToast(`Launched ${res.browser}`, 'info')
    } catch (e) {
      addToast(`Launch failed: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setLaunching(false)
    }
  }

  return (
    <button
      onClick={launch}
      disabled={launching || unavailable}
      title={title}
      className={`flex items-center p-1.5 rounded-sm transition-colors ${
        unavailable
          ? 'text-content-muted opacity-40 cursor-not-allowed'
          : 'text-content-muted hover:text-content-primary'
      }`}
    >
      <AppWindow size={20} strokeWidth={1.7} aria-hidden="true" className={launching ? 'animate-pulse' : ''} />
    </button>
  )
}
