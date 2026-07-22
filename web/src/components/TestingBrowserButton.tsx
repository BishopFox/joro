import { useEffect, useState } from 'react'
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
      {/* Browser-window glyph (no icon library in this project) */}
      <svg
        viewBox="0 0 24 24"
        width="20"
        height="20"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.7}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        className={launching ? 'animate-pulse' : ''}
      >
        <rect x="3" y="4" width="18" height="16" rx="2" />
        <path d="M3 8 H21" />
        <circle cx="6" cy="6" r="0.6" fill="currentColor" stroke="none" />
        <circle cx="8.2" cy="6" r="0.6" fill="currentColor" stroke="none" />
        <circle cx="10.4" cy="6" r="0.6" fill="currentColor" stroke="none" />
      </svg>
    </button>
  )
}
