import { useEffect, useRef, useState } from 'react'
import { Check } from 'lucide-react'
import { api } from '../lib/api'
import { getBrowserPrefs } from '../lib/browserPrefs'
import { useToastStore } from '../stores/toastStore'

type Health = Awaited<ReturnType<typeof api.healthCheck>>

interface Props {
  onFinish?: () => void
}

function StepMark({ done, n }: { done: boolean; n: number }) {
  return (
    <span
      className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
        done
          ? 'bg-accent-tertiary text-black'
          : 'border border-border text-content-muted'
      }`}
    >
      {done ? <Check size={14} /> : n}
    </span>
  )
}

export default function HealthCheck({ onFinish }: Props) {
  const [health, setHealth] = useState<Health | null>(null)
  const [launching, setLaunching] = useState(false)
  const [launched, setLaunched] = useState(false)
  const baseline = useRef<number | null>(null)
  const addToast = useToastStore((s) => s.addToast)

  useEffect(() => {
    let active = true
    const poll = async () => {
      try {
        const h = await api.healthCheck()
        if (!active) return
        if (baseline.current === null) baseline.current = h.requestCount
        setHealth(h)
      } catch {
        /* transient — keep polling */
      }
    }
    poll()
    const t = setInterval(poll, 2000)
    return () => {
      active = false
      clearInterval(t)
    }
  }, [])

  const captured = health !== null && baseline.current !== null && health.requestCount > baseline.current
  const proxyAddr = `${health?.bindAddr && health.bindAddr !== '0.0.0.0' ? health.bindAddr : '127.0.0.1'}:${health?.proxyPort ?? ''}`

  async function launch() {
    setLaunching(true)
    try {
      const res = await api.launchBrowser({ url: getBrowserPrefs().url })
      setLaunched(true)
      addToast(`Launched ${res.browser}`, 'info')
    } catch (e) {
      addToast(`Launch failed: ${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setLaunching(false)
    }
  }

  return (
    <div className="w-96 max-w-full bg-surface-card border border-border rounded p-5 space-y-5">
      <div>
        <h2 className="text-sm font-semibold text-content-primary">Connection Check</h2>
        <p className="text-xs text-content-muted mt-1">
          Confirm the proxy is capturing traffic before you begin.
        </p>
      </div>

      {/* Step 1 — proxy running */}
      <div className="flex gap-3">
        <StepMark done={health !== null} n={1} />
        <div className="flex-1">
          <p className="text-xs font-semibold text-content-primary">Proxy running</p>
          <p className="text-xs text-content-muted mt-0.5">
            {health ? `Listening on ${proxyAddr}` : 'Checking…'}
          </p>
        </div>
      </div>

      {/* Step 2 — launch testing browser */}
      <div className="flex gap-3">
        <StepMark done={launched} n={2} />
        <div className="flex-1">
          <p className="text-xs font-semibold text-content-primary">Open the testing browser</p>
          <p className="text-xs text-content-muted mt-0.5">
            Opens a browser routed through the proxy with the CA trusted for this project — no cert install needed.
          </p>
          <div className="flex flex-wrap items-center gap-2 mt-2">
            <button
              onClick={launch}
              disabled={launching || !health?.browserAvailable}
              className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
            >
              {launching ? 'Launching…' : 'Launch Testing Browser'}
            </button>
            <a
              href={api.caCertURL()}
              download="joro-ca.crt"
              className="px-3 py-1.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary text-xs font-semibold"
            >
              Download CA Cert
            </a>
          </div>
          {health && !health.browserAvailable && (
            <p className="text-xs text-semantic-warning mt-1.5">
              No supported browser detected (Chrome, Chromium, Edge, or Brave).
            </p>
          )}
        </div>
      </div>

      {/* Step 3 — verify capture */}
      <div className="flex gap-3">
        <StepMark done={captured} n={3} />
        <div className="flex-1">
          <p className="text-xs font-semibold text-content-primary">Verify capture</p>
          {captured ? (
            <p className="text-xs text-semantic-success mt-0.5">Traffic captured — you're all set.</p>
          ) : (
            <p className="text-xs text-content-muted mt-0.5">
              Browse to any HTTPS site in the testing browser; the first captured request appears here.
            </p>
          )}
        </div>
      </div>

      {onFinish && (
        <div className="flex justify-end pt-1">
          <button
            onClick={onFinish}
            className="px-4 py-2 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
          >
            {captured ? 'Finish' : 'Skip for now'}
          </button>
        </div>
      )}
    </div>
  )
}
