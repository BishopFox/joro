import type { ReactNode } from 'react'
import { ShieldCheck, ShieldOff } from 'lucide-react'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import { useDashboardDataStore } from '../../stores/dashboardDataStore'
import { useSettingsStore } from '../../stores/settingsStore'

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 px-3 py-1.5 border-t border-border-subtle first:border-t-0">
      <span className="text-content-secondary shrink-0">{label}</span>
      <span className="text-content-primary font-mono text-[11px] truncate text-right">{children}</span>
    </div>
  )
}

function OnOff({ on }: { on: boolean }) {
  return (
    <span className={on ? 'text-semantic-success' : 'text-content-muted'}>{on ? 'on' : 'off'}</span>
  )
}

// ProxyHealthWidget shows where the proxy is listening and the state of the
// current session, for an operator running Joro without a team server.
export default function ProxyHealthWidget() {
  const health = useDashboardDataStore((s) => s.health)
  const settings = useSettingsStore((s) => s.settings)

  return (
    <DashboardPanel title="Proxy Health">
      {!health ? (
        <EmptyPanelBody>Loading…</EmptyPanelBody>
      ) : (
        <div className="text-xs">
          <Row label="Proxy">{`${health.bindAddr || '127.0.0.1'}:${health.proxyPort}`}</Row>
          <Row label="UI">{`:${health.uiPort}`}</Row>
          <Row label="CA certificate">
            {health.caPresent ? (
              <span className="inline-flex items-center gap-1 text-semantic-success">
                <ShieldCheck size={12} /> installed
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-semantic-warning">
                <ShieldOff size={12} /> missing
              </span>
            )}
          </Row>
          <Row label="Testing browser">
            {health.browserAvailable ? health.browserName : 'none detected'}
          </Row>
          <Row label="Requests captured">
            {health.requestCount.toLocaleString()}
            {settings ? (
              <span className="text-content-muted"> / {settings.maxRequests.toLocaleString()}</span>
            ) : null}
          </Row>
          <Row label="Active project">{health.activeProject || 'none'}</Row>
          <Row label="Intercept">
            <OnOff on={!!settings?.interceptEnabled} />
          </Row>
          <Row label="Scope">
            <OnOff on={!!settings?.scopeEnabled} />
            {settings?.scopeEnabled && (
              <span className="text-content-muted"> ({settings.scopeRules?.length ?? 0} rules)</span>
            )}
          </Row>
          <Row label="Upstream proxy">
            {settings?.socksHost ? `socks ${settings.socksHost}:${settings.socksPort}` : 'direct'}
          </Row>
        </div>
      )}
    </DashboardPanel>
  )
}
