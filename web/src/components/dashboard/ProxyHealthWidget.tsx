import type { ReactNode } from 'react'
import { ShieldCheck, ShieldOff } from 'lucide-react'
import DashboardPanel, { EmptyPanelBody } from '../DashboardPanel'
import { useDashboardDataStore } from '../../stores/dashboardDataStore'
import { useSettingsStore } from '../../stores/settingsStore'
import { Redacted } from '../Redacted'

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
          {/* Ports are Joro's own configuration and stay readable; the address is
              what identifies the machine. */}
          <Row label="Proxy">
            <Redacted value={health.bindAddr || '127.0.0.1'} kind="ip" />
            {`:${health.proxyPort}`}
          </Row>
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
          <Row label="Active project">
            {health.activeProject ? <Redacted value={health.activeProject} kind="identity" /> : 'none'}
          </Row>
          <Row label="Intercept requests">
            <OnOff on={!!settings?.interceptEnabled} />
          </Row>
          <Row label="Intercept responses">
            <OnOff on={!!settings?.interceptResponses} />
          </Row>
          <Row label="Scope">
            <OnOff on={!!settings?.scopeEnabled} />
            {settings?.scopeEnabled && (
              <span className="text-content-muted"> ({settings.scopeRules?.length ?? 0} rules)</span>
            )}
          </Row>
          <Row label="Upstream proxy">
            {settings?.socksHost ? (
              <>
                socks <Redacted value={settings.socksHost} kind="host" />
                {`:${settings.socksPort}`}
              </>
            ) : (
              'direct'
            )}
          </Row>
        </div>
      )}
    </DashboardPanel>
  )
}
