import { useMemo } from 'react'
import NetworkGraph from '../NetworkGraph'
import DashboardPanel from '../DashboardPanel'
import { useDashboardDataStore } from '../../stores/dashboardDataStore'
import { useSettingsStore } from '../../stores/settingsStore'
import { useTeamConnectionStore } from '../../stores/teamConnectionStore'

// NetworkGraphWidget adapts the polled dashboard data onto <NetworkGraph>,
// which stays a pure prop-driven component.
export default function NetworkGraphWidget() {
  const localHost = useDashboardDataStore((s) => s.localHost)
  const sliver = useDashboardDataStore((s) => s.sliver)
  const mythic = useDashboardDataStore((s) => s.mythic)
  const listenerUrl = useSettingsStore((s) => s.settings?.listenerUrl)
  const teamConn = useTeamConnectionStore((s) => s.state)

  // Memoized so the SVG (which carries drag/zoom state) doesn't see fresh
  // object identities on every poll tick.
  const teamServer = useMemo(
    () => (listenerUrl ? { url: listenerUrl } : undefined),
    [listenerUrl]
  )
  const sliverServer = useMemo(
    () => (sliver.connected ? { lhost: sliver.lhost, lport: sliver.lport } : undefined),
    [sliver.connected, sliver.lhost, sliver.lport]
  )
  const mythicServer = useMemo(
    () => (mythic.connected ? { url: mythic.url } : undefined),
    [mythic.connected, mythic.url]
  )

  return (
    <DashboardPanel title="Network Graph" bodyClassName="flex-1 min-h-0">
      <NetworkGraph
        localHost={localHost || undefined}
        teamServer={teamServer}
        sliverServer={sliverServer}
        sessions={sliver.sessions}
        beacons={sliver.beacons}
        // Reflect real relay state when a team server is configured; in
        // solo mode there's no relay, so keep the graph "connected".
        connected={listenerUrl ? teamConn === 'connected' : true}
        mythicServer={mythicServer}
        mythicCallbacks={mythic.callbacks}
      />
    </DashboardPanel>
  )
}
