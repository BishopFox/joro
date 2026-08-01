import { useCallback, useEffect } from 'react'
import { api } from './api'
import { onMythicEvent } from './ws'
import { buildFindingQuery } from './detectFilters'
import type { DataNeed } from './dashboardWidgets'
import type { SliverSession } from '../components/NetworkGraph'
import { useDashboardDataStore } from '../stores/dashboardDataStore'
import { useDetectStore } from '../stores/detectStore'
import { useTeamConnectionStore } from '../stores/teamConnectionStore'
import { useTeamFlaggedStore } from '../stores/teamFlaggedStore'
import { useTeamStore } from '../stores/teamStore'

const POLL_INTERVAL = 5000

// useDashboardPolling owns the dashboard's single polling loop.
//
// `needs` is the union of the data needs of the widgets in the *resolved*
// layout, computed declaratively before render. Deriving it from the layout
// rather than from mounted widgets avoids an effect-ordering race on the first
// tick, and means a widget that is not on the dashboard never causes a request.
// Pass a memoized Set — it drives the effect dependencies.
export function useDashboardPolling(needs: ReadonlySet<DataNeed>, teamMode: boolean) {
  const setMode = useDashboardDataStore((s) => s.setMode)
  const setLocalHost = useDashboardDataStore((s) => s.setLocalHost)
  const setCallbackData = useDashboardDataStore((s) => s.setCallbackData)
  const setSliver = useDashboardDataStore((s) => s.setSliver)
  const setMythic = useDashboardDataStore((s) => s.setMythic)
  const setHealth = useDashboardDataStore((s) => s.setHealth)
  const setFlaggedItems = useTeamFlaggedStore((s) => s.setItems)

  // Refresh Mythic connection + callbacks for the network graph. Local proxy
  // calls, so safe to run even when the team server is down.
  const refreshMythic = useCallback(async () => {
    let status: { connected: boolean; url?: string } | null = null
    try {
      status = await api.mythicStatus()
    } catch {
      return // keep prior state on a transient failure
    }
    if (!status.connected) {
      setMythic({ connected: false, url: '', callbacks: [] })
      return
    }
    setMythic({ connected: true, url: status.url || '' })
    try {
      const res = await api.mythicCallbacks()
      setMythic({
        callbacks: (res.callbacks || []).map((cb): SliverSession => ({
          id: String(cb.display_id),
          name: cb.payload_type,
          hostname: cb.host,
          os: cb.os,
          arch: cb.architecture,
          remoteAddress: cb.ip,
          transport: cb.payload_type,
          username: cb.user,
        })),
      })
    } catch {
      // keep prior callbacks on a transient failure
    }
  }, [setMythic])

  const fetchData = useCallback(async () => {
    // Isolate each fetch so one failure doesn't block the rest. On failure a
    // call resolves to null (the sentinel) and we KEEP the prior state instead
    // of blanking the panel — a transient timeout (e.g. the team server busy
    // fanning out a flag) shouldn't wipe Recent Interactions for a poll cycle.
    // When the team server is known-down, its listener-proxied polls (callbacks +
    // xss lists) hang until the server-side timeout and saturate the connection
    // pool — skip them and keep the last-known values. getMode/sliverStatus stay
    // (they're local). The 5s interval auto-resumes when a team.relay 'connected'
    // event flips the store back.
    const teamDown = useTeamConnectionStore.getState().state === 'disconnected'
    const wantCallbacks = needs.has('callbacks') && !teamDown
    const wantSliver = needs.has('sliver')

    const [modeRes, intRes, tokRes, firesRes, probesRes, sliverRes, healthRes] = await Promise.all([
      // Always polled: `mode` decides which widgets are available at all.
      api.getMode().catch(() => null),
      wantCallbacks ? api.listInteractions({ limit: 20 }).catch(() => null) : null,
      wantCallbacks ? api.listTokens().catch(() => null) : null,
      wantCallbacks ? api.listFires({ limit: 20 }).catch(() => null) : null,
      wantCallbacks ? api.listProbes().catch(() => null) : null,
      wantSliver
        ? api.sliverStatus().catch((): { connected: boolean; lhost?: string; lport?: number } | null => null)
        : null,
      // Local call, so not teamDown-gated.
      needs.has('health') ? api.healthCheck().catch(() => null) : null,
    ])

    if (modeRes) setMode(modeRes.mode)
    if (intRes) setCallbackData({ interactions: intRes.items || [] })
    if (tokRes) setCallbackData({ tokens: tokRes || [] })
    if (firesRes) setCallbackData({ fires: firesRes.items || [] })
    if (probesRes) setCallbackData({ probes: probesRes || [] })
    if (healthRes) setHealth(healthRes)

    if (sliverRes) {
      if (!sliverRes.connected) {
        setSliver({ connected: false, lhost: '', lport: 0, sessions: [], beacons: [] })
      } else {
        const base = {
          connected: true,
          lhost: sliverRes.lhost || '',
          lport: sliverRes.lport || 0,
        }
        try {
          const sessRes = await api.sliverSessions()
          setSliver({ ...base, sessions: sessRes.sessions || [], beacons: sessRes.beacons || [] })
        } catch {
          // keep prior sessions/beacons on a transient failure
          const prev = useDashboardDataStore.getState().sliver
          setSliver({ ...base, sessions: prev.sessions, beacons: prev.beacons })
        }
      }
    }

    // Mythic callbacks for the network graph (local proxy call).
    if (needs.has('mythic')) refreshMythic()

    // Flagged requests live on the team server; only fetch in team mode and skip
    // when the relay is down (same pool-saturation reason as above).
    if (needs.has('flagged') && teamMode && !teamDown) {
      try {
        const flagged = await api.listFlagged({ limit: 50 })
        setFlaggedItems(flagged.items || [])
      } catch {
        // ignore
      }
    }
  }, [needs, teamMode, refreshMythic, setMode, setCallbackData, setSliver, setHealth, setFlaggedItems])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, POLL_INTERVAL)
    return () => clearInterval(id)
  }, [fetchData])

  // System info is static for the life of the process — fetch it once.
  useEffect(() => {
    if (!needs.has('systemInfo')) return
    api.systemInfo().then(setLocalHost).catch(() => {})
  }, [needs, setLocalHost])

  // Live-refresh the Mythic node group when a new callback checks in, so it
  // shows immediately rather than waiting for the 5s poll.
  useEffect(() => {
    if (!needs.has('mythic')) return
    return onMythicEvent((ev) => {
      if (ev.eventType === 'callback-new') refreshMythic()
    })
  }, [needs, refreshMythic])

  // On join, load the persisted session log (chat + connect/disconnect/rename)
  // and the current active-user list. Both then stay current over the WS.
  useEffect(() => {
    if (!needs.has('team') || !teamMode) return
    const { setMessages, setActiveUsers } = useTeamStore.getState()
    api
      .listChatMessages({ limit: 200 })
      .then((res) => setMessages([...(res.items || [])].reverse())) // endpoint returns newest-first
      .catch(() => {})
    api
      .listActiveUsers()
      .then((users) => setActiveUsers(users || []))
      .catch(() => {})
  }, [needs, teamMode])

  // Detection bootstrap. Findings then stay current over the WS
  // (detect.finding / detect.summary), so there is nothing to poll. The list is
  // only seeded when empty, so a page the operator loaded on /detect with a
  // filter applied is never clobbered.
  useEffect(() => {
    if (!needs.has('detect')) return
    const st = useDetectStore.getState()
    api
      .getDetect()
      .then((res) => {
        st.setEnabled(res.enabled)
        st.setSummary(res.summary)
      })
      .catch(() => {})
    if (st.items.length === 0) {
      api
        .listFindings(buildFindingQuery(st.filter, 'lastSeen', 'desc'))
        .then((res) => useDetectStore.getState().setItems(res.items || [], res.total))
        .catch(() => {})
    }
  }, [needs])
}
