import type { ReactNode } from 'react'
import NetworkGraphWidget from '../components/dashboard/NetworkGraphWidget'
import RecentInteractionsWidget from '../components/dashboard/RecentInteractionsWidget'
import FlaggedRequestsWidget from '../components/dashboard/FlaggedRequestsWidget'
import TeamChatWidget from '../components/dashboard/TeamChatWidget'
import ActiveUsersWidget from '../components/dashboard/ActiveUsersWidget'
import DetectFindingsWidget from '../components/dashboard/DetectFindingsWidget'
import ProxyHealthWidget from '../components/dashboard/ProxyHealthWidget'

// The dashboard widget catalog. Adding a widget means adding a component and
// one entry here — nothing in the Go backend, the layout store, or the Settings
// editor needs to change.

export type WidgetId =
  | 'network-graph'
  | 'recent-interactions'
  | 'flagged-requests'
  | 'team-chat'
  | 'active-users'
  | 'detect-findings'
  | 'proxy-health'

/** A slot value of 'none' leaves the slot empty. */
export const NO_WIDGET = 'none'

// DataNeed names a data source useDashboardPolling can fetch. The union of the
// needs of the widgets actually in the layout is what the poll loop fetches, so
// a widget that isn't on the dashboard costs no requests.
export type DataNeed =
  | 'callbacks'
  | 'sliver'
  | 'mythic'
  | 'systemInfo'
  | 'flagged'
  | 'team'
  | 'detect'
  | 'health'

export interface WidgetDef {
  id: WidgetId
  label: string
  description: string
  /** Only meaningful when joined to a team server. */
  requiresTeam?: boolean
  /** Only meaningful in proxy mode (the endpoints don't exist in listener mode). */
  requiresProxyMode?: boolean
  needs: DataNeed[]
  render: () => ReactNode
}

// Availability is expressed as two declarative flags rather than an opaque
// predicate, so the Settings editor can explain *why* a widget is unavailable.
export const WIDGETS: WidgetDef[] = [
  {
    id: 'network-graph',
    label: 'Network Graph',
    description: 'Operators, team server, and C2 sessions as a live graph.',
    requiresProxyMode: true,
    needs: ['sliver', 'mythic', 'systemInfo'],
    render: () => <NetworkGraphWidget />,
  },
  {
    id: 'detect-findings',
    label: 'Detected Findings',
    description: 'Passive detection: severity counts and the most recent findings.',
    requiresProxyMode: true,
    needs: ['detect'],
    render: () => <DetectFindingsWidget />,
  },
  {
    id: 'proxy-health',
    label: 'Proxy Health',
    description: 'Listener addresses, CA state, capture count, and session settings.',
    requiresProxyMode: true,
    needs: ['health'],
    render: () => <ProxyHealthWidget />,
  },
  {
    id: 'recent-interactions',
    label: 'Recent Interactions',
    description: 'Out-of-band callbacks and XSS fires, newest first.',
    needs: ['callbacks'],
    render: () => <RecentInteractionsWidget />,
  },
  {
    id: 'flagged-requests',
    label: 'Flagged Requests',
    description: 'Requests your team has flagged for review.',
    requiresTeam: true,
    needs: ['flagged'],
    render: () => <FlaggedRequestsWidget />,
  },
  {
    // Not requiresTeam: it degrades to a local-only scratchpad off a team server.
    id: 'team-chat',
    label: 'Team Chat',
    description: 'Team chat and slash commands; a local scratchpad when solo.',
    needs: ['team'],
    render: () => <TeamChatWidget />,
  },
  {
    id: 'active-users',
    label: 'Active Users',
    description: 'Who else is connected, and your own presence controls.',
    needs: ['team'],
    render: () => <ActiveUsersWidget />,
  },
]

export const WIDGET_BY_ID = new Map<string, WidgetDef>(WIDGETS.map((w) => [w.id, w]))

export interface AvailabilityCtx {
  mode: string
  teamMode: boolean
}

export function isAvailable(w: WidgetDef, ctx: AvailabilityCtx): boolean {
  if (w.requiresProxyMode && ctx.mode !== 'proxy') return false
  if (w.requiresTeam && !ctx.teamMode) return false
  return true
}

// unavailableReason explains a widget the current session can't show. Used by
// the Settings editor only — the dashboard itself just omits the widget.
export function unavailableReason(w: WidgetDef, ctx: AvailabilityCtx): string {
  if (w.requiresProxyMode && ctx.mode !== 'proxy') return 'proxy mode only'
  if (w.requiresTeam && !ctx.teamMode) return 'team server only'
  return ''
}
