import type { MenuItem } from '../components/ContextMenu'
import { api } from './api'
import { useToastStore } from '../stores/toastStore'

// Host-level context-menu actions shared by the History table rows and the Site Map host
// menu. Modeled on getSelectionMenuItems. Scope and noise both match a host glob with
// filepath.Match (internal/proxy/scope.go, noise.go), so patterns are the host verbatim.

// hostnameOnly strips a trailing :port, leaving IPv6 bracket forms intact.
function hostnameOnly(host: string): string {
  const close = host.lastIndexOf(']')
  const colon = host.lastIndexOf(':')
  return colon > close ? host.slice(0, colon) : host
}

function toast(msg: string, type: 'error' | 'info' = 'info') {
  useToastStore.getState().addToast(msg, type)
}

async function addScope(pattern: string, path: string, label: string) {
  try {
    const { enabled } = await api.getScope()
    await api.addScopeRule({ pattern, methods: [], path, include: true })
    toast(enabled ? `Added ${label} to scope` : `Added ${label} to scope — scope filtering is off`)
  } catch {
    toast('Failed to add scope rule', 'error')
  }
}

async function addNoise(pattern: string, label: string) {
  try {
    const { enabled } = await api.getNoise()
    await api.addNoisePattern(pattern)
    toast(enabled ? `Added ${label} to noise filter` : `Added ${label} to noise filter — noise filtering is off`)
  } catch {
    toast('Failed to add noise pattern', 'error')
  }
}

// removeHostFromScope deletes the include rules this feature creates for a host: the exact
// host (This host / Exact URL) and the subdomain wildcard. It leaves operator-authored broad
// wildcards and exclude rules alone.
async function removeHostFromScope(host: string) {
  try {
    const exact = host.toLowerCase()
    const wildcard = `*.${hostnameOnly(host).toLowerCase()}`
    const { rules } = await api.getScope()
    const victims = rules.filter((r) => r.include && (r.pattern === exact || r.pattern === wildcard))
    if (victims.length === 0) {
      toast(`No scope rules matched ${host}`)
      return
    }
    await Promise.all(victims.map((r) => api.deleteScopeRule(r.id)))
    toast(`Removed ${victims.length} scope rule${victims.length === 1 ? '' : 's'} for ${host}`)
  } catch {
    toast('Failed to remove scope rules', 'error')
  }
}

// getHostMenuItems builds the host actions for a context menu. When opts.url is given, the
// scope submenu also offers the request's exact URL (host + path); noise has no path field,
// so its submenu never does.
export function getHostMenuItems(host: string, opts?: { url?: string }): MenuItem[] {
  const wildcard = `*.${hostnameOnly(host)}`

  const scopeChildren: MenuItem[] = [
    { label: 'This host', onClick: () => void addScope(host, '', host) },
    { label: 'All subdomains', onClick: () => void addScope(wildcard, '', wildcard) },
  ]
  if (opts?.url) {
    try {
      const path = new URL(opts.url).pathname
      scopeChildren.push({
        label: 'Exact URL',
        onClick: () => void addScope(host, path, `${host}${path}`),
      })
    } catch {
      // Unparseable URL: skip the path-scoped option.
    }
  }

  return [
    { label: 'Add host to scope', children: scopeChildren },
    {
      label: 'Add host to noise filter',
      children: [
        { label: 'This host', onClick: () => void addNoise(host, host) },
        { label: 'All subdomains', onClick: () => void addNoise(wildcard, wildcard) },
      ],
    },
    { label: 'Remove host from scope', onClick: () => void removeHostFromScope(host) },
  ]
}
