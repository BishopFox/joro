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

// hostMatchesGlob is a best-effort mirror of filepath.Match for host patterns (which carry no
// path separator): * matches any run of characters, ? matches one. Advisory only — it drives a
// warning, never a scope decision, so an exotic char-class pattern merely skips the warning.
function hostMatchesGlob(pattern: string, host: string): boolean {
  let re = ''
  for (const c of pattern) {
    if (c === '*') re += '.*'
    else if (c === '?') re += '.'
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  try {
    return new RegExp(`^${re}$`).test(host)
  } catch {
    return false
  }
}

// excludeScope adds an exclude rule (include:false) for a scope target, but only if an identical
// one does not already exist. It warns when the rule would currently have no effect: excludes
// only subtract from an included host, so with scope off, or with no include rule matching this
// host, there is nothing in scope for it to remove.
async function excludeScope(pattern: string, path: string, label: string, host: string) {
  try {
    const { enabled, rules } = await api.getScope()
    const exists = rules.some(
      (r) => !r.include && r.pattern === pattern.toLowerCase() && r.path === path,
    )
    if (exists) {
      toast(`${label} is already excluded from scope`)
      return
    }
    await api.addScopeRule({ pattern, methods: [], path, include: false })
    const h = host.toLowerCase()
    if (!enabled) {
      toast(`Excluded ${label} — scope filtering is off`)
    } else if (!rules.some((r) => r.include && hostMatchesGlob(r.pattern, h))) {
      toast(`Excluded ${label} — no in-scope rule matches ${host}, so this has no effect`, 'error')
    } else {
      toast(`Excluded ${label} from scope`)
    }
  } catch {
    toast('Failed to add exclude rule', 'error')
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

// scopeTargets lists the scope targets for a host: the exact host, the subdomain wildcard, and
// (when a URL is available) the request's exact path. Shared by the scope-add and scope-exclude
// submenus so the two never drift.
function scopeTargets(host: string, opts?: { url?: string }) {
  const wildcard = `*.${hostnameOnly(host)}`
  const targets = [
    { label: 'This host', pattern: host, path: '', display: host },
    { label: 'All subdomains', pattern: wildcard, path: '', display: wildcard },
  ]
  if (opts?.url) {
    try {
      const path = new URL(opts.url).pathname
      targets.push({ label: 'Exact URL', pattern: host, path, display: `${host}${path}` })
    } catch {
      // Unparseable URL: skip the path-scoped option.
    }
  }
  return targets
}

// getHostMenuItems builds the host actions for a context menu. When opts.url is given, the
// scope submenus also offer the request's exact URL (host + path); noise has no path field,
// so its submenu never does.
export function getHostMenuItems(host: string, opts?: { url?: string }): MenuItem[] {
  const wildcard = `*.${hostnameOnly(host)}`
  const targets = scopeTargets(host, opts)

  const scopeChildren: MenuItem[] = targets.map((t) => ({
    label: t.label,
    onClick: () => void addScope(t.pattern, t.path, t.display),
  }))
  const excludeChildren: MenuItem[] = targets.map((t) => ({
    label: t.label,
    onClick: () => void excludeScope(t.pattern, t.path, t.display, host),
  }))

  return [
    { label: 'Add host to scope', children: scopeChildren },
    {
      label: 'Add host to noise filter',
      children: [
        { label: 'This host', onClick: () => void addNoise(host, host) },
        { label: 'All subdomains', onClick: () => void addNoise(wildcard, wildcard) },
      ],
    },
    { label: 'Exclude from scope', children: excludeChildren },
    { label: 'Remove host from scope', onClick: () => void removeHostFromScope(host) },
  ]
}
