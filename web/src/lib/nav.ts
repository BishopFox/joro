export interface NavEntry {
  to: string
  label: string
  proxyOnly?: boolean
}

export const NAV: NavEntry[] = [
  { to: '/dashboard',  label: 'Dashboard' },
  { to: '/map',        label: 'Map',        proxyOnly: true },
  { to: '/history',    label: 'History',    proxyOnly: true },
  { to: '/intercept',  label: 'Intercept',  proxyOnly: true },
  { to: '/manipulate', label: 'Manipulate', proxyOnly: true },
  { to: '/fuzz',       label: 'Fuzz',       proxyOnly: true },
  { to: '/generator',  label: 'Generate',   proxyOnly: true },
  { to: '/executor',   label: 'Execute',    proxyOnly: true },
  { to: '/callbacks',  label: 'Interact' },
  { to: '/notes',      label: 'Notes' },
  { to: '/transform',  label: 'Transform',  proxyOnly: true },
  { to: '/plugins',    label: 'Plugins' },
  { to: '/settings',   label: 'Settings' },
]
