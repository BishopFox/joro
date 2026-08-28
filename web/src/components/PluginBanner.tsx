import { useState } from 'react'
import { Link } from 'react-router'
import { AlertTriangle } from 'lucide-react'
import type { PluginInfo } from '../lib/api'

// PluginBanner reports plugins that did not load. The plugin list is owned by
// App (which needs it for the tab nav anyway), so this takes the failed rows as
// a prop rather than fetching a third copy of it.
//
// One banner, never one per plugin: a host binary that has moved past the
// toolchain its plugins were built against fails all of them at once, and the
// operator's next step is the same page either way. Only the single-failure case
// is worth naming a file for; past that the count is the useful part and the
// Settings table has the rest.
export default function PluginBanner({ failed }: { failed: PluginInfo[] }) {
  const [dismissed, setDismissed] = useState(false)

  if (failed.length === 0 || dismissed) return null

  const only = failed.length === 1 ? failed[0] : null

  return (
    <div className="flex items-center justify-between px-3 py-1.5 bg-surface-input border-b border-border text-xs text-content-secondary">
      <span className="flex items-center gap-1.5 min-w-0">
        <AlertTriangle size={12} className="text-semantic-warning shrink-0" />
        <span className="truncate">
          {only ? (
            <>
              Plugin <code className="text-semantic-warning">{only.filename}</code> failed to load
              {only.error ? `: ${only.error}` : '.'}
            </>
          ) : (
            <>{failed.length} plugins failed to load.</>
          )}
        </span>
      </span>
      <div className="flex items-center gap-2 ml-4 shrink-0">
        <Link
          to="/settings"
          className="text-accent-secondary hover:text-accent-secondary-hover underline"
        >
          Open plugin settings
        </Link>
        <button
          onClick={() => setDismissed(true)}
          className="text-content-muted hover:text-content-primary text-xs"
        >
          Dismiss
        </button>
      </div>
    </div>
  )
}
