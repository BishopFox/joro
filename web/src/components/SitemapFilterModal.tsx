import { CONTENT_TYPE_OPTIONS } from '../lib/contentTypes'
import { HTTP_METHOD_OPTIONS } from '../lib/requestFilters'
import MultiSelectDropdown from './MultiSelectDropdown'
import StatusFilter from './StatusFilter'

// SitemapFilter mirrors the subset of the backend RequestFilter that the site
// map exposes. `content`/`contentRegex` back the inline search box on the map;
// the rest are edited in this modal. methods/statusClasses/statusCodes match the
// field names in requestStore's RequestFilter so the shared filter controls work
// against both.
export interface SitemapFilter {
  host: string
  methods: string[]
  statusClasses: string[]
  statusCodes: string
  contentTypes: string[]
  scopeOnly: boolean
  contentMode: '' | 'include' | 'exclude'
  content: string
  contentRegex: boolean
}

export const emptySitemapFilter: SitemapFilter = {
  host: '',
  methods: [],
  statusClasses: [],
  statusCodes: '',
  contentTypes: [],
  scopeOnly: false,
  contentMode: '',
  content: '',
  contentRegex: false,
}

// hasModalFilters reports whether any of the modal-managed fields are set (used
// to show the "active" dot on the filter icon). The inline search box is tracked
// separately.
export function hasModalFilters(f: SitemapFilter): boolean {
  return (
    f.host !== '' ||
    f.methods.length > 0 ||
    f.statusClasses.length > 0 ||
    f.statusCodes !== '' ||
    f.contentTypes.length > 0 ||
    f.scopeOnly ||
    f.contentMode !== ''
  )
}

type Props = {
  filter: SitemapFilter
  onChange: (patch: Partial<SitemapFilter>) => void
  onClose: () => void
  onClear: () => void
}

export default function SitemapFilterModal({ filter, onChange, onClose, onClear }: Props) {
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-surface-card border border-border rounded p-4 w-[32rem] space-y-3" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center">
          <h3 className="text-sm font-semibold text-content-primary">Filter site map</h3>
          <button
            onClick={onClear}
            className="ml-auto px-2 py-1 rounded-sm text-xs text-content-secondary hover:text-content-primary hover:bg-surface-input"
          >
            Clear filters
          </button>
        </div>

        {/* Primary filters */}
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-1.5">
            <span className="text-xs text-content-muted">Host</span>
            <input
              className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-32"
              placeholder="substring"
              value={filter.host}
              onChange={(e) => onChange({ host: e.target.value })}
            />
          </label>
          <MultiSelectDropdown
            label="Method"
            options={HTTP_METHOD_OPTIONS}
            selected={filter.methods}
            onChange={(methods) => onChange({ methods })}
            tooltip="Filter by HTTP method — select any number"
          />
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <StatusFilter
            classes={filter.statusClasses}
            codes={filter.statusCodes}
            onChange={onChange}
          />
        </div>

        {/* Response type */}
        <div className="border-t border-border-subtle pt-3 space-y-2">
          <span className="text-xs text-content-muted">Response Type</span>
          <div className="flex flex-wrap items-center gap-2">
            {CONTENT_TYPE_OPTIONS.map((opt) => (
              <label key={opt.key} className="flex items-center gap-1 cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={filter.contentTypes.includes(opt.key)}
                  onChange={(e) => {
                    const next = e.target.checked
                      ? [...filter.contentTypes, opt.key]
                      : filter.contentTypes.filter((k) => k !== opt.key)
                    onChange({ contentTypes: next })
                  }}
                />
                <span className="text-xs text-content-secondary">{opt.label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Content search mode + scope */}
        <div className="border-t border-border-subtle pt-3 flex flex-wrap items-center gap-3">
          <span className="text-xs text-content-muted shrink-0">Search mode</span>
          <label className="flex items-center gap-1 cursor-pointer">
            <input
              type="checkbox"
              className="accent-accent"
              checked={filter.contentMode === 'exclude'}
              onChange={(e) => onChange({ contentMode: e.target.checked ? 'exclude' : '' })}
            />
            <span className="text-xs text-content-secondary">Exclude matches</span>
          </label>
          <div className="w-px h-5 bg-border mx-1 shrink-0" />
          <label className="flex items-center gap-1 cursor-pointer">
            <input
              type="checkbox"
              className="accent-accent"
              checked={filter.scopeOnly}
              onChange={(e) => onChange({ scopeOnly: e.target.checked })}
            />
            <span className="text-xs text-content-secondary">In Scope</span>
          </label>
        </div>
        <p className="text-[10px] text-content-muted">
          The search box matches a string or regex against the raw request and response bytes.
          Exclude flips it to hide matching endpoints. Endpoints that only ever returned 404 are always hidden.
        </p>

        <div className="flex justify-end gap-2 pt-1">
          <button onClick={onClose} className="px-3 py-1.5 rounded-sm text-xs bg-accent-secondary hover:bg-accent-secondary-hover text-black font-semibold">Done</button>
        </div>
      </div>
    </div>
  )
}
