import type { SignatureCatalogItem } from '../lib/api'
import { severityBadge } from '../lib/severity'

// field renders a labelled read-only row, skipping empty values. Shared shape with
// DetectRuleModal's RuleReference so active detail reads like passive detail.
export function field(label: string, value?: string | string[], mono = false) {
  if (!value || (Array.isArray(value) && value.length === 0)) return null
  const text = Array.isArray(value) ? value.join('\n') : value
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-content-muted">{label}</div>
      <div className={`text-xs text-content-secondary whitespace-pre-wrap break-words ${mono ? 'font-mono' : ''}`}>
        {text}
      </div>
    </div>
  )
}

// monoLabels are the detail fields rendered monospaced — raw bytes, ids, payloads.
const monoLabels = new Set(['Request', 'Nuclei ID', 'Source', 'Payloads'])

// SignatureDetail is the read-only detail for one catalog item — a template signature
// or an injection check — shown when a row is clicked. It renders the common fields
// plus the item's free-form detail list, so it serves every catalog rule. The active
// counterpart to DetectRuleModal's RuleReference.
export default function SignatureDetail({ sig }: { sig: SignatureCatalogItem }) {
  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-2">
        {severityBadge(sig.severity)}
        {!sig.enabled && (
          <span className="text-[10px] px-1.5 py-0.5 rounded-sm bg-surface-input text-content-muted">disabled</span>
        )}
      </div>
      <div className="text-sm font-semibold text-content-primary">{sig.name}</div>
      {field('Description', sig.description)}
      {field('Remediation', sig.remediation)}
      {(sig.detail ?? []).map((d) => (
        <div key={d.label}>{field(d.label, d.value, monoLabels.has(d.label))}</div>
      ))}
    </div>
  )
}
