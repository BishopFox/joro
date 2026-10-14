// Small shared badges for the feed widgets.

// EpssBadge shows the EPSS probability of exploitation as a percentage, tinted when high.
// Renders nothing when there is no score.
export function EpssBadge({ epss }: { epss?: number }) {
  if (epss == null || epss <= 0) return null
  const pct = Math.round(epss * 100)
  const tint = epss >= 0.5 ? 'text-semantic-warning' : 'text-content-muted'
  return (
    <span
      title={`EPSS: ${pct}% probability of exploitation in the next 30 days`}
      className={`text-[9px] font-semibold uppercase tracking-wide ${tint}`}
    >
      EPSS {pct}%
    </span>
  )
}
