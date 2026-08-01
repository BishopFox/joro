// timeAgo renders an ISO timestamp as a coarse relative age.
export function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime()
  // Clamp negatives: timestamps come from the team server, so clock skew
  // between machines can put a fresh createdAt slightly ahead of our clock.
  const secs = Math.max(0, Math.floor(diff / 1000))
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}
