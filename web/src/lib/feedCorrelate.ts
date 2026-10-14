import type { HostTech, Tech } from './api'
import type { FeedItem } from './feedTypes'

// Correlate the technologies Joro fingerprinted on in-scope hosts against the CVE/KEV feeds,
// so the dashboard can answer "which of my targets run something under active exploitation?".
//
// The precise join is CPE vendor:product — present on the security-relevant subset of the
// fingerprint DB (nginx, apache, wordpress, …) and already how Joro derives a feed item's
// vendor/product. For a technology with no CPE we fall back to a conservative single-token
// name match (length-guarded, product-only) so "WordPress"/"nginx"/"jQuery" still match while
// a generic vendor like "apache" cannot drag in every Apache product. Matches carry a
// confidence so the UI can label a fallback as "possible".

export interface ExposureMatch {
  host: string
  tech: Tech
  item: FeedItem
  confidence: 'exact' | 'possible'
}

// normToken lowercases and strips every non-alphanumeric rune, so "http_server",
// "HTTP Server" and "http-server" all compare equal.
function normToken(s?: string): string {
  return (s ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '')
}

// cpeVendorProduct parses a CPE 2.3 string into normalized vendor/product, or null.
function cpeVendorProduct(cpe?: string): { vendor: string; product: string } | null {
  if (!cpe) return null
  const parts = cpe.split(':')
  if (parts.length < 6 || parts[0] !== 'cpe' || parts[1] !== '2.3') return null
  const clean = (f: string) => (f === '*' || f === '-' ? '' : f)
  const product = normToken(clean(parts[4]))
  if (!product) return null
  return { vendor: normToken(clean(parts[3])), product }
}

export function correlateExposure(hosts: HostTech[], items: FeedItem[]): ExposureMatch[] {
  // Index feed items by normalized product.
  const byProduct = new Map<string, FeedItem[]>()
  for (const it of items) {
    const p = normToken(it.product)
    if (!p) continue
    const arr = byProduct.get(p)
    if (arr) arr.push(it)
    else byProduct.set(p, [it])
  }

  const matches: ExposureMatch[] = []
  const seen = new Set<string>()
  const add = (host: string, tech: Tech, item: FeedItem, confidence: 'exact' | 'possible') => {
    const key = `${host}|${tech.name}|${item.id}`
    if (seen.has(key)) return
    seen.add(key)
    matches.push({ host, tech, item, confidence })
  }

  for (const host of hosts) {
    for (const tech of host.technologies) {
      const cpe = cpeVendorProduct(tech.cpe)
      if (cpe) {
        for (const it of byProduct.get(cpe.product) ?? []) {
          const itVendor = normToken(it.vendor)
          const vendorOk = !cpe.vendor || !itVendor || itVendor === cpe.vendor
          add(host.host, tech, it, vendorOk ? 'exact' : 'possible')
        }
      } else {
        // No CPE: a single-token name match on the product only, length-guarded.
        const name = normToken(tech.name)
        if (name.length >= 4) {
          for (const it of byProduct.get(name) ?? []) {
            add(host.host, tech, it, 'possible')
          }
        }
      }
    }
  }

  // Exact first, then by CVSS, then EPSS — the operator's prioritization order.
  matches.sort((a, b) => {
    if (a.confidence !== b.confidence) return a.confidence === 'exact' ? -1 : 1
    const sa = a.item.score ?? 0
    const sb = b.item.score ?? 0
    if (sb !== sa) return sb - sa
    return (b.item.epss ?? 0) - (a.item.epss ?? 0)
  })
  return matches
}
