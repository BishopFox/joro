// Package feeds aggregates curated external threat-intelligence sources (high-severity
// CVEs, the CISA KEV catalog, and reputable security advisory headlines) into a single
// normalized, in-memory snapshot the dashboard renders.
//
// It is a leaf package: it imports only the standard library and internal/atomicfile. The
// HTTP client is injected as a FetchFunc, the same way internal/webhook receives its client
// factory, so this package never reaches internal/proxy and stays supply-chain clean.
//
// Feed bytes are untrusted and are data, never instructions. Two guarantees keep that true:
//   - normalize.go is the firewall every value crosses before it reaches the snapshot: it
//     emerges a bounded, validated scalar (see that file's doc comment). This stops
//     browser-side content injection — the UI's origin is fully privileged.
//   - Nothing read off the wire reaches a code-execution sink. This package must never import
//     os/exec, text/template, html/template, database/sql, internal/localcmd, or
//     internal/jsruntime; no feed-derived string is ever a format argument; the one
//     feed-derived outbound URL (EPSS) is built from already-validated CVE ids; and only the
//     operator's settings — never feed content — are written to disk. That is what makes feed
//     ingestion safe against server-side command/template/SQL injection.
package feeds

import "time"

// Category groups items by what they are, which is also how the dashboard lays them out.
type Category string

const (
	CategoryCVE      Category = "cve"      // high-severity CVEs (the ticker)
	CategoryKEV      Category = "kev"      // CISA Known Exploited Vulnerabilities
	CategoryHeadline Category = "headline" // curated advisory/news headlines
)

// allCategories is the full set, in display order. Snapshot always carries every key.
var allCategories = []Category{CategoryCVE, CategoryKEV, CategoryHeadline}

// Item is one normalized feed entry. Every field is a bounded scalar that has passed
// normalize.go: strings are length-capped plain UTF-8 with no control/BiDi/zero-width
// runes, Severity is an enum, Score is in [0,10], and URL is an https link on a known host
// (or empty). No []byte, json.RawMessage, or interface value ever reaches this struct, so
// the frontend can render every field as an auto-escaped React text node.
type Item struct {
	Category   Category  `json:"category"`
	ID         string    `json:"id"`                   // CVE id, or a derived hash for a headline
	Title      string    `json:"title"`                // short, plain text
	Summary    string    `json:"summary,omitempty"`    // plain text; never a feed's HTML body
	Vendor     string    `json:"vendor,omitempty"`     // "" means unknown
	Product    string    `json:"product,omitempty"`    //
	Severity   string    `json:"severity,omitempty"`   // "HIGH" | "CRITICAL" only
	Score      float64   `json:"score,omitempty"`      // CVSS base score, [0,10]
	EPSS       float64   `json:"epss,omitempty"`       // EPSS probability of exploitation, [0,1]
	Ransomware bool      `json:"ransomware,omitempty"` // KEV: known ransomware-campaign use
	AlsoInKEV  bool      `json:"alsoInKEV,omitempty"`  // a CVE that also appears in the KEV catalog
	URL        string    `json:"url,omitempty"`        // validated https, or "" (render as text)
	Source     string    `json:"source"`               // the registry's display name, never feed bytes
	Published  time.Time `json:"published"`
}

// SourceStatus reports how one source's last fetch went, so the UI can show "stale since X"
// rather than silently presenting old data as current.
type SourceStatus struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    Category  `json:"category"`
	LastAttempt time.Time `json:"lastAttempt"`
	LastSuccess time.Time `json:"lastSuccess"`
	LastError   string    `json:"lastError,omitempty"` // sanitized, capped
	ItemCount   int       `json:"itemCount"`
	Stale       bool      `json:"stale"` // last attempt failed since the last success
}

// Snapshot is the whole aggregated state the API returns and the UI renders. Items always
// carries all three category keys (possibly empty arrays) so the client never indexes nil.
type Snapshot struct {
	Items       map[Category][]Item `json:"items"`
	Sources     []SourceStatus      `json:"sources"`
	GeneratedAt time.Time           `json:"generatedAt"`
}
