package feeds

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// normalize.go is the injection firewall.
//
// Feed bytes are untrusted and the UI origin is fully privileged, so nothing reaches an Item
// except through one of these functions. The contract each enforces:
//
//   - sanitizeText: bounded plain UTF-8, whitespace collapsed, every control / BiDi-override
//     / zero-width / non-printable rune dropped. This is what lets the frontend render a value
//     as a text node without escaping surprises — a hostile "<img onerror=…>" lands as literal
//     text, and a "‮" right-to-left override cannot reorder a line.
//   - cleanCVEID: a CVE id or nothing. Everything CVE-derived is gated on it, and a canonical
//     URL is *built* from the cleaned id rather than trusted from the feed.
//   - validateURL: https on an allow-listed host, or "" (meaning "render as text, no link").
//     Used only for headline links, where no canonical URL can be derived.
//   - the enum/clamp helpers: Severity is HIGH|CRITICAL or "", Score is clamped to [0,10],
//     a future Published is clamped to now.
const (
	maxID      = 64
	maxTitle   = 300
	maxSummary = 1000
	maxVendor  = 128
	maxProduct = 128
	maxSource  = 64
	maxURL     = 512
	maxError   = 256
)

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// sanitizeText scrubs and bounds a string decoded by encoding/json or encoding/xml.
//
// Whitespace (any Unicode space, including tab/newline/NBSP) collapses to a single ASCII
// space; every other non-printable rune — C0/C1 controls, zero-width marks, BiDi overrides,
// invalid UTF-8 — is dropped. The result is trimmed and truncated on a rune boundary.
func sanitizeText(s string, max int) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			continue // invalid byte sequence
		case unicode.IsSpace(r):
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		case !unicode.IsPrint(r):
			continue // controls, zero-width, BiDi overrides (all category C)
		default:
			b.WriteRune(r)
			lastSpace = false
		}
	}
	return truncateRunes(strings.TrimSpace(b.String()), max)
}

// truncateRunes caps a string to max runes, appending an ellipsis when it cuts.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max == 1 {
		return "…"
	}
	return strings.TrimSpace(string(runes[:max-1])) + "…"
}

// cleanCVEID returns the canonical upper-cased CVE id, or ("", false) for anything that is
// not one. The gate for every CVE- and KEV-derived value.
func cleanCVEID(s string) (string, bool) {
	id := strings.ToUpper(strings.TrimSpace(s))
	if len(id) > maxID || !cveIDPattern.MatchString(id) {
		return "", false
	}
	return id, true
}

// nvdCanonicalURL builds the authoritative detail URL from an already-cleaned CVE id. The
// feed's own link/reference fields are never used for CVE or KEV items, so a feed cannot
// smuggle a hostile URL in through them.
func nvdCanonicalURL(id string) string {
	return "https://nvd.nist.gov/vuln/detail/" + id
}

// validateURL accepts an https link whose host is on allow, stripped to scheme+host+path.
// Anything else — a non-https scheme (javascript:, data:, http:), userinfo, a non-443 port,
// an off-list host, an unparseable or over-long value — returns ("", false), which callers
// treat as "no link, render the title as plain text".
func validateURL(raw string, allow []string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxURL {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(u.Scheme, "https") || u.User != nil {
		return "", false
	}
	if p := u.Port(); p != "" && p != "443" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || !hostAllowed(host, allow) {
		return "", false
	}
	clean := url.URL{Scheme: "https", Host: host, Path: u.EscapedPath()}
	out := clean.String()
	if len(out) > maxURL {
		return "", false
	}
	return out, true
}

// hostAllowed reports whether host equals or is a subdomain of an allow-list entry.
func hostAllowed(host string, allow []string) bool {
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// headlineID derives a stable id for a headline from its source and link, so the same
// article dedups across refreshes without trusting any id the feed supplies.
func headlineID(source, link string) string {
	sum := sha256.Sum256([]byte(source + "|" + link))
	return hex.EncodeToString(sum[:])[:32]
}

// cleanSeverity passes only the two buckets at or above our floor; everything else is "".
func cleanSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "HIGH":
		return "HIGH"
	case "CRITICAL":
		return "CRITICAL"
	default:
		return ""
	}
}

// deriveSeverity buckets a score when a feed gives none (e.g. CVSS v2). Returns "" below the
// HIGH floor, which the score filter rejects anyway.
func deriveSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	default:
		return ""
	}
}

// clampScore bounds a CVSS score into the valid range.
func clampScore(s float64) float64 {
	switch {
	case s < 0:
		return 0
	case s > 10:
		return 10
	default:
		return s
	}
}

// normalizeTime returns t in UTC, clamping a future timestamp to now so one mis-stamped item
// cannot dominate a newest-first sort.
func normalizeTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	now := time.Now().UTC()
	if t.After(now) {
		return now
	}
	return t.UTC()
}

func parseNVDTime(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func parseKEVDate(s string) time.Time {
	if t, err := time.Parse("2006-01-02", strings.TrimSpace(s)); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func parseFeedTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{
		time.RFC1123Z, time.RFC1123, time.RFC3339Nano, time.RFC3339, time.RFC822Z, time.RFC822,
		// Weekday + two-digit year variants (CISA's all.xml uses "Tue, 13 Oct 26 12:00:00 +0000").
		"Mon, 02 Jan 06 15:04:05 -0700",
		"Mon, 02 Jan 06 15:04:05 MST",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
