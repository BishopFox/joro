// Package detect implements passive vulnerability detection over HTTP traffic
// already captured by the proxy. It reads proxy.CapturedRequest records and
// reports findings; it never sends requests of its own.
//
// Two kinds of check run against each captured message:
//
//   - Regex rules (KindRegex), from rules_builtin.go or created by the operator:
//     a pattern plus gates (content type, status, scheme) and named post-filters
//     that validate the captured group in Go.
//   - Analyzers (KindAnalyzer), Go functions in analyzers.go, for absence and
//     relational logic a regex cannot express — a missing header, a cookie flag
//     matrix, an Access-Control-Allow-Origin that echoes the request.
//
// Both converge on Engine.newFinding, the only code path that produces a Finding.
//
// Patterns compile with Go's regexp (RE2): no lookahead, no lookbehind, no
// backreferences. PostFilters is the escape hatch for negative conditions.
package detect

import (
	"regexp"
	"time"
)

// Severity ranks how much a finding matters. The rubric for assigning it to a
// new rule:
//
//   - Info:     not directly exploitable, and discloses nothing beyond a surface
//     or an identity — exposed panels, missing headers, software and
//     version fingerprints, analytics keys, identifiers that are not
//     credentials.
//   - Low:      a real if minor weakness, or disclosure of something more than an
//     identity — an exposed configuration file, a verbose error or debug
//     page, a directory listing, a disclosed filesystem path, a CORS or
//     redirect misconfiguration.
//   - Medium:   anything not covered by the other bands.
//   - High:     account credentials, sensitive API keys, database connection
//     strings, low-level PII (phone number, date of birth).
//   - Critical: high-grade PII (a national identity number or equivalent, or a
//     payment card), or anything that alone leads to severe
//     compromise — remote code execution, authentication bypass, a
//     served database dump.
//
// Every credential is High; none is Critical. A rule that detects a surface
// (an admin console, an absent header) is Info.
//
// The Info/Low line runs through what the match itself gives away, which matters
// most for error pages: one that leaks source paths, stack frames, or settings is
// Low, while one that only names the framework or an exception class is Info.
//
// Severity is orthogonal to Confidence: a low-confidence match on a national ID
// is still Critical, a certain match on a Server header is still Info.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// severityRank orders severities for sorting and for MinSeverity filtering.
var severityRank = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
}

// Rank returns the sort weight of a severity (Critical highest, 0 if unknown).
func (s Severity) Rank() int { return severityRank[s] }

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// Severities lists every severity, most serious first. Exported so a consumer offering
// them as a choice — the trigger editor's condition dropdown — reads them from here rather
// than restating a list that would drift the moment one is added.
var Severities = []Severity{
	SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo,
}

// Confidence describes whether a match is what the rule claims it is,
// independent of Severity.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Valid reports whether c is a known confidence level.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	}
	return false
}

// Confidences lists every confidence, most certain first. See Severities.
var Confidences = []Confidence{ConfidenceHigh, ConfidenceMedium, ConfidenceLow}

// Category groups rules for filtering and for the Rules UI.
type Category string

const (
	CategorySecrets     Category = "secrets"
	CategoryPII         Category = "pii"
	CategoryCredentials Category = "credentials"
	CategoryAccess      Category = "access"
	CategoryDisclosure  Category = "disclosure"
	CategoryHeaders     Category = "headers"
	CategoryCookies     Category = "cookies"
)

// Categories lists every category. See Severities.
var Categories = []Category{
	CategorySecrets, CategoryPII, CategoryCredentials, CategoryAccess,
	CategoryDisclosure, CategoryHeaders, CategoryCookies,
}

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	switch c {
	case CategorySecrets, CategoryPII, CategoryCredentials, CategoryAccess,
		CategoryDisclosure, CategoryHeaders, CategoryCookies:
		return true
	}
	return false
}

// AllCategories lists every category in display order.
func AllCategories() []Category {
	return []Category{
		CategorySecrets, CategoryCredentials, CategoryPII, CategoryAccess,
		CategoryDisclosure, CategoryHeaders, CategoryCookies,
	}
}

// RuleKind distinguishes a declarative pattern from a Go analyzer function.
// Operators may only create KindRegex rules; KindAnalyzer rules are built in,
// because their behavior lives in code rather than in the rule record.
type RuleKind string

const (
	KindRegex    RuleKind = "regex"
	KindAnalyzer RuleKind = "analyzer"
)

// Target names the part of the message a rule is matched against.
type Target string

const (
	TargetResponseBody   Target = "response_body"
	TargetResponseHeader Target = "response_header"
	TargetRequestBody    Target = "request_body"
	TargetRequestHeader  Target = "request_header"
	TargetURL            Target = "url"
	// TargetMessage is used by analyzers, which receive the whole *Message and
	// decide for themselves what to inspect.
	TargetMessage Target = "message"
)

// Valid reports whether t is a known target.
func (t Target) Valid() bool {
	switch t {
	case TargetResponseBody, TargetResponseHeader, TargetRequestBody,
		TargetRequestHeader, TargetURL, TargetMessage:
		return true
	}
	return false
}

// GroupBy selects how repeated matches collapse into a single finding.
type GroupBy string

const (
	// GroupByEvidence: one finding per distinct matched value on a host. Used by
	// secrets and PII rules.
	GroupByEvidence GroupBy = "evidence"
	// GroupByURL: one finding per path on a host. Used by panels, directory
	// listings, and interesting files.
	GroupByURL GroupBy = "url"
	// GroupByHost: one finding per host. Used by header, cookie, and
	// fingerprint rules.
	GroupByHost GroupBy = "host"
)

// Valid reports whether g is a known grouping mode.
func (g GroupBy) Valid() bool {
	switch g {
	case GroupByEvidence, GroupByURL, GroupByHost:
		return true
	}
	return false
}

// defaultMaxPerResponse caps findings from one rule against one message; the
// remaining matches raise the occurrence count instead.
const defaultMaxPerResponse = 3

// maxEvidenceBytes caps both Evidence and RawEvidence. A size bound only —
// RawEvidence holds the unmasked value.
const maxEvidenceBytes = 256

// Rule is a single detection check. Built-in rules use stable string IDs, which
// operator toggles, severity overrides, and Finding.RuleID reference across
// restarts and project reloads; user rules get a generated ID.
type Rule struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Remediation string     `json:"remediation,omitempty"`
	Kind        RuleKind   `json:"kind"`
	Category    Category   `json:"category"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Target      Target     `json:"target"`

	// Pattern is the RE2 source for KindRegex rules.
	Pattern string `json:"pattern,omitempty"`
	// Literal is a case-insensitive substring prescreen: when set, the regex only
	// runs if the haystack contains it. Must appear in every string the pattern
	// can match, or the rule silently never fires.
	Literal string `json:"literal,omitempty"`
	// Literals is an any-of prescreen for alternation rules: when set, the regex
	// only runs if the haystack contains at least one of these case-insensitive
	// substrings. Every branch of the pattern must be covered by one of them, or
	// matches from an uncovered branch are silently missed. Used by the WAF
	// fingerprint rules, whose broad alternations have no single common Literal.
	// Literal and Literals are independent; a rule with both must satisfy both.
	Literals []string `json:"literals,omitempty"`
	// CaptureGroup selects which submatch becomes the evidence (0 = whole match).
	CaptureGroup int `json:"captureGroup,omitempty"`
	// PostFilters name validators in the postfilters.go registry, run in order
	// against the captured group.
	PostFilters []string `json:"postFilters,omitempty"`
	// Analyzer names a function in the analyzers.go registry (KindAnalyzer only).
	Analyzer string `json:"analyzer,omitempty"`

	// GroupBy selects the dedupe collapse mode. Empty means GroupByEvidence.
	GroupBy GroupBy `json:"groupBy,omitempty"`

	// ContentTypes gates body rules to simplified content-type keywords
	// ("json", "html", "xml", "csv", "plain", "js", "css"). Empty means any
	// scannable body.
	ContentTypes []string `json:"contentTypes,omitempty"`
	// ExcludeContentTypes is the inverse of ContentTypes and takes precedence
	// over it: the rule never runs against these keywords. Rules that look for
	// data rather than a format use this instead of ContentTypes.
	ExcludeContentTypes []string `json:"excludeContentTypes,omitempty"`
	// StatusCodes gates the rule with a proxy status expression, e.g.
	// "200,301,302,401,403". Empty means any status.
	StatusCodes string `json:"statusCodes,omitempty"`
	// Scheme gates the rule to "http" or "https". Empty means either.
	Scheme string `json:"scheme,omitempty"`
	// MinLength rejects captured groups shorter than this.
	MinLength int `json:"minLength,omitempty"`
	// MinEntropy rejects captured groups below this Shannon entropy in bits per
	// character. 0 disables the check.
	MinEntropy float64 `json:"minEntropy,omitempty"`
	// MaxPerResponse caps findings per message (0 means defaultMaxPerResponse).
	MaxPerResponse int `json:"maxPerResponse,omitempty"`
	// RedactEvidence masks the middle of the captured value before storing it.
	RedactEvidence bool `json:"redactEvidence,omitempty"`

	Builtin bool `json:"builtin"`
	Enabled bool `json:"enabled"`

	// Resolved once by Engine.rebuildLocked; the scan path never compiles a regex
	// or looks up a registry.
	compiled      *regexp.Regexp
	status        func(int) bool
	filters       []postFilter
	literalLower  []byte
	literalsLower [][]byte
	ctSet         map[string]struct{}
	excludeCtSet  map[string]struct{}
}

// Occurrence records one sighting of a finding.
type Occurrence struct {
	RequestID  string    `json:"requestId"`
	Seq        int       `json:"seq"`
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	StatusCode int       `json:"statusCode"`
	Timestamp  time.Time `json:"timestamp"`
	// Offset is the byte offset of the match within the scanned part, used to
	// highlight the evidence in the response viewer.
	Offset int `json:"offset"`
	// Part names which buffer Offset indexes into, so the UI knows whether to
	// highlight in the request or the response.
	Part string `json:"part"`
}

// maxOccurrences caps the occurrence ring kept per finding in memory.
const maxOccurrences = 20

// maxOccSeen caps the occurrence-identity set. Past this bound Count is a
// monotonic floor rather than an exact tally.
const maxOccSeen = 512

// Finding is one deduplicated detection result.
//
// ID is a deterministic group hash:
//
//	hex(sha256(ruleID \x00 host \x00 groupDim))[:32]
//
// It carries no request ID, timestamp, or sequence number, so rescanning the
// same traffic reproduces byte-identical IDs. Rescan is therefore idempotent,
// live merges are a map upsert, and persisted findings reload without ID
// remapping.
type Finding struct {
	ID         string     `json:"id"`
	RuleID     string     `json:"ruleId"`
	RuleName   string     `json:"ruleName"`
	Category   Category   `json:"category"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Target     Target     `json:"target"`

	Host      string `json:"host"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	RequestID string `json:"requestId"`

	// Detail is a short human-readable qualifier, e.g. the cookie name for a
	// cookie rule or the matched product for a fingerprint rule.
	Detail string `json:"detail,omitempty"`
	// Evidence is the redacted, truncated, control-character-escaped snippet
	// rendered by every list and table.
	Evidence string `json:"evidence"`
	// RawEvidence is the unmasked matched value, stored verbatim and populated
	// only for rules that redact. Redaction is a display control; the operator
	// can reveal this per finding.
	RawEvidence    string `json:"rawEvidence,omitempty"`
	EvidenceOffset int    `json:"evidenceOffset"`
	EvidenceLength int    `json:"evidenceLength"`
	EvidencePart   string `json:"evidencePart,omitempty"`

	FirstSeen   time.Time    `json:"firstSeen"`
	LastSeen    time.Time    `json:"lastSeen"`
	Count       int          `json:"count"`
	Occurrences []Occurrence `json:"occurrences,omitempty"`

	FalsePositive bool   `json:"falsePositive"`
	Notes         string `json:"notes,omitempty"`
	// Truncated marks a finding produced from a body that hit a scan size cap:
	// the scan was not exhaustive for that response.
	Truncated bool `json:"truncated,omitempty"`
	// SeverityOverridden records that an operator changed Severity by hand. A
	// rescan leaves it alone.
	SeverityOverridden bool `json:"severityOverridden,omitempty"`

	// occSeen holds "requestID:part:offset" keys. Upsert increments Count only
	// for occurrences not already present, so a rescan does not double counts.
	occSeen map[string]struct{}
	// generation records the scan pass that last confirmed this finding, used by
	// an optional purge to drop findings no longer present.
	generation uint64
}

// Config holds the tunable engine settings that ride with a project.
type Config struct {
	// ScopeOnly limits scanning to in-scope requests. On by default.
	ScopeOnly bool `json:"scopeOnly"`
	// ScanRequests enables request-side targets (Basic auth, credentials in
	// query strings, keys posted by the app).
	ScanRequests bool `json:"scanRequests"`
	// PersistFindings snapshots findings into the project file, preserving
	// false-positive marks and notes. On by default.
	PersistFindings bool `json:"persistFindings"`
	// ClearFindingsWithHistory clears findings when request history is cleared.
	// Off by default.
	ClearFindingsWithHistory bool `json:"clearFindingsWithHistory"`

	MaxBodyScanBytes        int `json:"maxBodyScanBytes"`
	MaxRequestBodyScanBytes int `json:"maxRequestBodyScanBytes"`

	// SkipContentTypes and SkipExtensions are MIME prefixes and URL suffixes
	// never scanned. .js and .css are not in either list.
	SkipContentTypes []string `json:"skipContentTypes"`
	SkipExtensions   []string `json:"skipExtensions"`
	// ExcludeHosts suppresses findings whose host contains any of these
	// substrings.
	ExcludeHosts []string `json:"excludeHosts"`
}

// DefaultOHTTPContentTypes are the Oblivious HTTP media types never scanned.
// OHTTP bodies are HPKE-encrypted to a gateway key the proxy never holds, so
// they are opaque by design rather than a codec gap; skipping them by content
// type keeps them out of the skippedBinary "unreadable" count. Exported so the
// project-config backfill adds the same values these defaults ship.
var DefaultOHTTPContentTypes = []string{"message/ohttp-", "application/ohttp-keys"}

// DefaultConfig returns the shipped engine configuration.
func DefaultConfig() Config {
	return Config{
		ScopeOnly:                true,
		ScanRequests:             true,
		PersistFindings:          true,
		ClearFindingsWithHistory: false,
		MaxBodyScanBytes:         1 << 20,
		MaxRequestBodyScanBytes:  256 << 10,
		SkipContentTypes: append([]string{
			"image/", "font/", "video/", "audio/",
			"application/octet-stream", "application/pdf", "application/zip",
			"application/wasm", "application/x-7z", "application/x-rar",
		}, DefaultOHTTPContentTypes...),
		SkipExtensions: []string{
			".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico",
			".svg", ".woff", ".woff2", ".ttf", ".otf", ".eot",
			".mp4", ".webm", ".mp3", ".wav", ".ogg", ".avi", ".mov",
			".zip", ".gz", ".bz2", ".7z", ".rar", ".pdf", ".wasm",
		},
		ExcludeHosts: []string{},
	}
}

// normalize fills zero values with defaults, so a partially-populated config
// (an older project file, a partial PUT) is usable.
func (c *Config) normalize() {
	d := DefaultConfig()
	if c.MaxBodyScanBytes <= 0 {
		c.MaxBodyScanBytes = d.MaxBodyScanBytes
	}
	if c.MaxRequestBodyScanBytes <= 0 {
		c.MaxRequestBodyScanBytes = d.MaxRequestBodyScanBytes
	}
	if c.SkipContentTypes == nil {
		c.SkipContentTypes = d.SkipContentTypes
	}
	if c.SkipExtensions == nil {
		c.SkipExtensions = d.SkipExtensions
	}
	if c.ExcludeHosts == nil {
		c.ExcludeHosts = []string{}
	}
}

// Summary aggregates the findings store for the dashboard header and for the
// detect.summary WebSocket event.
type Summary struct {
	Total          int            `json:"total"`
	BySeverity     map[string]int `json:"bySeverity"`
	ByCategory     map[string]int `json:"byCategory"`
	FalsePositives int            `json:"falsePositives"`
	// HiddenByDisabledRule counts findings whose rule is currently switched off.
	// The findings table hides them by default.
	HiddenByDisabledRule int `json:"hiddenByDisabledRule"`
	SkippedEncoded       int `json:"skippedEncoded"`
	SkippedBinary        int `json:"skippedBinary"`
	Scanned              int `json:"scanned"`
}
