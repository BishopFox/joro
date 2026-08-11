package httptools

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/proxy"
)

// Search caps.
const (
	DefaultSearchContext = 60
	MaxSearchContext     = 200
	DefaultMatchesPerReq = 3
	DefaultMatchesSingle = 20
	DefaultTotalMatches  = 40
	DefaultSearchMaxReqs = 50
	MaxSearchMaxRequests = 200
)

// SearchArgs is the argument shape of http.search. The absence of Ref selects
// corpus mode; its presence selects single-response mode.
type SearchArgs struct {
	Pattern string `json:"pattern"`
	Regex   bool   `json:"regex"`
	Ref     int    `json:"ref"`
	Part    string `json:"part"` // req | resp | both

	// Corpus narrowing, mirroring history.list. These must stay in step with the
	// historyFilterProps schema fragment in internal/capreg, which both tools
	// share; a field advertised there but missing here would be rejected by the
	// handler's DisallowUnknownFields decoder for every client that follows the
	// documented contract. TestSchemasMatchArgStructs pins the pairing.
	Host        string `json:"host"`
	Method      string `json:"method"`
	Status      string `json:"status"`
	Search      string `json:"search"`
	ContentType string `json:"contentType"`
	Exclude     string `json:"exclude"`
	ExtMode     string `json:"extMode"`
	ScopeOnly   bool   `json:"scopeOnly"`

	MaxRequests   int  `json:"maxRequests"`
	MaxMatches    int  `json:"maxMatches"`
	Context       int  `json:"context"`
	CaseSensitive bool `json:"caseSensitive"`
	Deep          bool `json:"deep"`
}

// SearchDeps is what the search capability needs from the host.
type SearchDeps struct {
	Store *proxy.Store
	Scope *proxy.Scope

	// MaskCredentials masks sensitive header values before the pattern is applied,
	// so a match cannot be reported from inside a value the caller may not see. It
	// lives here rather than in SearchArgs because it is the host's decision.
	MaskCredentials bool
}

// SearchCorpus greps captured traffic and returns match offsets with context.
//
// Corpus mode is two stages, and stage one is free: the pattern goes into
// RequestFilter.Content, so the store's own matcher runs it over ReqRaw and
// RespRaw inside its read lock and never copies a non-matching body out. Stage two
// re-runs the pattern over the survivors, because the matcher only answers yes or
// no and this tool needs offsets.
//
// Two properties of that split are traps worth naming:
//
//  1. Stage two must be at least as permissive as stage one. The store's
//     non-regex path lowercases both sides, so stage one is case-insensitive; a
//     case-sensitive stage two would report zero matches for a request stage one
//     said matched, which is a silent dead end. So case-insensitivity is the
//     default and CaseSensitive narrows stage two only — narrowing is always safe.
//
//  2. The store matches raw bytes, so a gzipped response will not match a
//     plaintext pattern at stage one. Deep opts into decompressing the
//     filter-narrowed set instead, which is a real cost and therefore never
//     implicit.
func SearchCorpus(d SearchDeps, args SearchArgs) (string, error) {
	if strings.TrimSpace(args.Pattern) == "" {
		return "", fmt.Errorf("pattern is required")
	}
	ctxBytes := clampInt(args.Context, DefaultSearchContext, 1, MaxSearchContext)
	maxReqs := clampInt(args.MaxRequests, DefaultSearchMaxReqs, 1, MaxSearchMaxRequests)

	matcher, err := compileMatcher(args.Pattern, args.Regex, args.CaseSensitive)
	if err != nil {
		return "", err
	}

	if args.Ref > 0 {
		return searchSingle(d, args, matcher, ctxBytes)
	}

	f := proxy.RequestFilter{
		Host:        args.Host,
		Method:      args.Method,
		Status:      args.Status,
		Search:      args.Search,
		ContentType: args.ContentType,
		Exclude:     args.Exclude,
		ExtMode:     orDefault(args.ExtMode, "exclude"),
		Limit:       maxReqs,
	}
	// Stage 1. Deep mode skips the content prefilter deliberately: a compressed
	// body cannot match on raw bytes, so filtering on content there would exclude
	// exactly the requests deep mode exists to reach.
	if !args.Deep {
		f.Content = args.Pattern
		f.ContentRegex = args.Regex
		f.ContentMode = "include"
	}
	if args.ScopeOnly && d.Scope != nil {
		f.InScopeFunc = d.Scope.InScope
	}

	items, total := d.Store.List(f)

	perReq := clampInt(args.MaxMatches, DefaultMatchesPerReq, 1, DefaultTotalMatches)
	t := newTable("seq", "part", "off", "context")
	t.empty = "(no matches)"

	hits, scanned, withHits := 0, 0, 0
	var redacted []string
	for _, item := range items {
		scanned++
		before := hits
		for _, pw := range partsFor(args.Part) {
			raw := pw.pick(item)
			if len(raw) == 0 {
				continue
			}
			body, masked := searchable(raw, args.Deep, d.MaskCredentials)
			redacted = mergeNames(redacted, masked)
			for _, loc := range matcher.find(body, perReq-(hits-before)) {
				t.add(strconv.Itoa(item.Seq), pw.name, strconv.Itoa(loc),
					contextAround(body, loc, matcher.width(body, loc), ctxBytes))
				hits++
				if hits >= DefaultTotalMatches {
					break
				}
			}
			if hits >= DefaultTotalMatches {
				break
			}
		}
		if hits > before {
			withHits++
		}
		if hits >= DefaultTotalMatches {
			break
		}
	}

	mode := "corpus"
	if args.Deep {
		mode += " deep"
	}
	t.note(fmt.Sprintf("q=%q mode=%s hits=%d in %d/%d scanned (%d matched the filter)",
		args.Pattern, mode, hits, withHits, scanned, total))
	if hits >= DefaultTotalMatches {
		t.note(fmt.Sprintf("[capped at %d matches; narrow with host/status/contentType or raise specificity]", DefaultTotalMatches))
	}
	if !args.Deep {
		t.note("note: matched against raw captured bytes, so a compressed response will not match a plaintext pattern (use deep=true)")
	}
	if note := RedactionNote(redacted); note != "" {
		t.note(note)
	}
	return t.String(), nil
}

func searchSingle(d SearchDeps, args SearchArgs, m *matcher, ctxBytes int) (string, error) {
	item := d.Store.GetBySeq(args.Ref)
	if item == nil {
		return "", fmt.Errorf("no captured request with seq %d", args.Ref)
	}
	limit := clampInt(args.MaxMatches, DefaultMatchesSingle, 1, DefaultTotalMatches)

	t := newTable("part", "off", "context")
	t.empty = "(no matches)"
	hits := 0
	var redacted []string
	for _, pw := range partsFor(args.Part) {
		raw := pw.pick(item)
		if len(raw) == 0 {
			continue
		}
		body, masked := searchable(raw, args.Deep, d.MaskCredentials)
		redacted = mergeNames(redacted, masked)
		for _, loc := range m.find(body, limit-hits) {
			t.add(pw.name, strconv.Itoa(loc), contextAround(body, loc, m.width(body, loc), ctxBytes))
			hits++
		}
		if hits >= limit {
			break
		}
	}
	t.note(fmt.Sprintf("q=%q mode=single seq=%d hits=%d", args.Pattern, args.Ref, hits))
	if note := RedactionNote(redacted); note != "" {
		t.note(note)
	}
	return t.String(), nil
}

// searchable returns the bytes to grep. In deep mode a compressed body is
// replaced by its decompressed form, spliced back after the original header block
// so reported offsets still point into a document the client can ask to read.
// Those offsets are into the decoded document, not the wire bytes — which is why
// deep mode is opt-in rather than the default.
//
// Masking runs first and is length-preserving, so a pattern cannot match inside a
// withheld header value and offsets are unchanged either way.
func searchable(raw []byte, deep, mask bool) ([]byte, []string) {
	var names []string
	if mask {
		raw, names = MaskHeaders(raw)
	}
	if !deep {
		return raw, names
	}
	m := parseMessage(raw, true)
	if m.Decoded == "" {
		return raw, names
	}
	out := make([]byte, 0, len(m.HdrRaw)+4+len(m.Body))
	out = append(out, m.HdrRaw...)
	out = append(out, '\r', '\n', '\r', '\n')
	return append(out, m.Body...), names
}

type partPicker struct {
	name string
	pick func(*proxy.CapturedRequest) []byte
}

func partsFor(part string) []partPicker {
	req := partPicker{"req", func(c *proxy.CapturedRequest) []byte { return c.ReqRaw }}
	resp := partPicker{"resp", func(c *proxy.CapturedRequest) []byte { return c.RespRaw }}
	switch strings.ToLower(strings.TrimSpace(part)) {
	case "req":
		return []partPicker{req}
	case "both":
		return []partPicker{req, resp}
	default:
		return []partPicker{resp}
	}
}

// matcher wraps the literal and regex search paths behind one interface, so the
// permissiveness invariant with the store's stage-one matcher lives in one place.
type matcher struct {
	re      *regexp.Regexp
	literal []byte
	fold    bool
}

func compileMatcher(pattern string, isRegex, caseSensitive bool) (*matcher, error) {
	if isRegex {
		// The store compiles with no added flags, so stage two must not add any
		// either, or the two stages disagree about what matched.
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		return &matcher{re: re}, nil
	}
	return &matcher{literal: []byte(pattern), fold: !caseSensitive}, nil
}

func (m *matcher) find(hay []byte, limit int) []int {
	if limit <= 0 {
		return nil
	}
	var out []int
	if m.re != nil {
		for _, loc := range m.re.FindAllIndex(hay, limit) {
			out = append(out, loc[0])
		}
		return out
	}
	needle := m.literal
	search := hay
	if m.fold {
		search = bytes.ToLower(hay)
		needle = bytes.ToLower(needle)
	}
	off := 0
	for len(out) < limit {
		i := bytes.Index(search[off:], needle)
		if i < 0 {
			break
		}
		out = append(out, off+i)
		off += i + max(1, len(needle))
		if off >= len(search) {
			break
		}
	}
	return out
}

// width reports the length of the match starting at off, so context can bracket
// the whole match rather than a fixed guess.
func (m *matcher) width(hay []byte, off int) int {
	if m.re != nil {
		if loc := m.re.FindIndex(hay[off:]); loc != nil && loc[0] == 0 {
			return loc[1]
		}
		return 1
	}
	return len(m.literal)
}

// contextAround renders the bytes surrounding a match as one escaped line, marking
// clipping at either end.
func contextAround(hay []byte, off, width, ctx int) string {
	start := max(0, off-ctx)
	end := min(off+width+ctx, len(hay))
	var b strings.Builder
	if start > 0 {
		b.WriteString("...")
	}
	b.WriteString(escapeCell(hay[start:end]))
	if end < len(hay) {
		b.WriteString("...")
	}
	return b.String()
}

func clampInt(v, def, lo, hi int) int {
	if v <= 0 {
		v = def
	}
	return min(max(v, lo), hi)
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
