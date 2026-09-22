package chain

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/httptools"
)

// Correlation thresholds.
const (
	// minCandidateLen is the shortest value worth binding. Below this a literal
	// occurs by coincidence: an order id of "42" appears in a dozen innocent
	// places in a request, and binding it corrupts them all.
	minCandidateLen = 6

	// minCandidateEntropy separates an identifier from a word. Random base64
	// scores around 6.0 and random hex around 4.0; English prose runs 4.0 to 4.5
	// over a paragraph but a single short word scores well under 3.0, which is
	// what this is filtering out.
	minCandidateEntropy = 2.6

	// maxCandidatesPerStep bounds the harvest from one response. A JSON document
	// with thousands of leaves would otherwise turn correlation into a
	// cross-product over the whole chain.
	maxCandidatesPerStep = 400
)

// tokenRun matches identifier-shaped runs in a response body: the shape a CSRF
// token, a signed id or a nonce takes. Deliberately not a catch-all — anything
// this misses is still reachable by hand with a regex or between source.
var tokenRun = regexp.MustCompile(`[A-Za-z0-9_\-+/=.]{6,}`)

// interestingHeaders are response headers whose values routinely feed a later
// request. Values from anywhere else in the header block are still found by the
// body scan, which runs over the serialized headers too.
var interestingHeaders = []string{
	"Location", "ETag", "Authorization", "X-CSRF-Token", "X-XSRF-Token",
	"X-Request-Token", "X-Auth-Token", "X-Access-Token",
}

// candidate is one value a step's response produced, with the tightest rule that
// would read it back out of a fresh response.
type candidate struct {
	value  string
	source Source
	rank   int // higher is a more specific rule; breaks ties toward cookie/json
}

// Correlate proposes the data dependencies in a chain.
//
// Without this the feature does not work. Every reordered or repeated run would
// die on a stale CSRF token, and an operator could not tell a business-logic
// bypass from a replay that simply fell apart — which is the one distinction the
// whole tab exists to make.
//
// The result is a proposal. It is not written to the chain: the operator accepts
// or rejects each binding, the way a render is a preview and not a send.
func Correlate(chain *Chain) []Binding {
	var out []Binding
	n := 0
	nextID := func() string { n++; return "b" + strconv.Itoa(n) }

	for i, producer := range chain.Steps {
		if len(producer.RespRaw) == 0 {
			continue
		}
		cands := harvest(producer.RespRaw, plausible, maxCandidatesPerStep)
		if len(cands) == 0 {
			continue
		}

		for j := i + 1; j < len(chain.Steps); j++ {
			consumer := chain.Steps[j]
			for _, c := range cands {
				if isConstant(chain, i, c.value) {
					continue
				}
				spans := findSpans(consumer.ReqRaw, c.value)
				if len(spans) == 0 || len(spans) > MaxSpansPerBinding {
					continue
				}
				out = append(out, Binding{
					ID:        nextID(),
					Var:       varName(c, out),
					FromStep:  producer.ID,
					Source:    c.source,
					ToStep:    consumer.ID,
					Spans:     spans,
					Recorded:  c.value,
					OnMissing: MissingFail,
					Auto:      true,
				})
			}
		}
	}
	return out
}

// isConstant reports whether a value already appeared in a request at or before
// its supposed producer.
//
// A static API key is present in every request in the chain, so a naive search
// binds it to everything and buries the two dependencies that matter in forty
// that do not. A value that existed before the step that supposedly produced it
// was not produced by that step.
func isConstant(chain *Chain, producerIdx int, value string) bool {
	for k := 0; k <= producerIdx && k < len(chain.Steps); k++ {
		if len(findSpans(chain.Steps[k].ReqRaw, value)) > 0 {
			return true
		}
	}
	return false
}

// harvest pulls candidate values out of a recorded response, best rule first.
//
// keep decides which values are worth returning and maxRuns bounds the body
// scan; both are the caller's policy rather than this function's. A scan over a
// whole chain needs the entropy floor and the cap, or it proposes hundreds of
// coincidences. A value an operator pointed at needs neither, and applying them
// there would refuse to bind the case the operator came here for. Keeping the
// rule table here and the judgment at the call site is what lets correlation and
// hand-authored bindings share one definition of what a Source can read.
//
// maxRuns of zero or less means unlimited.
func harvest(respRaw []byte, keep func(string) bool, maxRuns int) []candidate {
	resp := httptools.ReadResponse(respRaw)
	seen := make(map[string]candidate)

	add := func(c candidate) {
		if !keep(c.value) {
			return
		}
		if prev, ok := seen[c.value]; !ok || c.rank > prev.rank {
			seen[c.value] = c
		}
	}

	// Cookies first: they are the most specific rule and the one that survives
	// the server rotating the value, because it resolves by name.
	for _, sc := range resp.Header.Values("Set-Cookie") {
		name, val, ok := strings.Cut(sc, "=")
		if !ok {
			continue
		}
		val, _, _ = strings.Cut(val, ";")
		add(candidate{
			value:  strings.TrimSpace(val),
			source: Source{Kind: SourceCookie, Name: strings.TrimSpace(name)},
			rank:   40,
		})
	}

	for _, h := range interestingHeaders {
		if v := resp.Header.Get(h); v != "" {
			add(candidate{value: v, source: Source{Kind: SourceHeader, Name: h}, rank: 30})
		}
	}

	// JSON leaves, addressed by path.
	if looksJSON(resp) {
		var doc any
		if json.Unmarshal(resp.Body, &doc) == nil {
			walkJSON(doc, "", func(path, val string) {
				add(candidate{value: val, source: Source{Kind: SourceJSON, Path: path}, rank: 35})
			})
		}
	}

	// Everything else, anchored on the literal text around it. This is the
	// fallback precisely because it is the least robust rule: it survives a
	// changing value but not a changing page.
	body := resp.Body
	runs := maxRuns
	if runs <= 0 {
		runs = -1 // FindAllIndex reads a negative count as "every match".
	}
	for _, loc := range tokenRun.FindAllIndex(body, runs) {
		val := string(body[loc[0]:loc[1]])
		if _, ok := seen[val]; ok {
			continue
		}
		add(candidate{
			value:  val,
			source: Source{Kind: SourceBetween, Prefix: contextBefore(body, loc[0]), Suffix: contextAfter(body, loc[1])},
			rank:   10,
		})
	}

	out := make([]candidate, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	// Most specific rule first, then longest value: a long value is less likely
	// to be a coincidence, and ordering makes the proposal list readable.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank > out[j].rank
		}
		return len(out[i].value) > len(out[j].value)
	})
	if maxRuns > 0 && len(out) > maxRuns {
		out = out[:maxRuns]
	}
	return out
}

// plausible is the length-and-entropy filter.
func plausible(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < minCandidateLen || len(v) > maxValueLen {
		return false
	}
	// A value that is all one character carries no identity no matter how long.
	if strings.Count(v, string(v[0])) == len(v) {
		return false
	}
	return shannonEntropy(v) >= minCandidateEntropy
}

// shannonEntropy returns bits per character.
//
// Deliberately a copy of detect.ShannonEntropy rather than an import, for the
// reason httptools.splitRaw records about detect.Parse: taking the export drags
// the 167-rule engine into this package's dependency graph for one twelve-line
// pure function. Cross-referenced in internal/detect/entropy.go.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

func looksJSON(resp httptools.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "json") {
		return true
	}
	t := strings.TrimSpace(string(resp.Body))
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}

// walkJSON visits every scalar leaf with its dotted path.
func walkJSON(v any, path string, fn func(path, val string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walkJSON(sub, p, fn)
		}
	case []any:
		for i, sub := range t {
			walkJSON(sub, path+"["+strconv.Itoa(i)+"]", fn)
		}
	case string:
		if path != "" {
			fn(path, t)
		}
	case float64:
		if path != "" {
			fn(path, strconv.FormatFloat(t, 'f', -1, 64))
		}
	}
}

// contextBefore and contextAfter capture the literal text bracketing a value, so
// a between source can find it again in a fresh response.
func contextBefore(body []byte, at int) string {
	const window = 24
	start := at - window
	if start < 0 {
		start = 0
	}
	return string(body[start:at])
}

func contextAfter(body []byte, at int) string {
	const window = 16
	end := at + window
	if end > len(body) {
		end = len(body)
	}
	return string(body[at:end])
}

// findSpans locates every occurrence of a value in a recorded request.
//
// Every occurrence, not the first: a CSRF token is routinely present in both a
// header and a form field, and binding only one leaves the request internally
// inconsistent in a way the origin rejects.
func findSpans(raw []byte, value string) []Span {
	if value == "" {
		return nil
	}
	var out []Span
	off := 0
	for {
		i := strings.Index(string(raw[off:]), value)
		if i < 0 {
			return out
		}
		start := off + i
		out = append(out, Span{Start: start, End: start + len(value)})
		off = start + len(value)
		if len(out) > MaxSpansPerBinding {
			return out
		}
	}
}

// varName derives a readable, unique name for a proposed binding.
func varName(c candidate, existing []Binding) string {
	base := ""
	switch c.source.Kind {
	case SourceCookie:
		base = sanitizeVar(c.source.Name)
	case SourceHeader:
		base = sanitizeVar(c.source.Name)
	case SourceJSON:
		segs := splitJSONPath(c.source.Path)
		if len(segs) > 0 {
			base = sanitizeVar(segs[len(segs)-1])
		}
	case SourceBetween:
		base = sanitizeVar(lastIdent(c.source.Prefix))
	case SourceRegex:
		base = sanitizeVar(lastIdent(c.source.Expr))
	}
	if base == "" {
		base = "value"
	}

	// Reuse the name when the same value is already bound: one value feeding
	// three steps should read as one variable in three places, not three
	// variables that happen to be equal.
	for _, b := range existing {
		if b.Recorded == c.value {
			return b.Var
		}
	}
	taken := map[string]bool{}
	for _, b := range existing {
		taken[b.Var] = true
	}
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		n := base + strconv.Itoa(i)
		if !taken[n] {
			return n
		}
	}
}

// identRun matches a name-shaped run, for deriving a variable name from the text
// a between source anchors on.
var identRun = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_-]*`)

// lastIdent returns the final name-shaped run in s.
//
// The text immediately before a value is what names it: a prefix ending
// `var cfg={csrf:"` says the value is a csrf token. Without this every value
// reached by the between fallback is called "value", "value2", "value3" — which
// is exactly the set of bindings an operator most needs to tell apart, because
// the fallback is what fires for a token buried in a script.
func lastIdent(s string) string {
	m := identRun.FindAllString(s, -1)
	if len(m) == 0 {
		return ""
	}
	return m[len(m)-1]
}

func sanitizeVar(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		case r == '_' || r == '-':
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if len(out) > MaxVarLen {
		out = out[:MaxVarLen]
	}
	return out
}
