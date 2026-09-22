package chain

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/BishopFox/joro/internal/httptools"
)

// ProposeBinding works one operator-chosen value up into bindings.
//
// The same inference Correlate runs, aimed by hand. Correlate's filters exist so
// a bulk scan does not bury the two dependencies that matter in forty that do
// not; an operator pointing at one value has already made that judgment, and the
// places it lands are on screen. So they are reported as warnings here, and only
// what the run cannot do is refused.
//
// The rules are not restated: harvest is the one table of what can read a value
// out of a response.
func ProposeBinding(c *Chain, fromStep, value string, opts BindOptions) (BindProposal, error) {
	producer, from, ok := c.StepByID(fromStep)
	if !ok {
		return BindProposal{}, fmt.Errorf("no such step %q", fromStep)
	}
	if len(producer.RespRaw) == 0 {
		return BindProposal{}, fmt.Errorf("%q has no recorded response to read a value out of", producer.Label)
	}
	if value == "" {
		return BindProposal{}, fmt.Errorf("nothing selected")
	}
	if len(value) > maxValueLen {
		return BindProposal{}, fmt.Errorf("selection is %d bytes, over the %d byte limit a source may return", len(value), maxValueLen)
	}

	resp := httptools.ReadResponse(producer.RespRaw)
	sources := proposeSources(producer.RespRaw, resp, value, opts)
	out := BindProposal{Recorded: value, Sources: sources}

	if len(sources) == 0 {
		return BindProposal{}, fmt.Errorf(
			"no rule can read that value back out of %q's response — nothing in the recorded response matches it", producer.Label)
	}
	best := sources[0].Source
	out.Var = varName(candidate{value: value, source: best}, c.Bindings)

	// Correlate's filters are reported rather than applied — both are about how
	// easily a value is mistaken for another, which the span list now shows.
	if !plausible(value) {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"%q is short or repetitive, so it may occur in places that are not this dependency — check the highlighted spans before accepting", value))
	}
	if isConstant(c, from, value) {
		out.Warnings = append(out.Warnings, fmt.Sprintf(
			"this value also appears in a request at or before %q, so it may be a constant rather than something that step produces", producer.Label))
	}

	want := map[string]bool{}
	for _, id := range opts.ToSteps {
		want[id] = true
	}

	for j := from + 1; j < len(c.Steps); j++ {
		consumer := c.Steps[j]
		if len(want) > 0 && !want[consumer.ID] {
			continue
		}
		spans, manual := opts.Spans[consumer.ID], false
		if len(spans) > 0 {
			manual = true
		} else {
			spans = findSpans(consumer.ReqRaw, value)
		}
		if len(spans) == 0 {
			if enc := encodedNote(consumer.ReqRaw, value); enc != "" {
				out.Warnings = append(out.Warnings, fmt.Sprintf("%s in %q", enc, consumer.Label))
			}
			continue
		}

		t := BindTarget{Binding: Binding{
			Var:       out.Var,
			FromStep:  producer.ID,
			Source:    best,
			ToStep:    consumer.ID,
			Spans:     spans,
			Recorded:  value,
			OnMissing: MissingFail,
		}}
		if manual {
			t.Note = "bytes you picked"
		}
		if err := checkSpans(c, consumer, spans); err != nil {
			t.Conflict = err.Error()
		}
		out.Targets = append(out.Targets, t)
	}
	return out, nil
}

// BindOptions narrows a proposal to what the operator has already decided.
type BindOptions struct {
	// Occurrence picks which appearance of the value in the producer's response
	// a between source anchors on. A token printed twice on one page needs two
	// different anchors, and the first is not always the one selected.
	Occurrence int

	// Source overrides inference outright. An operator writing a regex has made
	// a judgment about a response that has not happened yet, which no ranking
	// over a single recording can make, so it is taken as given and only
	// verified.
	Source *Source

	// ToSteps limits the search. Empty searches every step after the producer.
	ToSteps []string

	// Spans supplied per consumer replace the literal search for that step. A
	// consumer that carries the value re-encoded has no literal occurrence to
	// find, and pointing at the bytes is the only remaining honest answer.
	Spans map[string][]Span
}

// SourceOption is one rule that would read the chosen value out of a fresh
// response, with the proof that it reads it out of the recorded one.
//
// Verified, not merely ranked: a value is hand-picked precisely when correlation
// missed it, so inference is least trustworthy here. Extract turns "this rule
// looks applicable" into "this rule returns the bytes you selected".
type SourceOption struct {
	Source Source `json:"source"`
	Detail string `json:"detail"`
	Rank   int    `json:"rank"`

	// Matched is what Extract returned against the recorded response, OK whether
	// that equals the selection, and Err why it did not run.
	Matched string `json:"matched,omitempty"`
	OK      bool   `json:"ok"`
	Err     string `json:"err,omitempty"`
}

// BindTarget is one consumer the value could be written into.
type BindTarget struct {
	Binding Binding `json:"binding"`

	// Conflict names why these spans cannot be accepted. Validation refuses an
	// overlap outright, so reporting it here keeps the refusal next to the click
	// rather than at the next save.
	Conflict string `json:"conflict,omitempty"`
	Note     string `json:"note,omitempty"`
}

// BindProposal is what one selected value amounts to. Empty Targets is a result,
// not an error: a value nothing consumes literally is normal, and the source
// inference is still the half the operator cannot redo by hand.
type BindProposal struct {
	Var      string         `json:"var"`
	Recorded string         `json:"recorded"`
	Sources  []SourceOption `json:"sources"`
	Targets  []BindTarget   `json:"targets"`
	Warnings []string       `json:"warnings,omitempty"`
}

// proposeSources ranks and verifies every rule that would read value back out.
//
// respRaw as well as resp: harvest re-parses the captured bytes, and a
// re-serialized decoded copy would contradict its own Content-Encoding.
func proposeSources(respRaw []byte, resp httptools.Response, value string, opts BindOptions) []SourceOption {
	var cands []candidate
	if opts.Source != nil {
		cands = []candidate{{value: value, source: *opts.Source, rank: 100}}
	} else {
		exact := func(v string) bool { return v == value }
		cands = harvest(respRaw, exact, 0)
		if h, ok := headerSource(resp, value); ok {
			cands = append(cands, candidate{value: value, source: h, rank: 31})
		}
		// The same haystack Extract searches: a value in a header line has no
		// anchor in the body alone.
		hay := append(append([]byte(nil), headerBytes(resp)...), resp.Body...)
		if b, ok := betweenAt(hay, value, opts.Occurrence); ok {
			cands = append(cands, candidate{value: value, source: b, rank: 9})
		}
	}

	seen := map[string]bool{}
	out := make([]SourceOption, 0, len(cands))
	for _, c := range cands {
		key := c.source.Describe()
		if seen[key] {
			continue
		}
		seen[key] = true
		o := SourceOption{Source: c.source, Detail: key, Rank: c.rank}
		got, err := Extract(c.source, resp)
		if err != nil {
			o.Err = err.Error()
		} else {
			o.Matched = got
			o.OK = got == value
		}
		out = append(out, o)
	}
	// A rule that returns the selection outranks a more specific one that does
	// not: specificity is a guess, failing on the recording is a fact.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].OK != out[j].OK {
			return out[i].OK
		}
		return out[i].Rank > out[j].Rank
	})
	return out
}

// headerSource matches a chosen value against the producer's response headers.
//
// Correlate reads only interestingHeaders, because a bulk pass proposes
// Content-Type and Date. A hand-picked value carries no such doubt, so any
// header name is fair, and a whole-value match outlasts a text anchor.
func headerSource(resp httptools.Response, value string) (Source, bool) {
	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		names = append(names, name)
	}
	sort.Strings(names) // Header order is map order; a stable proposal needs one.
	for _, name := range names {
		for _, v := range resp.Header.Values(name) {
			if v == value {
				return Source{Kind: SourceHeader, Name: name}, true
			}
		}
	}
	return Source{}, false
}

// betweenAt anchors a between source on the nth occurrence of value in the body.
//
// The fallback for a selection tokenRun does not match. It survives a changing
// value but not a changing page, so it ranks below everything harvest produces.
func betweenAt(body []byte, value string, occurrence int) (Source, bool) {
	s := string(body)
	at, off := -1, 0
	for i := 0; i <= occurrence; i++ {
		k := strings.Index(s[off:], value)
		if k < 0 {
			return Source{}, false
		}
		at = off + k
		off = at + len(value)
	}
	prefix := contextBefore(body, at)
	if prefix == "" {
		return Source{}, false // validateSource refuses an unanchored between.
	}
	return Source{Kind: SourceBetween, Prefix: prefix, Suffix: contextAfter(body, at+len(value))}, true
}

// checkSpans applies the write-path rules a save would, so a target that cannot
// be accepted says so at the click.
func checkSpans(c *Chain, consumer Step, spans []Span) error {
	if len(spans) > MaxSpansPerBinding {
		return fmt.Errorf("writes to %d places, over the limit of %d", len(spans), MaxSpansPerBinding)
	}
	limit := len(consumer.ReqRaw)
	for _, sp := range spans {
		if sp.Start < 0 || sp.End > limit || sp.Start >= sp.End {
			return fmt.Errorf("a span falls outside %q's recorded request", consumer.Label)
		}
	}
	for _, b := range c.BindingsInto(consumer.ID) {
		for _, a := range b.Spans {
			for _, sp := range spans {
				if sp.Start < a.End && a.Start < sp.End {
					return fmt.Errorf("overlaps the bytes %q already writes", b.Var)
				}
			}
		}
	}
	return nil
}

// encodedNote reports a value a consumer carries in some encoded form.
//
// Named, never offered as a span: Binding has no per-sink transform, so binding
// an encoded occurrence injects the raw value and the rejection reads as the
// application enforcing its order.
//
// Decoding the request rather than re-encoding the value, because there is no
// single right percent-encoding and an encoder here would have to guess which
// one the application used.
func encodedNote(raw []byte, value string) string {
	s := string(raw)
	if dec := percentDecode(s); dec != s && strings.Contains(dec, value) {
		return "appears percent-encoded, so a span there would inject the raw value"
	}
	if enc := base64.StdEncoding.EncodeToString([]byte(value)); strings.Contains(s, strings.TrimRight(enc, "=")) {
		return "appears base64-encoded, so a span there would inject the raw value"
	}
	if esc := strings.ReplaceAll(value, "/", `\/`); esc != value && strings.Contains(s, esc) {
		return "appears with its slashes escaped, so a span there would inject the raw value"
	}
	return ""
}

// percentDecode resolves %XX escapes and leaves everything else alone.
//
// Not net/url.QueryUnescape, which refuses the whole input on a malformed
// escape — and raw request bodies routinely carry a bare %.
func percentDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
