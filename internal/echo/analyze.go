package echo

import (
	"bytes"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/proxy"
)

// ParseConfig is the detect configuration this engine parses with. It is not
// the operator's detect configuration and must not be: detect.Parse fills
// ReqBody only when ScanRequests is set, so borrowing a configuration with it
// off would leave every body parameter unseen and the map silently half empty.
func ParseConfig(cfg Config) detect.Config {
	return detect.Config{
		ScanRequests:            true,
		MaxBodyScanBytes:        cfg.MaxBodyScanBytes,
		MaxRequestBodyScanBytes: cfg.MaxRequestBodyScanBytes,
	}
}

// Analyze maps one captured message. It never sends and never mutates its
// input.
func Analyze(r *proxy.CapturedRequest, cfg Config) *Report {
	cfg.Normalize()
	m := detect.Parse(r, ParseConfig(cfg))

	rep := &Report{
		RequestID: r.ID,
		Seq:       r.Seq,
		Host:      m.Host,
		Method:    r.Method,
		URL:       r.URL,
		Timestamp: r.Timestamp,
	}

	values := Walk(m, cfg)
	rep.Values = len(values)
	if len(values) == 0 {
		return rep
	}

	// Dedupe needles: two parameters carrying the same value are one search
	// with two owners, and the automaton must not hold the same string twice.
	index := map[string][]int{}
	var needles []string
	for i, v := range values {
		if !admit(v.Value, cfg) {
			continue
		}
		if _, seen := index[v.Value]; !seen {
			needles = append(needles, v.Value)
		}
		index[v.Value] = append(index[v.Value], i)
	}
	rep.Needles = len(needles)

	ac := newMatcher(needles)
	if ac == nil {
		return rep
	}

	// seen keys a reflection by needle and source offset, so a region that is
	// byte-identical across two views is reported once, under the least decoded
	// transform. The identity view is searched first for exactly that reason.
	seen := map[[2]int]bool{}
	capped := false

	record := func(v view, idx int32, start, end int, base int, coord string, part string, spans []ctxSpan) bool {
		if len(rep.Reflections) >= cfg.MaxReflectionsPerRequest {
			capped = true
			return false
		}
		srcStart, srcEnd := v.at(start), v.at(end)
		key := [2]int{int(idx), srcStart}
		if seen[key] {
			return true
		}
		seen[key] = true

		s := sink{ctx: ContextHeaderValue}
		if spans != nil {
			s = sinkAt(spans, srcStart)
		}
		sur := survivedChars(v, start, end)
		val := ac.needles[idx]
		for _, vi := range index[val] {
			src := values[vi]
			rep.Reflections = append(rep.Reflections, Reflection{
				Source: src.Source, Name: src.Name, Value: val,
				Transform: v.kind, Context: s.ctx, JSContext: s.js,
				Attr: s.attr, Quote: s.quote,
				Part: part, Coord: coord,
				Span:       Span{Start: base + srcStart, End: base + srcEnd},
				Survived:   sur,
				Breakout:   breakout(s, sur),
				Confidence: confidence(val),
			})
		}
		return true
	}

	// The response header block: where an injected line break and an echoed
	// redirect target land, and a document a browser acts on before the body.
	if len(m.RespRawHdr) > 0 {
		for _, v := range buildViews(m.RespRawHdr, cfg) {
			ac.find(v.b, func(idx int32, s, e int) bool {
				return record(v, idx, s, e, 0, "raw", "response", nil)
			})
			if capped {
				break
			}
		}
	}

	if m.BodyScannable && len(m.RespBody) > 0 && !capped {
		spans := classify(m.RespBody, detect.ContentTypeKeyword(m.ContentType))
		// A decompressed body shares no coordinates with the raw document, so
		// the offsets are declared against the decoded body instead of being
		// dropped: gzip is the common case and losing it would gut the map.
		base, coord := m.RespBodyStart, "raw"
		if m.RespBodyDecoded {
			base, coord = 0, "decoded-body"
		}
		for _, v := range buildViews(m.RespBody, cfg) {
			ac.find(v.b, func(idx int32, s, e int) bool {
				return record(v, idx, s, e, base, coord, "response", spans)
			})
			if capped {
				break
			}
		}
	}

	rep.Truncated = capped || m.Truncated
	for _, rf := range rep.Reflections {
		if rf.Breakout {
			rep.Breakouts++
		}
	}
	sortReflections(rep.Reflections)
	return rep
}

// sortReflections orders a report for display and for a stable finding
// signature: breakouts first, then by confidence, then by position.
func sortReflections(rs []Reflection) {
	rank := map[Confidence]int{ConfidenceHigh: 0, ConfidenceMedium: 1, ConfidenceLow: 2}
	less := func(a, b Reflection) bool {
		if a.Breakout != b.Breakout {
			return a.Breakout
		}
		if rank[a.Confidence] != rank[b.Confidence] {
			return rank[a.Confidence] < rank[b.Confidence]
		}
		if a.Span.Start != b.Span.Start {
			return a.Span.Start < b.Span.Start
		}
		return a.Name < b.Name
	}
	// Insertion sort: a report is capped at a few hundred entries and this
	// keeps the comparison in one place.
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && less(rs[j], rs[j-1]); j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}

// HostExcluded reports whether a host is on the exclusion list. Matching is a
// case-insensitive substring, as it is in detect, so "cdn." covers every CDN
// host on the engagement.
func HostExcluded(host string, exclude []string) bool {
	if len(exclude) == 0 {
		return false
	}
	h := bytes.ToLower([]byte(host))
	for _, e := range exclude {
		if e == "" {
			continue
		}
		if bytes.Contains(h, bytes.ToLower([]byte(e))) {
			return true
		}
	}
	return false
}
