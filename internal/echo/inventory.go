package echo

import (
	"sort"
	"time"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/proxy"
)

// maxExampleValue bounds the example carried on a row. A JSON leaf has no length
// limit of its own, and a row is a table cell.
const maxExampleValue = 256

// RequestParams is Walk's output without the matching step: every input the
// request carried, whether or not it is worth searching a response for.
//
// ScanHeaders is forced on. The engine leaves it off because a header walk buries
// a reflection map in values the operator never sent, but that reasoning is about
// ranking matches and there are no matches here — a header and a cookie are inputs
// the target parses, so an inventory that hid them would be answering a different
// question than the one it was asked. boringHeaders still drops the ones the
// client fixes.
func RequestParams(r *proxy.CapturedRequest, cfg Config) []Value {
	cfg.Normalize()
	cfg.ScanHeaders = true
	return Walk(detect.Parse(r, ParseConfig(cfg)), cfg)
}

// ParamRow is one parameter observed across a set of requests, identified the way
// Value.Key identifies it: by source and name, independent of value.
type ParamRow struct {
	Source Source `json:"source"`
	Name   string `json:"name"`

	// Requests counts the requests that carried the parameter, not the times it
	// appeared: a name repeated within one request counts once.
	Requests       int      `json:"requests"`
	DistinctValues int      `json:"distinctValues"`
	Methods        []string `json:"methods"`

	ExampleValue     string    `json:"exampleValue"`
	ExampleRequestID string    `json:"exampleRequestId"`
	LastSeen         time.Time `json:"lastSeen"`

	// Reflected and Breakouts are filled by the caller from the reflection store,
	// which this package's inventory half knows nothing about. Both stay zero when
	// reflection mapping has never run, which reads as "not known to reflect" and
	// must not be rendered as "does not reflect".
	Reflected bool `json:"reflected"`
	Breakouts int  `json:"breakouts"`
}

// Inventory folds a set of captured requests into one row per parameter, sorted
// by source display order then name. Input order does not matter; the example and
// LastSeen come from the newest request that carried the parameter.
//
// The caller decides how many requests to walk. This is the expensive half of the
// package — every request is parsed and every body walked — so it is built on
// demand for one site-map node rather than maintained as the engine scans.
func Inventory(reqs []*proxy.CapturedRequest, cfg Config) []ParamRow {
	type agg struct {
		row     ParamRow
		values  map[string]struct{}
		methods map[string]struct{}
	}

	rows := make(map[string]*agg)
	for _, r := range reqs {
		if r == nil {
			continue
		}
		// A name repeated within one request must not inflate Requests, so the
		// per-request keys are collapsed before folding.
		seen := make(map[string]struct{})
		for _, v := range RequestParams(r, cfg) {
			key := v.Key()
			a, ok := rows[key]
			if !ok {
				a = &agg{
					row:     ParamRow{Source: v.Source, Name: v.Name},
					values:  make(map[string]struct{}),
					methods: make(map[string]struct{}),
				}
				rows[key] = a
			}
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				a.row.Requests++
			}
			a.values[v.Value] = struct{}{}
			a.methods[r.Method] = struct{}{}
			if r.Timestamp.After(a.row.LastSeen) {
				a.row.LastSeen = r.Timestamp
				a.row.ExampleRequestID = r.ID
				a.row.ExampleValue = truncateValue(v.Value)
			}
		}
	}

	order := make(map[Source]int, len(Sources))
	for i, s := range Sources {
		order[s] = i
	}

	out := make([]ParamRow, 0, len(rows))
	for _, a := range rows {
		a.row.DistinctValues = len(a.values)
		methods := make([]string, 0, len(a.methods))
		for m := range a.methods {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		a.row.Methods = methods
		out = append(out, a.row)
	}
	sort.Slice(out, func(i, j int) bool {
		if oi, oj := order[out[i].Source], order[out[j].Source]; oi != oj {
			return oi < oj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// truncateValue cuts an example to maxExampleValue bytes without splitting a
// rune, so the result is still valid UTF-8 for a JSON encoder.
func truncateValue(v string) string {
	if len(v) <= maxExampleValue {
		return v
	}
	cut := maxExampleValue
	for cut > 0 && v[cut]&0xC0 == 0x80 {
		cut--
	}
	return v[:cut]
}
