package proxy

import (
	"strconv"
	"strings"
)

// statusMatcher is the precompiled form of a status filter expression: a
// comma-separated OR of classes ("4xx"), exact codes ("403"), inclusive ranges
// ("500-599"), and "none" (no response captured, StatusCode == 0).
//
// The frontend keeps a hand-written mirror of this in
// web/src/lib/requestFilters.ts — keep the two in sync.
type statusMatcher struct {
	active  bool
	none    bool
	classes [6]bool // index = code/100
	codes   map[int]struct{}
	ranges  [][2]int
}

// parseStatusFilter compiles a status expression. Unparsable tokens are skipped
// silently, so a half-typed value degrades to the tokens that do parse rather
// than matching nothing. An expression with no parsable token is inactive
// (matches every request), which preserves the old behavior of a non-numeric
// status param.
func parseStatusFilter(expr string) statusMatcher {
	var sm statusMatcher
	for _, raw := range strings.Split(expr, ",") {
		tok := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case tok == "":
			continue
		case tok == "none" || tok == "0":
			sm.none = true
		case len(tok) == 3 && tok[0] >= '1' && tok[0] <= '5' && tok[1] == 'x' && tok[2] == 'x':
			sm.classes[tok[0]-'0'] = true
		case strings.Contains(tok, "-"):
			lo, hi, ok := parseStatusRange(tok)
			if !ok {
				continue
			}
			sm.ranges = append(sm.ranges, [2]int{lo, hi})
		default:
			code, err := strconv.Atoi(tok)
			if err != nil || code <= 0 {
				continue
			}
			if sm.codes == nil {
				sm.codes = make(map[int]struct{}, 4)
			}
			sm.codes[code] = struct{}{}
		}
		sm.active = true
	}
	return sm
}

// parseStatusRange splits an inclusive "lo-hi" range token.
func parseStatusRange(tok string) (int, int, bool) {
	parts := strings.SplitN(tok, "-", 2)
	lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, false
	}
	hi, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || lo > hi {
		return 0, 0, false
	}
	return lo, hi, true
}

// match reports whether a status code satisfies the filter. An inactive matcher
// matches everything. A code of 0 (no response captured) matches only the
// "none" token — class, code, and range tokens never match it.
func (sm statusMatcher) match(code int) bool {
	if !sm.active {
		return true
	}
	if code == 0 {
		return sm.none
	}
	if c := code / 100; c >= 1 && c <= 5 && sm.classes[c] {
		return true
	}
	if _, ok := sm.codes[code]; ok {
		return true
	}
	for _, r := range sm.ranges {
		if code >= r[0] && code <= r[1] {
			return true
		}
	}
	return false
}
