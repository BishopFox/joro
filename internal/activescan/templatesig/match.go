package templatesig

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/activescan"
	"github.com/BishopFox/joro/internal/httptools"
)

// replacer substitutes the URL template tokens nuclei expands inside matcher
// words at match time. BaseURL is the target origin; Host is its host[:port].
type replacer struct {
	baseURL string
	host    string
}

func (r replacer) apply(s string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	s = strings.ReplaceAll(s, "{{BaseURL}}", r.baseURL)
	s = strings.ReplaceAll(s, "{{RootURL}}", r.baseURL)
	s = strings.ReplaceAll(s, "{{Hostname}}", r.host)
	s = strings.ReplaceAll(s, "{{Host}}", r.host)
	return s
}

// evalMatchers evaluates a request's matcher set against a response and returns
// whether it matched, with a short evidence string naming what matched.
func evalMatchers(req *Request, resp httptools.Response, rp replacer) (bool, string) {
	if len(req.Matchers) == 0 {
		return false, ""
	}
	and := strings.EqualFold(req.MatchersCondition, "and")
	var evidence []string
	allOK := true
	anyOK := false
	for i := range req.Matchers {
		ok, ev := evalMatcher(&req.Matchers[i], resp, rp)
		if ok {
			anyOK = true
			if ev != "" {
				evidence = append(evidence, ev)
			}
		} else {
			allOK = false
		}
	}
	matched := anyOK
	if and {
		matched = allOK
	}
	if !matched {
		return false, ""
	}
	return true, strings.Join(evidence, "; ")
}

// evalMatcher evaluates one matcher. Negative inverts the result; a negative
// match reports no evidence (there is nothing to show).
func evalMatcher(m *Matcher, resp httptools.Response, rp replacer) (bool, string) {
	ok, ev := matcherHit(m, resp, rp)
	if m.Negative {
		return !ok, ""
	}
	return ok, ev
}

func matcherHit(m *Matcher, resp httptools.Response, rp replacer) (bool, string) {
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if resp.Status == s {
				return true, "status " + strconv.Itoa(s)
			}
		}
		return false, ""
	case "size":
		n := len(resp.Body)
		for _, s := range m.Sizes {
			if n == s {
				return true, "size " + strconv.Itoa(n)
			}
		}
		return false, ""
	case "word":
		return matchWords(m, part(m.Part, resp), rp)
	case "regex":
		return matchRegexes(m, part(m.Part, resp))
	default:
		return false, ""
	}
}

// matchWords applies the word list with the matcher's and/or condition. Words are
// matched case-insensitively, matching nuclei's default.
func matchWords(m *Matcher, hay string, rp replacer) (bool, string) {
	if len(m.Words) == 0 {
		return false, ""
	}
	and := strings.EqualFold(m.Condition, "and")
	lower := strings.ToLower(hay)
	anyOK, allOK := false, true
	var first string
	for _, w := range m.Words {
		w = rp.apply(w)
		if strings.Contains(lower, strings.ToLower(w)) {
			anyOK = true
			if first == "" {
				first = w
			}
		} else {
			allOK = false
		}
	}
	if (and && allOK) || (!and && anyOK) {
		return true, "matched " + strconv.Quote(first)
	}
	return false, ""
}

// matchRegexes applies the compiled regex list with the matcher's and/or
// condition. The evidence is the first concrete match, truncated.
func matchRegexes(m *Matcher, hay string) (bool, string) {
	if len(m.compiled) == 0 {
		return false, ""
	}
	and := strings.EqualFold(m.Condition, "and")
	anyOK, allOK := false, true
	var first string
	for _, re := range m.compiled {
		if loc := re.FindString(hay); loc != "" || re.MatchString(hay) {
			anyOK = true
			if first == "" {
				first = loc
			}
		} else {
			allOK = false
		}
	}
	if (and && allOK) || (!and && anyOK) {
		return true, "matched " + strconv.Quote(truncate(first, 80))
	}
	return false, ""
}

// part selects the response region a matcher reads. Default is the body.
func part(name string, resp httptools.Response) string {
	switch strings.ToLower(name) {
	case "header", "headers":
		return headerString(resp)
	case "all", "response", "raw":
		return headerString(resp) + "\r\n\r\n" + string(resp.Body)
	default:
		return string(resp.Body)
	}
}

func headerString(resp httptools.Response) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d\r\n", resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// spreader distributes a rule's share of the run's URL-based total across its own
// internal steps, so the scan's completed/total stays coherent when the rule's
// real unit of work (signatures) differs from the planned unit (URLs).
type spreader struct {
	rep     activescan.Reporter
	budget  int
	steps   int
	done    int
	emitted int
}

func newSpreader(rep activescan.Reporter, budget, steps int) *spreader {
	return &spreader{rep: rep, budget: budget, steps: steps}
}

func (p *spreader) step() {
	p.done++
	want := p.budget
	if p.steps > 0 {
		want = p.budget * p.done / p.steps
	}
	if want > p.budget {
		want = p.budget
	}
	if want > p.emitted {
		p.rep.Progress(want - p.emitted)
		p.emitted = want
	}
}

func (p *spreader) finish() {
	if p.budget > p.emitted {
		p.rep.Progress(p.budget - p.emitted)
		p.emitted = p.budget
	}
}
