package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// MatchReplaceRule defines a single match-and-replace transformation.
type MatchReplaceRule struct {
	ID        string         `json:"id"`
	Target    string         `json:"target"`    // "request_header", "request_body", "response_header", "response_body", "ws_message"
	MatchType string         `json:"matchType"` // "string" or "regex"
	Match     string         `json:"match"`
	Replace   string         `json:"replace"`
	compiled  *regexp.Regexp // cached for regex rules
}

// MatchReplace manages a set of match-and-replace rules applied to proxy traffic.
type MatchReplace struct {
	mu      sync.RWMutex
	enabled bool
	rules   []MatchReplaceRule
}

// NewMatchReplace creates a disabled MatchReplace with no rules.
func NewMatchReplace() *MatchReplace {
	return &MatchReplace{}
}

// IsEnabled reports whether match-and-replace is active.
func (mr *MatchReplace) IsEnabled() bool {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.enabled
}

// SetEnabled enables or disables match-and-replace.
func (mr *MatchReplace) SetEnabled(enabled bool) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.enabled = enabled
}

// Rules returns a copy of the current rules.
func (mr *MatchReplace) Rules() []MatchReplaceRule {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	out := make([]MatchReplaceRule, len(mr.rules))
	copy(out, mr.rules)
	return out
}

// SetRules replaces all match-and-replace rules, compiling regex patterns.
func (mr *MatchReplace) SetRules(rules []MatchReplaceRule) {
	for i := range rules {
		if rules[i].MatchType == "regex" {
			rules[i].compiled, _ = regexp.Compile(rules[i].Match)
		}
	}
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.rules = rules
}

// AddRule adds a new rule with a generated ID. Returns the rule.
func (mr *MatchReplace) AddRule(target, matchType, match, replace string) MatchReplaceRule {
	rule := MatchReplaceRule{
		ID:        GenerateID(),
		Target:    target,
		MatchType: matchType,
		Match:     match,
		Replace:   replace,
	}
	if matchType == "regex" {
		rule.compiled, _ = regexp.Compile(match)
	}
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.rules = append(mr.rules, rule)
	return rule
}

// RemoveRule deletes a rule by ID. Returns true if found.
func (mr *MatchReplace) RemoveRule(id string) bool {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	for i, r := range mr.rules {
		if r.ID == id {
			mr.rules = append(mr.rules[:i], mr.rules[i+1:]...)
			return true
		}
	}
	return false
}

// HasResponseRules reports whether any rules target response_header or response_body.
func (mr *MatchReplace) HasResponseRules() bool {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	for _, r := range mr.rules {
		if r.Target == "response_header" || r.Target == "response_body" {
			return true
		}
	}
	return false
}

// Apply runs all enabled rules matching the given target against data, returning the modified result.
func (mr *MatchReplace) Apply(target string, data []byte) []byte {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	if !mr.enabled {
		return data
	}
	for _, r := range mr.rules {
		if r.Target != target {
			continue
		}
		if r.MatchType == "regex" {
			if r.compiled != nil {
				data = r.compiled.ReplaceAll(data, []byte(r.Replace))
			}
		} else {
			data = []byte(strings.ReplaceAll(string(data), r.Match, r.Replace))
		}
	}
	return data
}

// stripBlankHeaderLines removes empty lines from a header block. A header rule
// that replaces a header with an empty string leaves the surrounding CRLF
// behind, producing a blank line; since a blank line marks the end of the
// header section, the request/response would be truncated. Collapsing empty
// lines makes "replace with empty" delete the header line entirely. Valid
// header blocks never contain blank lines, so this is a no-op otherwise.
func stripBlankHeaderLines(header []byte) []byte {
	lines := bytes.Split(header, []byte("\r\n"))
	out := lines[:0]
	for _, ln := range lines {
		if len(ln) == 0 {
			continue
		}
		out = append(out, ln)
	}
	return bytes.Join(out, []byte("\r\n"))
}

// applyRequestReplace applies request_header and request_body rules to an *http.Request.
func applyRequestReplace(mr *MatchReplace, r *http.Request) *http.Request {
	raw, err := dumpRequest(r, true)
	if err != nil {
		return r
	}

	sep := []byte("\r\n\r\n")
	parts := bytes.SplitN(raw, sep, 2)
	headerBytes := stripBlankHeaderLines(mr.Apply("request_header", parts[0]))
	var bodyBytes []byte
	if len(parts) > 1 {
		bodyBytes = mr.Apply("request_body", parts[1])
	}

	modified := append(headerBytes, sep...)
	modified = append(modified, bodyBytes...)

	parsed, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(modified)))
	if err != nil {
		return r
	}
	// Preserve original URL scheme/host.
	parsed.URL.Scheme = r.URL.Scheme
	parsed.URL.Host = r.URL.Host
	parsed.RequestURI = ""
	return parsed
}

// applyResponseReplace applies response_header and response_body rules to an *http.Response.
func applyResponseReplace(mr *MatchReplace, resp *http.Response) *http.Response {
	// Buffer body and dump from a shallow copy with chunked encoding cleared,
	// so response_body match/replace rules see the decoded bytes rather than
	// chunk-size markers from a re-encoded chunked dump.
	rawBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	capturedResp := *resp
	capturedResp.TransferEncoding = nil
	capturedResp.ContentLength = int64(len(rawBody))
	capturedResp.Body = io.NopCloser(bytes.NewReader(rawBody))
	raw, err := dumpResponse(&capturedResp, true)
	if err != nil {
		return resp
	}

	sep := []byte("\r\n\r\n")
	parts := bytes.SplitN(raw, sep, 2)
	headerBytes := stripBlankHeaderLines(mr.Apply("response_header", parts[0]))
	var bodyBytes []byte
	if len(parts) > 1 {
		bodyBytes = mr.Apply("response_body", parts[1])
	}

	modified := append(headerBytes, sep...)
	modified = append(modified, bodyBytes...)

	parsed, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(modified)), nil)
	if err != nil {
		return resp
	}
	// Update Content-Length to match the new body.
	if len(bodyBytes) > 0 {
		parsed.ContentLength = int64(len(bodyBytes))
		parsed.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	return parsed
}
