package trigger

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/proxy"
)

// Subject supplies field values for one event. Two implementations: RequestSubject over a
// captured request, and JSONSubject over the compact reference a discrete event carries.
type Subject interface {
	Value(field string) FieldValue
}

// FieldValue is one field read.
//
// Ok is false when the event has nothing for that field — a response that was never
// captured, a body that is binary or brotli-encoded, a key the payload does not carry.
// Every operator except exists is false on a missing value, and **negation does not
// rescue it**: "the body does not contain X" must not be satisfied by there being no body
// to look in. Matches enforces that; see the note there, because the flip is exactly what
// would undo it.
type FieldValue struct {
	Ok    bool
	Text  string
	Raw   []byte
	Num   float64
	IsNum bool
}

func (v FieldValue) bytes() []byte {
	if v.Raw != nil {
		return v.Raw
	}
	return []byte(v.Text)
}

// Text, Raw and Number build a FieldValue that is present.
func Text(s string) FieldValue    { return FieldValue{Ok: true, Text: s} }
func Raw(b []byte) FieldValue     { return FieldValue{Ok: true, Raw: b} }
func Number(n float64) FieldValue { return FieldValue{Ok: true, Num: n, IsNum: true} }

// Matches reports whether an event should produce a run.
//
// A nil Compiled means no filter, which is what a built-in trigger is. A poisoned one
// matches nothing.
func (c *Compiled) Matches(s Subject) bool {
	if c == nil {
		return true
	}
	if c.Poisoned {
		return false
	}
	if c.root < 0 {
		return true
	}
	// memo carries each node's answer for this one event, so a node feeding two parents
	// is evaluated once. Sized to the node count and thrown away with the call: it is
	// per-event scratch, not a cache.
	memo := make([]int8, len(c.nodes))
	return c.eval(c.root, s, memo)
}

func (c *Compiled) eval(i int, s Subject, memo []int8) bool {
	if memo[i] != 0 {
		return memo[i] > 0
	}
	n := c.nodes[i]

	var got bool
	switch n.kind {
	case NodeCondition:
		got = n.cond.matches(s)
	case NodeNot:
		got = len(n.children) == 1 && !c.eval(n.children[0], s, memo)
	case NodeAll:
		got = true
		for _, k := range n.children {
			if !c.eval(k, s, memo) {
				got = false
				break
			}
		}
	case NodeAny:
		for _, k := range n.children {
			if c.eval(k, s, memo) {
				got = true
				break
			}
		}
	}

	if got {
		memo[i] = 1
	} else {
		memo[i] = -1
	}
	return got
}

func (c compiledCondition) matches(s Subject) bool {
	v := s.Value(c.field)
	if !v.Ok && c.op != OpExists {
		// A field the event does not carry satisfies nothing, and negation does not
		// rescue it: "the response body does not contain X" must not become true because
		// the response was binary and there is no body to look in. Tested here rather
		// than inside test, because the flip below is exactly what would undo it.
		//
		// exists is the one operator this does not apply to. Asking whether a field is
		// there is a question a missing field answers, and negating it is how an operator
		// writes "responses with no readable body".
		return false
	}
	got := c.test(v)
	if c.negate {
		return !got
	}
	return got
}

func (c compiledCondition) test(v FieldValue) bool {
	if c.op == OpExists {
		return v.Ok && (len(v.Raw) > 0 || v.Text != "" || v.IsNum)
	}
	if !v.Ok {
		return false
	}

	switch c.op {
	case OpStatus:
		if !v.IsNum {
			return false
		}
		return c.status(int(v.Num))

	case OpGt, OpLt, OpGte, OpLte:
		n, ok := numericOf(v)
		if !ok {
			return false
		}
		switch c.op {
		case OpGt:
			return n > c.num
		case OpLt:
			return n < c.num
		case OpGte:
			return n >= c.num
		default:
			return n <= c.num
		}

	case OpIn:
		return slices.Contains(c.set, c.fold(textOf(v)))
	}

	if c.kind == KindBytes {
		hay := v.bytes()
		if c.lit != nil && !bytes.Contains(hay, c.lit) {
			// The regexp's own literal prefix, checked first. A case-insensitive pattern
			// has none, which is why this is a prescreen and not the match.
			return false
		}
		return c.re != nil && c.re.Match(hay)
	}

	text := c.fold(textOf(v))
	switch c.op {
	case OpEq:
		return text == c.value
	case OpNe:
		return text != c.value
	case OpContains:
		return strings.Contains(text, c.value)
	case OpPrefix:
		return strings.HasPrefix(text, c.value)
	case OpSuffix:
		return strings.HasSuffix(text, c.value)
	case OpMatches:
		return c.re != nil && c.re.MatchString(textOf(v))
	case OpGlob:
		ok, err := filepath.Match(c.value, text)
		return err == nil && ok
	}
	return false
}

// fold applies the condition's case rule to the haystack. compileCondition already
// lowercased c.value when the condition is case-insensitive, so the two sides agree.
func (c compiledCondition) fold(s string) string {
	if c.cs {
		return s
	}
	return strings.ToLower(s)
}

func textOf(v FieldValue) string {
	if v.IsNum && v.Text == "" {
		return strconv.FormatFloat(v.Num, 'f', -1, 64)
	}
	if v.Raw != nil && v.Text == "" {
		return string(v.Raw)
	}
	return v.Text
}

func numericOf(v FieldValue) (float64, bool) {
	if v.IsNum {
		return v.Num, true
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(textOf(v)), 64)
	return n, err == nil
}

// ---- subjects ----

// parseConfig is the parse budget for condition evaluation.
//
// Deliberately Joro's shipped defaults rather than the operator's Detect settings, even
// though it is detect.Parse doing the work. The two are unrelated decisions: an operator
// who narrows what Detect scans is saying something about false positives in findings, not
// about which of their own automations should run, and silently importing one into the
// other is a coupling nobody would look for. What it does buy is the parser itself — CRLF
// and LF header terminators, gzip and deflate bodies, the binary sniff and the size caps —
// none of which is worth a second implementation here.
func parseConfig() detect.Config { return detect.DefaultConfig() }

// RequestSubject reads condition fields off a captured request.
//
// Both parses are lazy and each happens at most once, which is what makes the cheap-first
// ordering in the compiler pay: a candidate rejected on its status code never has its body
// decompressed. One subject is built per candidate per dispatch pass and shared by every
// armed automation, so the cost is paid once no matter how many are watching.
type RequestSubject struct {
	req *proxy.CapturedRequest

	parsedURL *url.URL
	urlDone   bool

	msg     *detect.Message
	msgDone bool
}

// NewRequestSubject returns a subject over one captured request.
func NewRequestSubject(r *proxy.CapturedRequest) *RequestSubject {
	return &RequestSubject{req: r}
}

func (s *RequestSubject) path() string {
	if !s.urlDone {
		s.urlDone = true
		s.parsedURL, _ = url.Parse(s.req.URL)
	}
	if s.parsedURL == nil || s.parsedURL.Path == "" {
		return "/"
	}
	return s.parsedURL.Path
}

func (s *RequestSubject) message() *detect.Message {
	if !s.msgDone {
		s.msgDone = true
		s.msg = detect.Parse(s.req, parseConfig())
	}
	return s.msg
}

// Value reads one field.
func (s *RequestSubject) Value(field string) FieldValue {
	r := s.req
	switch field {
	case "method":
		return Text(r.Method)
	case "host":
		return Text(r.Host)
	case "url":
		return Text(r.URL)
	case "path":
		return Text(s.path())
	case "status":
		// Zero is reported as a value, not as a missing field: the status operator has to
		// see it to honor "none", which is what an operator writes for a request whose
		// response never arrived.
		return Number(float64(r.StatusCode))
	case "contentType":
		return Text(detect.ContentTypeKeyword(r.ContentType))
	case "protocol":
		return Text(r.Protocol)
	case "responseSize":
		return Number(float64(r.ResponseSize))
	case "durationMs":
		return Number(float64(r.Duration.Milliseconds()))
	case "request.raw":
		return Raw(r.ReqRaw)
	case "response.raw":
		return Raw(r.RespRaw)
	case "request.headers":
		return Raw(s.message().ReqRawHdr)
	case "response.headers":
		return Raw(s.message().RespRawHdr)
	case "request.body":
		return Raw(s.message().ReqBody)
	case "response.body":
		m := s.message()
		if !m.BodyScannable {
			// Binary, brotli, or absent. Reported as missing rather than as empty so a
			// negated condition does not read it as "the body does not contain X".
			return FieldValue{}
		}
		return Raw(m.RespBody)
	}
	return FieldValue{}
}

// JSONSubject reads condition fields off the compact reference a discrete event carries.
//
// Decoded once per event rather than per condition. These are low-volume by nature — a
// finding, a finished campaign, a finished run — so the map lookup costs less than a
// second set of typed accessors would cost to keep in step with the payload structs.
type JSONSubject struct {
	fields map[string]any
}

// NewJSONSubject returns a subject over one event reference.
func NewJSONSubject(ref json.RawMessage) *JSONSubject {
	s := &JSONSubject{}
	if err := json.Unmarshal(ref, &s.fields); err != nil {
		s.fields = nil
	}
	return s
}

// Value reads one field.
func (s *JSONSubject) Value(field string) FieldValue {
	v, ok := s.fields[field]
	if !ok || v == nil {
		return FieldValue{}
	}
	switch t := v.(type) {
	case string:
		return Text(t)
	case float64:
		return Number(t)
	case bool:
		return Text(strconv.FormatBool(t))
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return FieldValue{}
		}
		return Raw(b)
	}
}
