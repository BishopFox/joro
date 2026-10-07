// Package inject is the shared scaffold for the active injection-scanning rules
// (reflected XSS, SQLi, SSTI, command injection, open redirect, path traversal).
// It enumerates a request's injectable parameters, mutates one with a payload,
// sends the result through Joro's proxy, and exposes baseline/differential/timing
// and OAST helpers — so each rule is just a payload set plus a detector.
//
// Enumeration reuses internal/echo (the one parameter walker in the repo);
// mutation is name-aware per source (query/form/json/path) rather than relying on
// byte offsets, which echo computes only best-effort.
package inject

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/echo"
	"github.com/BishopFox/joro/internal/httptools"
	"github.com/BishopFox/joro/internal/proxy"
)

// Point is an injectable parameter. It aliases echo.Value so rules speak echo's
// vocabulary (Source, Name, Value) without re-deriving it.
type Point = echo.Value

// Enumerate returns the injectable parameters of a raw request: query, path, form
// and JSON-body values. Headers, cookies and multipart parts are deliberately
// excluded to bound scan volume to the parameters that carry most injection.
func Enumerate(raw []byte) []Point {
	if len(raw) == 0 {
		return nil
	}
	// detect.Parse derives the URL/host/content-type from the CapturedRequest's
	// fields, not the raw request line, so reconstruct them from the bytes.
	host := headerValue(raw, "Host")
	cr := &proxy.CapturedRequest{
		ReqRaw:      raw,
		Host:        host,
		URL:         reconstructURL(raw, host),
		ContentType: headerValue(raw, "Content-Type"),
	}
	cfg := echo.DefaultConfig()
	cfg.ScanHeaders = false // skip headers/cookies for injection fuzzing
	vals := echo.Walk(detect.Parse(cr, echo.ParseConfig(cfg)), cfg)
	out := vals[:0:0]
	for _, v := range vals {
		switch v.Source {
		case echo.SourceQuery, echo.SourcePath, echo.SourceForm, echo.SourceJSON:
			out = append(out, v)
		}
	}
	return out
}

// Mutate produces a copy of raw with point p's value set to payload (or, when
// appendMode, the original value followed by payload). Content-Length is
// recomputed. An unsupported source returns an error so the caller skips the point.
func Mutate(raw []byte, p Point, payload string, appendMode bool) ([]byte, error) {
	value := payload
	if appendMode {
		value = p.Value + payload
	}
	var out []byte
	var err error
	switch p.Source {
	case echo.SourceQuery:
		out, err = httptools.ApplyEdits(raw, []httptools.Edit{{Op: "setQuery", Name: p.Name, Value: value}})
	case echo.SourcePath:
		out, err = setPathSegment(raw, p.Name, value)
	case echo.SourceForm:
		out, err = setFormField(raw, p.Name, value)
	case echo.SourceJSON:
		out, err = setJSONField(raw, p.Name, value)
	default:
		return nil, fmt.Errorf("inject: unsupported source %q", p.Source)
	}
	if err != nil {
		return nil, err
	}
	return httptools.UpdateContentLength(out), nil
}

// splitRequest separates the header block (through the blank line) from the body.
func splitRequest(raw []byte) (head, body []byte) {
	if i := strings.Index(string(raw), "\r\n\r\n"); i >= 0 {
		return raw[:i+4], raw[i+4:]
	}
	if i := strings.Index(string(raw), "\n\n"); i >= 0 {
		return raw[:i+2], raw[i+2:]
	}
	return raw, nil
}

// setFormField re-encodes a urlencoded body with one field changed.
func setFormField(raw []byte, name, value string) ([]byte, error) {
	head, body := splitRequest(raw)
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	vals.Set(name, value)
	return append(append([]byte(nil), head...), []byte(vals.Encode())...), nil
}

// setPathSegment replaces the i-th path segment (echo names path values "[i]").
func setPathSegment(raw []byte, name, value string) ([]byte, error) {
	idx, err := strconv.Atoi(strings.Trim(name, "[]"))
	if err != nil {
		return nil, fmt.Errorf("inject: bad path index %q", name)
	}
	line, rest, ok := firstLine(raw)
	if !ok {
		return nil, fmt.Errorf("inject: no request line")
	}
	method, target, version, ok := splitRequestLine(line)
	if !ok {
		return nil, fmt.Errorf("inject: bad request line")
	}
	path, query := target, ""
	if q := strings.IndexByte(target, '?'); q >= 0 {
		path, query = target[:q], target[q:]
	}
	segs := strings.Split(path, "/") // leading "" from the leading slash
	seg := idx + 1                   // echo indexes segments after the leading slash
	if seg <= 0 || seg >= len(segs) {
		return nil, fmt.Errorf("inject: path index %d out of range", idx)
	}
	segs[seg] = url.PathEscape(value)
	newLine := method + " " + strings.Join(segs, "/") + query + " " + version
	return append([]byte(newLine), rest...), nil
}

// setJSONField sets a leaf addressed by a dotted path with [i] indices.
func setJSONField(raw []byte, path, value string) ([]byte, error) {
	head, body := splitRequest(raw)
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if err := setJSONPath(&doc, splitJSONPath(path), value); err != nil {
		return nil, err
	}
	nb, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), head...), nb...), nil
}

// splitJSONPath breaks "a.b[0].c" into ["a","b","0","c"].
func splitJSONPath(p string) []string {
	var out []string
	for _, part := range strings.Split(p, ".") {
		for {
			b := strings.IndexByte(part, '[')
			if b < 0 {
				if part != "" {
					out = append(out, part)
				}
				break
			}
			if b > 0 {
				out = append(out, part[:b])
			}
			e := strings.IndexByte(part, ']')
			if e < 0 {
				break
			}
			out = append(out, part[b+1:e])
			part = part[e+1:]
		}
	}
	return out
}

// setJSONPath walks segs into the decoded doc and sets the leaf to value (as a
// string, matching how the application most commonly receives injected input).
func setJSONPath(doc *any, segs []string, value string) error {
	if len(segs) == 0 {
		*doc = value
		return nil
	}
	seg := segs[0]
	switch node := (*doc).(type) {
	case map[string]any:
		child := node[seg]
		if err := setJSONPath(&child, segs[1:], value); err != nil {
			return err
		}
		node[seg] = child
		return nil
	case []any:
		i, err := strconv.Atoi(seg)
		if err != nil || i < 0 || i >= len(node) {
			return fmt.Errorf("inject: bad json index %q", seg)
		}
		child := node[i]
		if err := setJSONPath(&child, segs[1:], value); err != nil {
			return err
		}
		node[i] = child
		return nil
	default:
		return fmt.Errorf("inject: json path does not resolve at %q", seg)
	}
}

// reconstructURL builds an absolute URL from the request line's target and the Host
// header, so detect.Parse can extract the path and query. The scheme is irrelevant
// to parameter enumeration.
func reconstructURL(raw []byte, host string) string {
	line, _, ok := firstLine(raw)
	if !ok {
		return ""
	}
	_, target, _, ok := splitRequestLine(line)
	if !ok {
		return ""
	}
	if host == "" {
		host = "placeholder"
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return target
	}
	return "http://" + host + target
}

// headerValue returns the first value of header name (case-insensitive) from the
// request's header block.
func headerValue(raw []byte, name string) string {
	head, _ := splitRequest(raw)
	lower := strings.ToLower(name) + ":"
	for _, ln := range strings.Split(string(head), "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.HasPrefix(strings.ToLower(ln), lower) {
			return strings.TrimSpace(ln[len(lower):])
		}
	}
	return ""
}

func firstLine(raw []byte) (line string, rest []byte, ok bool) {
	i := strings.IndexByte(string(raw), '\n')
	if i < 0 {
		return "", nil, false
	}
	line = strings.TrimRight(string(raw[:i]), "\r")
	return line, raw[i:], true
}

func splitRequestLine(line string) (method, target, version string, ok bool) {
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
