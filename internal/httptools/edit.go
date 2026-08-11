package httptools

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Edit is one structural change to a captured request.
//
// Edits are structural rather than "here is the whole new request" for two
// reasons. Shipping a full request back costs hundreds to thousands of tokens per
// attempt, and — more importantly — a model retyping a raw request will eventually
// corrupt a byte. A mangled Cookie or a dropped header turns a negative result into
// a false negative, which is the worst outcome in a security test because it reads
// as "not vulnerable". A setHeader op is about twenty-five tokens and cannot
// corrupt anything it does not name.
type Edit struct {
	Op    string `json:"op"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
	Find  string `json:"find,omitempty"`
	Regex bool   `json:"regex,omitempty"`
	All   bool   `json:"all,omitempty"`
	Count int    `json:"count,omitempty"`
}

// EditOps enumerates the supported operations, for the tool schema and for the
// error message when a client invents one.
//
// setVersion is deliberately absent: automation sends go through Joro's own proxy
// over HTTP/1.1, so there is no version for a client to choose. See proxysend.go.
var EditOps = []string{
	"setHeader", "addHeader", "removeHeader",
	"setMethod", "setPath", "setQuery", "removeQuery", "setRequestTarget",
	"replaceInBody", "setBody",
}

// ApplyEdits rewrites raw request bytes.
//
// The discipline mirrors internal/proxy/replace.go: split at the header
// terminator, rebuild the header block with canonical CRLF, and leave body bytes
// untouched unless a body op ran. Header names match case-insensitively and
// original ordering is preserved, with new headers appended at the end of the
// block so Host stays first — some servers care.
func ApplyEdits(raw []byte, edits []Edit) ([]byte, error) {
	hdrRaw, body, _ := splitRaw(raw)
	lines := splitHeaderLines(hdrRaw)
	if len(lines) == 0 {
		return nil, fmt.Errorf("request has no start line")
	}
	start := lines[0]
	headers := lines[1:]

	for i, e := range edits {
		var err error
		switch e.Op {
		case "setHeader":
			headers, err = setHeader(headers, e.Name, e.Value)
		case "addHeader":
			if err = requireName(e); err == nil {
				headers = append(headers, e.Name+": "+e.Value)
			}
		case "removeHeader":
			headers, err = removeHeader(headers, e.Name)
		case "setMethod":
			start, err = editStartLine(start, func(_, target, ver string) (string, string, string) {
				return e.Value, target, ver
			})
		case "setPath":
			start, err = editStartLine(start, func(m, target, ver string) (string, string, string) {
				return m, replacePath(target, e.Value), ver
			})
		case "setQuery":
			start, err = editStartLine(start, func(m, target, ver string) (string, string, string) {
				return m, setQueryParam(target, e.Name, e.Value), ver
			})
		case "removeQuery":
			start, err = editStartLine(start, func(m, target, ver string) (string, string, string) {
				return m, removeQueryParam(target, e.Name), ver
			})
		case "setRequestTarget":
			start, err = editStartLine(start, func(m, _, ver string) (string, string, string) {
				return m, e.Value, ver
			})
		case "replaceInBody":
			body, err = replaceInBody(body, e)
		case "setBody":
			body = []byte(e.Value)
		default:
			err = fmt.Errorf("unknown op %q (supported: %s)", e.Op, strings.Join(EditOps, ", "))
		}
		if err != nil {
			return nil, fmt.Errorf("edit %d (%s): %w", i, e.Op, err)
		}
	}
	var out bytes.Buffer
	out.WriteString(start)
	out.WriteString("\r\n")
	for _, h := range headers {
		if strings.TrimSpace(h) == "" {
			continue
		}
		out.WriteString(h)
		out.WriteString("\r\n")
	}
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes(), nil
}

func requireName(e Edit) error {
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

func splitHeaderLines(hdr []byte) []string {
	s := strings.ReplaceAll(string(hdr), "\r\n", "\n")
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func headerNameOf(line string) string {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(line[:i]))
}

// setHeader replaces the first occurrence in place, keeping position, and removes
// any duplicates. Appends when absent.
func setHeader(headers []string, name, value string) ([]string, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	want := strings.ToLower(strings.TrimSpace(name))
	out := make([]string, 0, len(headers)+1)
	replaced := false
	for _, h := range headers {
		if headerNameOf(h) == want {
			if replaced {
				continue
			}
			out = append(out, name+": "+value)
			replaced = true
			continue
		}
		out = append(out, h)
	}
	if !replaced {
		out = append(out, name+": "+value)
	}
	return out, nil
}

func removeHeader(headers []string, name string) ([]string, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	want := strings.ToLower(strings.TrimSpace(name))
	out := headers[:0:0]
	for _, h := range headers {
		if headerNameOf(h) != want {
			out = append(out, h)
		}
	}
	return out, nil
}

// editStartLine applies fn to the three tokens of the request line and rejoins.
// The line is never regexed: a request target may contain almost anything, and a
// pattern over it is how a request gets silently mangled.
func editStartLine(line string, fn func(method, target, version string) (string, string, string)) (string, error) {
	method, target, version, ok := requestLine(line)
	if !ok {
		return "", fmt.Errorf("could not parse request line %q", line)
	}
	m, t, v := fn(method, target, version)
	if strings.TrimSpace(m) == "" || strings.TrimSpace(t) == "" {
		return "", fmt.Errorf("edit produced an empty method or target")
	}
	return m + " " + t + " " + v, nil
}

// replacePath swaps the path while preserving the query string.
func replacePath(target, newPath string) string {
	if newPath == "" {
		return target
	}
	if !strings.HasPrefix(newPath, "/") {
		newPath = "/" + newPath
	}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return newPath + target[i:]
	}
	return newPath
}

func splitTarget(target string) (path, query string) {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i], target[i+1:]
	}
	return target, ""
}

func setQueryParam(target, name, value string) string {
	if name == "" {
		return target
	}
	path, query := splitTarget(target)
	vals, err := url.ParseQuery(query)
	if err != nil {
		vals = url.Values{}
	}
	vals.Set(name, value)
	if enc := vals.Encode(); enc != "" {
		return path + "?" + enc
	}
	return path
}

func removeQueryParam(target, name string) string {
	if name == "" {
		return target
	}
	path, query := splitTarget(target)
	vals, err := url.ParseQuery(query)
	if err != nil {
		return target
	}
	vals.Del(name)
	if enc := vals.Encode(); enc != "" {
		return path + "?" + enc
	}
	return path
}

func replaceInBody(body []byte, e Edit) ([]byte, error) {
	if e.Find == "" {
		return nil, fmt.Errorf("find is required")
	}
	n := e.Count
	if e.All || n <= 0 {
		n = -1
	}
	if e.Regex {
		re, err := regexp.Compile(e.Find)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		if n < 0 {
			return re.ReplaceAllLiteral(body, []byte(e.Value)), nil
		}
		count := 0
		return re.ReplaceAllFunc(body, func(m []byte) []byte {
			if count >= n {
				return m
			}
			count++
			return []byte(e.Value)
		}), nil
	}
	return bytes.Replace(body, []byte(e.Find), []byte(e.Value), n), nil
}
