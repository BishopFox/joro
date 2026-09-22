package chain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/internal/httptools"
)

// maxValueLen bounds an extracted value. A source that matches a whole page body
// is a mistake in the rule, not a value worth injecting, and letting it through
// would put a megabyte into the next request.
const maxValueLen = 8 << 10

// Extract reads one value out of a live response.
//
// The empty string with a nil error is not possible: a source that matches
// nothing returns an error naming what it looked for, because "produced an empty
// value" and "did not fire" lead to completely different next actions and a run
// that conflates them cannot report an honest verdict.
func Extract(src Source, resp httptools.Response) (string, error) {
	var out string
	var err error

	switch src.Kind {
	case SourceHeader:
		out, err = extractHeader(src, resp)
	case SourceCookie:
		out, err = extractCookie(src, resp)
	case SourceJSON:
		out, err = extractJSON(src, resp)
	case SourceRegex:
		out, err = extractRegex(src, resp)
	case SourceBetween:
		out, err = extractBetween(src, resp)
	default:
		return "", fmt.Errorf("unknown source kind %q", src.Kind)
	}
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", fmt.Errorf("%s matched an empty value", describeSource(src))
	}
	if len(out) > maxValueLen {
		return "", fmt.Errorf("%s matched %d bytes, over the %d byte limit", describeSource(src), len(out), maxValueLen)
	}
	return out, nil
}

func extractHeader(src Source, resp httptools.Response) (string, error) {
	v := resp.Header.Get(src.Name)
	if v == "" {
		return "", fmt.Errorf("response has no %s header", src.Name)
	}
	return v, nil
}

// extractCookie reads a cookie by name from Set-Cookie.
//
// By name rather than by value, which is what lets a rotated session id still
// bind: the server issuing a different value for the same cookie is the normal
// case on a replay, not a failure.
func extractCookie(src Source, resp httptools.Response) (string, error) {
	want := strings.ToLower(strings.TrimSpace(src.Name))
	for _, sc := range resp.Header.Values("Set-Cookie") {
		name, val, ok := strings.Cut(sc, "=")
		if !ok {
			continue
		}
		if strings.ToLower(strings.TrimSpace(name)) != want {
			continue
		}
		// Trim attributes; the value ends at the first semicolon.
		val, _, _ = strings.Cut(val, ";")
		return strings.TrimSpace(val), nil
	}
	return "", fmt.Errorf("response set no %s cookie", src.Name)
}

// extractJSON walks a dotted path with optional [i] indices.
func extractJSON(src Source, resp httptools.Response) (string, error) {
	var doc any
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return "", fmt.Errorf("response body is not JSON: %v", err)
	}
	cur := doc
	for _, seg := range splitJSONPath(src.Path) {
		if idx, isIdx := strings.CutPrefix(seg, "["); isIdx {
			n, err := strconv.Atoi(strings.TrimSuffix(idx, "]"))
			if err != nil {
				return "", fmt.Errorf("bad index %q in path %s", seg, src.Path)
			}
			arr, ok := cur.([]any)
			if !ok {
				return "", fmt.Errorf("%s is not an array in path %s", seg, src.Path)
			}
			if n < 0 || n >= len(arr) {
				return "", fmt.Errorf("index %d out of range in path %s", n, src.Path)
			}
			cur = arr[n]
			continue
		}
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("%q is not an object in path %s", seg, src.Path)
		}
		cur, ok = obj[seg]
		if !ok {
			return "", fmt.Errorf("path %s has no %q", src.Path, seg)
		}
	}
	return jsonScalar(cur, src.Path)
}

// jsonScalar renders a leaf. A number is rendered the way it appeared rather than
// through %v, which would turn an id of 1000000 into 1e+06 and inject that.
func jsonScalar(v any, path string) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(t), nil
	case nil:
		return "", fmt.Errorf("path %s is null", path)
	default:
		return "", fmt.Errorf("path %s is not a scalar", path)
	}
}

// splitJSONPath turns "data.items[0].id" into ["data","items","[0]","id"].
func splitJSONPath(path string) []string {
	var out []string
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		for {
			before, rest, ok := strings.Cut(part, "[")
			if !ok {
				if before != "" {
					out = append(out, before)
				}
				break
			}
			if before != "" {
				out = append(out, before)
			}
			idx, after, ok := strings.Cut(rest, "]")
			if !ok {
				out = append(out, "["+rest+"]")
				break
			}
			out = append(out, "["+idx+"]")
			part = after
		}
	}
	return out
}

func extractRegex(src Source, resp httptools.Response) (string, error) {
	re, err := regexp.Compile(src.Expr)
	if err != nil {
		return "", fmt.Errorf("bad pattern: %v", err)
	}
	// Match over headers as well as body: a value is as likely to be in a
	// Location header as in the page.
	hay := append(append([]byte(nil), headerBytes(resp)...), resp.Body...)
	m := re.FindSubmatch(hay)
	if m == nil {
		return "", fmt.Errorf("pattern %s matched nothing", src.Expr)
	}
	g := src.Group
	if g == 0 && len(m) > 1 {
		// A pattern with a capture group almost always means the group, not the
		// whole match. Defaulting to 1 is what an operator writing (\w+) expects.
		g = 1
	}
	if g < 0 || g >= len(m) {
		return "", fmt.Errorf("pattern %s has no group %d", src.Expr, src.Group)
	}
	return string(m[g]), nil
}

func extractBetween(src Source, resp httptools.Response) (string, error) {
	hay := append(append([]byte(nil), headerBytes(resp)...), resp.Body...)
	s := string(hay)
	i := strings.Index(s, src.Prefix)
	if i < 0 {
		return "", fmt.Errorf("response does not contain %q", truncate(src.Prefix, 40))
	}
	rest := s[i+len(src.Prefix):]
	if src.Suffix == "" {
		return rest, nil
	}
	j := strings.Index(rest, src.Suffix)
	if j < 0 {
		return "", fmt.Errorf("no %q after %q", truncate(src.Suffix, 20), truncate(src.Prefix, 40))
	}
	return rest[:j], nil
}

// headerBytes re-serializes headers so regex and between sources can address
// them. Order is not stable across a map walk, which is fine: these two sources
// anchor on a literal, not on position.
func headerBytes(resp httptools.Response) []byte {
	var b strings.Builder
	for name, vals := range resp.Header {
		for _, v := range vals {
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// describeSource renders a source for an error message.
func describeSource(src Source) string {
	switch src.Kind {
	case SourceHeader:
		return "header " + src.Name
	case SourceCookie:
		return "cookie " + src.Name
	case SourceJSON:
		return "json path " + src.Path
	case SourceRegex:
		return "pattern " + truncate(src.Expr, 40)
	case SourceBetween:
		return fmt.Sprintf("text between %q and %q", truncate(src.Prefix, 20), truncate(src.Suffix, 20))
	}
	return src.Kind
}

// Describe renders a source for the UI, which needs the same string the error
// messages use so an operator reading a failure recognizes the rule it names.
func (s Source) Describe() string { return describeSource(s) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
