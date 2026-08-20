package httptools

import (
	"bytes"
	"slices"
	"strings"
)

// sensitiveHeaders have their values withheld from automation clients that were
// not granted credential visibility. Shared by MaskHeaders and http.diff.
var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true,
	"cookie": true, "set-cookie": true,
	"x-api-key": true, "x-auth-token": true,
	"x-csrf-token": true, "x-xsrf-token": true,
}

// maskByte replaces each byte of a withheld header value.
const maskByte = '*'

// maskSpan is one withheld header value's byte range within the raw message.
// Coordinates are raw-message coordinates, so a span is directly comparable to a
// window read from the header block or from section "raw".
type maskSpan struct {
	name       string
	start, end int
}

// MaskHeaders overwrites the values of sensitive headers with '*', leaving header
// names, framing and every byte offset unchanged, and returns the names it masked.
func MaskHeaders(raw []byte) (masked []byte, names []string) {
	out, spans := maskHeaderSpans(raw)
	return out, spanNames(spans)
}

// maskHeaderSpans masks sensitive header values and reports where each withheld
// value sits, so a caller returning only part of the message can announce the
// values that part actually contains.
//
// Masking is length-preserving because http.read reports offsets and totalLength
// against the same coordinates the History Raw tab uses; a shorter placeholder
// would shift every subsequent offset and desynchronize http.read from http.search.
func maskHeaderSpans(raw []byte) (masked []byte, spans []maskSpan) {
	if len(raw) == 0 {
		return raw, nil
	}
	hdr, _, _ := splitRaw(raw)
	if len(hdr) == 0 {
		return raw, nil
	}

	out := bytes.Clone(raw)
	folding := ""

	for i := 0; i < len(hdr); {
		end := bytes.IndexByte(hdr[i:], '\n')
		if end < 0 {
			end = len(hdr)
		} else {
			end += i
		}
		line := out[i:end]
		lineEnd := end
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
			lineEnd--
		}

		switch {
		case len(line) == 0:
			folding = ""
		case line[0] == ' ' || line[0] == '\t':
			// Obsolete line folding: the continuation belongs to the previous header.
			if folding != "" {
				maskRange(line)
				spans = append(spans, maskSpan{folding, i, lineEnd})
			}
		default:
			folding = ""
			if c := bytes.IndexByte(line, ':'); c > 0 {
				name := strings.ToLower(strings.TrimSpace(string(line[:c])))
				if sensitiveHeaders[name] {
					maskRange(line[c+1:])
					folding = name
					spans = append(spans, maskSpan{name, i + c + 1, lineEnd})
				}
			}
		}
		i = end + 1
	}

	if len(spans) == 0 {
		return raw, nil
	}
	return out, spans
}

// maskRange overwrites v in place, preserving leading whitespace so the header
// still parses.
func maskRange(v []byte) {
	for i := range v {
		if i == 0 && (v[i] == ' ' || v[i] == '\t') {
			continue
		}
		v[i] = maskByte
	}
}

// RedactionNote is the line appended to any output whose bytes were masked. Without
// it a masked Authorization header reads as an absent one, which is how an agent
// reports an authenticated endpoint as unauthenticated.
func RedactionNote(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return "redacted: " + strings.Join(names, ", ") +
		" (values withheld; this token does not have credential visibility)"
}

// spanNames collects the distinct names of every span, sorted.
func spanNames(spans []maskSpan) []string {
	if len(spans) == 0 {
		return nil
	}
	names := make([]string, 0, len(spans))
	for _, s := range spans {
		names = append(names, s.name)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// namesInRange returns the masked header names whose withheld bytes fall inside
// [start,end) of the raw message. Names outside the window are not announced: a
// redaction notice for bytes the caller never received reads as a credential the
// returned half actually carried, which is how a response with no Set-Cookie gets
// reported as having set a session cookie.
func namesInRange(spans []maskSpan, start, end int) []string {
	var hit []maskSpan
	for _, s := range spans {
		if s.start < end && s.end > start {
			hit = append(hit, s)
		}
	}
	return spanNames(hit)
}

func mergeNames(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	return slices.Compact(out)
}
