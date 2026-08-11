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

// MaskHeaders overwrites the values of sensitive headers with '*', leaving header
// names, framing and every byte offset unchanged, and returns the names it masked.
//
// Masking is length-preserving because http.read reports offsets and totalLength
// against the same coordinates the History Raw tab uses; a shorter placeholder
// would shift every subsequent offset and desynchronize http.read from http.search.
func MaskHeaders(raw []byte) (masked []byte, names []string) {
	if len(raw) == 0 {
		return raw, nil
	}
	hdr, _, _ := splitRaw(raw)
	if len(hdr) == 0 {
		return raw, nil
	}

	out := bytes.Clone(raw)
	seen := map[string]bool{}
	folding := false

	for i := 0; i < len(hdr); {
		end := bytes.IndexByte(hdr[i:], '\n')
		if end < 0 {
			end = len(hdr)
		} else {
			end += i
		}
		line := out[i:end]
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}

		switch {
		case len(line) == 0:
			folding = false
		case line[0] == ' ' || line[0] == '\t':
			// Obsolete line folding: the continuation belongs to the previous header.
			if folding {
				maskRange(line)
			}
		default:
			folding = false
			if c := bytes.IndexByte(line, ':'); c > 0 {
				name := strings.ToLower(strings.TrimSpace(string(line[:c])))
				if sensitiveHeaders[name] {
					maskRange(line[c+1:])
					folding = true
					if !seen[name] {
						seen[name] = true
						names = append(names, name)
					}
				}
			}
		}
		i = end + 1
	}

	if len(names) == 0 {
		return raw, nil
	}
	slices.Sort(names)
	return out, names
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

// MaskPair masks both halves of a captured exchange, returning the union of the
// names masked in either.
func MaskPair(reqRaw, respRaw []byte) (req, resp []byte, names []string) {
	req, a := MaskHeaders(reqRaw)
	resp, b := MaskHeaders(respRaw)
	return req, resp, mergeNames(a, b)
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
