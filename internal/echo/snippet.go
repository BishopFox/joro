package echo

import (
	"bytes"
	"strings"
)

// Snippet bounds. A Reflection carries its snippet in capped slices but many of
// them, so the window is the budget: snippetPad bytes of context on each side,
// the whole window clamped to snippetMaxBytes. snippetMaxBytes mirrors detect's
// maxEvidenceBytes so the two evidence surfaces stay the same size.
const (
	snippetPad      = 80
	snippetMaxBytes = 256
)

// snippetWindow returns the raw byte range [lo, hi) of src to cut a snippet
// from, given the matched run [start, end). It pads each side, then expands
// outward to whole lines so the match reads with a line of context above and
// below, and clamps the window to snippetMaxBytes with the match kept. lo <=
// start and hi >= end always, except a match longer than the cap, whose head
// alone is returned.
func snippetWindow(src []byte, start, end int) (lo, hi int) {
	n := len(src)
	if start < 0 {
		start = 0
	}
	if end > n {
		end = n
	}
	if end < start {
		end = start
	}
	if end-start >= snippetMaxBytes {
		hi = min(start+snippetMaxBytes, n)
		return start, hi
	}

	lo0 := max(start-snippetPad, 0)
	hi0 := min(end+snippetPad, n)
	// Expand to the line lo0 falls in and the line hi0 falls in, so a context
	// line survives on each side rather than collapsing to the match's own line.
	lo = 0
	if nl := bytes.LastIndexByte(src[:lo0], '\n'); nl >= 0 {
		lo = nl + 1
	}
	hi = n
	if nl := bytes.IndexByte(src[hi0:], '\n'); nl >= 0 {
		hi = hi0 + nl
	}

	// Clamp to the byte cap, trimming context toward the match (a single line
	// longer than the budget is cut mid-way; the viewer wraps it).
	avail := snippetMaxBytes - (end - start)
	if start-lo > avail/2 {
		lo = start - avail/2
	}
	if hi-end > avail-avail/2 {
		hi = end + (avail - avail/2)
	}
	return lo, hi
}

// sanitizeSnippet renders a response slice for display. It keeps newlines and
// tabs so the window reads as the two or three lines around the match, drops
// lone carriage returns (the newline alone breaks the line), and escapes other
// control bytes to \xNN. Unlike detect's sanitizeEvidence it never truncates:
// the three parts of a snippet are sanitized separately so the match offsets
// stay exact, and snippetWindow has already bounded the raw input.
func sanitizeSnippet(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, r := range string(b) {
		switch {
		case r == '\n' || r == '\t':
			sb.WriteRune(r)
		case r == '\r':
			// Dropped: a CRLF still breaks at the newline.
		case r < 0x20 || r == 0x7f:
			const hexDigits = "0123456789abcdef"
			sb.WriteString("\\x")
			sb.WriteByte(hexDigits[(r>>4)&0xf])
			sb.WriteByte(hexDigits[r&0xf])
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// buildSnippet cuts a display snippet from src around the matched run
// [start, end) and returns it with the match located inside it. The match may
// be clamped when it is longer than the cap; the caller's stored Span is
// unaffected because that indexes the document, not the snippet.
func buildSnippet(src []byte, start, end int) (string, Span) {
	lo, hi := snippetWindow(src, start, end)
	mEnd := min(end, hi)
	pre := sanitizeSnippet(src[lo:start])
	mid := sanitizeSnippet(src[start:mEnd])
	suf := sanitizeSnippet(src[mEnd:hi])
	return pre + mid + suf, Span{Start: len(pre), End: len(pre) + len(mid)}
}
