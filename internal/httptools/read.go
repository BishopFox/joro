package httptools

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Read caps. The default is small on purpose: 16 KB of text is already four to six
// thousand tokens, and a client that needs more should say so a window at a time
// rather than have the tool guess.
const (
	DefaultReadLength = 2048
	MaxReadLength     = 16384
	// maxHexBytes gates the hex rendering. A hex dump costs roughly four times the
	// tokens of the bytes it shows, so past this size base64 is the honest choice
	// even though it is useless to reason over.
	maxHexBytes = 512
)

// ReadArgs is the argument shape of http.read.
type ReadArgs struct {
	Seq      int    `json:"seq" alias:"ref"`
	Part     string `json:"part"`     // req | resp
	Section  string `json:"section"`  // headers | body | raw
	Offset   int    `json:"offset"`   // negative reads from the end
	Length   int    `json:"length"`   //
	Decode   *bool  `json:"decode"`   // default true
	Encoding string `json:"encoding"` // auto | text | hex | base64
}

// ReadResult is the structured half of a read, and the value the JavaScript SDK
// returns: a script reads r.text and branches on r.truncated rather than parsing
// anything. An MCP client receives Render's text instead, chosen at that boundary.
// The two forms are never both sent — text may be 16 KB, and duplicating it as
// structuredContent would double the cost of every read.
type ReadResult struct {
	Seq         int    `json:"seq"`
	Part        string `json:"part"`
	Section     string `json:"section"`
	Encoding    string `json:"encoding"`
	TotalLength int    `json:"totalLength"`
	Offset      int    `json:"offset"`
	Returned    int    `json:"returned"`
	Truncated   bool   `json:"truncated"`
	Decoded     string `json:"decoded,omitempty"`
	Text        string `json:"text"`

	// Redacted names the withheld header values that lie inside the returned
	// window, and only those: naming one the caller did not receive implies a
	// credential the returned bytes never carried.
	Redacted []string `json:"redacted,omitempty"`
}

// ReadRange extracts a byte window from a captured request or response.
//
// Coordinates are bytes of the selected section after decoding. section "raw" is
// the whole dump with decoding forced off, so it stays byte-exact and matches the
// contract of the History Raw tab.
//
// maskCredentials withholds sensitive header values. It is applied to the half that
// is actually returned, never to both, so the redaction notice cannot name a header
// the other half carried.
func ReadRange(reqRaw, respRaw []byte, args ReadArgs, maskCredentials bool) (*ReadResult, error) {
	part := strings.ToLower(strings.TrimSpace(args.Part))
	if part == "" {
		part = "resp"
	}
	section := strings.ToLower(strings.TrimSpace(args.Section))
	if section == "" {
		section = "body"
	}

	var raw []byte
	switch part {
	case "req":
		raw = reqRaw
	case "resp":
		raw = respRaw
	default:
		return nil, fmt.Errorf(`part must be "req" or "resp", got %q`, args.Part)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("no %s bytes were captured for request %d", part, args.Seq)
	}

	var spans []maskSpan
	if maskCredentials {
		raw, spans = maskHeaderSpans(raw)
	}

	// Raw stays byte-exact: decoding it would make offsets disagree with what the
	// History Raw tab shows for the same request.
	decode := args.Decode == nil || *args.Decode
	if section == "raw" {
		decode = false
	}
	m := parseMessage(raw, decode)

	var sel []byte
	switch section {
	case "headers":
		sel = m.HdrRaw
	case "body":
		sel = m.Body
	case "raw":
		sel = m.Raw
	default:
		return nil, fmt.Errorf(`section must be "headers", "body" or "raw", got %q`, args.Section)
	}

	total := len(sel)
	length := args.Length
	if length <= 0 {
		length = DefaultReadLength
	}
	length = min(length, MaxReadLength)

	// A negative offset reads from the end. Without it, "what does the bottom of
	// the error page say" costs a round trip purely to learn the total length.
	start := args.Offset
	if start < 0 {
		start = max(0, total+start)
	}
	if start > total {
		start = total
	}
	end := min(start+length, total)
	window := sel[start:end]

	res := &ReadResult{
		Seq:         args.Seq,
		Part:        part,
		Section:     section,
		TotalLength: total,
		Offset:      start,
		Returned:    len(window),
		Truncated:   end < total,
		Decoded:     m.Decoded,
	}
	res.Encoding, res.Text = encodeWindow(window, args.Encoding, start)

	switch section {
	case "headers", "raw":
		// Both share the raw message's coordinates — the header block is its
		// prefix, and raw is decoded-off — so a span compares to the window directly.
		res.Redacted = namesInRange(spans, start, end)
	case "body":
		// Only header values are ever withheld, so a body window holds none.
	}
	return res, nil
}

// encodeWindow picks a rendering for the selected bytes.
func encodeWindow(window []byte, want string, baseOffset int) (encoding, text string) {
	switch strings.ToLower(strings.TrimSpace(want)) {
	case "text":
		return "text", string(window)
	case "hex":
		return "hex", hexDump(window, baseOffset)
	case "base64":
		return "base64", base64.StdEncoding.EncodeToString(window)
	}
	switch {
	case looksText(window):
		return "text", string(window)
	case len(window) <= maxHexBytes:
		return "hex", hexDump(window, baseOffset)
	default:
		return "base64", base64.StdEncoding.EncodeToString(window)
	}
}

// Render produces the text form: exactly one meta line, then the window, then any
// notes. The bytes begin immediately after the first '\n' and nothing is ever
// inserted ahead of them.
//
// The fixed preamble is the point. A note above the window makes the offset of the
// first payload byte depend on whether that note fired, and the framing changes from
// '\n' to '\r\n' at the same boundary — so a reader taking the first line gets the
// meta line, a note and the request line welded together, with nothing in the output
// to say which shape arrived.
//
// The meta line always names decoded when an encoding was unwrapped, because a
// decoded total disagrees with the Content-Length the client just read in the
// headers, and an unexplained mismatch reads as a bug. It names redacted for the same
// reason a note does: a withheld value the reader has not been told about is a
// credential it will report as absent.
func (r *ReadResult) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "seq=%d part=%s section=%s enc=%s total=%d off=%d ret=%d truncated=%t",
		r.Seq, r.Part, r.Section, r.Encoding, r.TotalLength, r.Offset, r.Returned, r.Truncated)
	if r.Decoded != "" {
		fmt.Fprintf(&b, " decoded=%s", r.Decoded)
	}
	if len(r.Redacted) > 0 {
		fmt.Fprintf(&b, " redacted=%s", strings.Join(r.Redacted, ","))
	}
	b.WriteByte('\n')
	b.WriteString(r.Text)
	if r.Truncated {
		// Truncation must always name the way to get the rest, or the client
		// simply retries the identical call.
		fmt.Fprintf(&b, "\n[truncated: %d of %d bytes. Continue with offset=%d]",
			r.Returned, r.TotalLength, r.Offset+r.Returned)
	}
	// Last, so the prose is the final thing read: what it warns against is a masked
	// header being reported as one the target never sent.
	if note := RedactionNote(r.Redacted); note != "" {
		b.WriteByte('\n')
		b.WriteString(note)
	}
	return b.String()
}
