package httptools

import (
	"net/http"
	"strings"

	"github.com/BishopFox/joro/internal/proxy"
)

// message is one half of a captured exchange, split and optionally decompressed.
type message struct {
	Raw       []byte
	HdrRaw    []byte
	Body      []byte
	BodyStart int // offset of Body within Raw

	StartLine string
	Header    http.Header
	Status    int // responses only

	// Decoded names the content encoding that was unwrapped, or "" if none. Tools
	// surface it because a decoded length disagrees with the Content-Length the
	// client just read in the headers, and without an explanation that reads as a
	// bug and provokes a wasted follow-up call.
	Decoded string
}

// parseMessage splits raw bytes and, when decode is set, unwraps gzip or deflate.
//
// Bodies are not reliably plaintext here: TransportConfig sets DisableCompression
// and stripHopHeaders leaves Content-Encoding in place, so a captured body is
// whatever the origin sent. Brotli and zstd have no stdlib decoder, so those stay
// compressed and Decoded reports the encoding that was left alone.
func parseMessage(raw []byte, decode bool) *message {
	hdr, body, start := splitRaw(raw)
	line, h := parseHeaderBlock(hdr)
	m := &message{
		Raw:       raw,
		HdrRaw:    hdr,
		Body:      body,
		BodyStart: start,
		StartLine: line,
		Header:    h,
		Status:    statusFromLine(line),
	}
	if !decode || len(body) == 0 {
		return m
	}
	enc := strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding")))
	if enc == "" {
		return m
	}
	if out, ok := proxy.TryDecompress(enc, body); ok {
		m.Body = out
		m.Decoded = enc
	} else {
		// Unsupported encoding (br, zstd). Say so rather than presenting the
		// compressed bytes as if they were the content.
		m.Decoded = enc + " (not decoded)"
	}
	return m
}

// UpdateContentLength re-frames a raw request after its body has been rewritten.
//
// A pass-through to proxy.UpdateContentLength, exported here because this is the
// package that owns raw-request editing and every ApplyEdits caller has to follow
// with it — a body op that does not re-frame produces a request the origin reads
// as truncated, which looks exactly like the server rejecting it. Having it
// beside ApplyEdits is also what lets internal/chain render a step without
// importing internal/proxy, and so without acquiring a send path.
func UpdateContentLength(raw []byte) []byte { return proxy.UpdateContentLength(raw) }

// Response is a parsed, decoded response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte

	// Decoded names the content encoding that was unwrapped, or "" if none. It
	// carries the same "(not decoded)" suffix parseMessage uses for br and zstd.
	Decoded string
}

// ReadResponse parses and decompresses raw response bytes.
//
// Exported for the same reason FingerprintResponse is: a caller outside this
// package that needs to read a value out of a response would otherwise write a
// third copy of split-headers-then-maybe-gunzip, and the decode half is not
// obvious — TransportConfig sets DisableCompression and the proxy leaves
// Content-Encoding in place, so a captured body is whatever the origin sent.
// internal/chain uses this to resolve a chain's data dependencies, which is also
// how it stays free of any import that could open a socket.
func ReadResponse(raw []byte) Response {
	m := parseMessage(raw, true)
	return Response{
		Status:  m.Status,
		Header:  m.Header,
		Body:    m.Body,
		Decoded: m.Decoded,
	}
}

// contentType returns the message's Content-Type keyword.
func (m *message) contentType() string {
	if m == nil || m.Header == nil {
		return "-"
	}
	return contentTypeKeyword(m.Header.Get("Content-Type"))
}
