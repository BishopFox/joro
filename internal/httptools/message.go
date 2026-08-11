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

// contentType returns the message's Content-Type keyword.
func (m *message) contentType() string {
	if m == nil || m.Header == nil {
		return "-"
	}
	return contentTypeKeyword(m.Header.Get("Content-Type"))
}
