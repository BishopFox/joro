package detect

import (
	"bufio"
	"bytes"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/BishopFox/joro/internal/proxy"
)

// Message is a captured request/response pair decomposed into the buffers rules
// are matched against. Parse handles the raw-byte quirks so rules do not have to:
//
//   - RespRaw is Content-Length framed with a dechunked body (every capture
//     helper in internal/proxy clears TransferEncoding), but proxy hook plugins
//     can substitute their own bytes, so an LF-only header terminator is also
//     accepted.
//   - Bodies may arrive gzip- or deflate-encoded with Content-Encoding intact;
//     Parse decompresses them.
//   - Brotli and zstd bodies are marked unscannable and counted.
type Message struct {
	Req *proxy.CapturedRequest

	URL    *url.URL
	Scheme string
	Host   string
	Path   string

	RespStatus int
	RespHeader http.Header
	RespRawHdr []byte
	RespBody   []byte

	ReqHeader http.Header
	ReqRawHdr []byte
	ReqBody   []byte

	ContentType string

	// BodyScannable reports whether RespBody is worth matching against.
	BodyScannable bool
	// SkipReason explains why not: "binary", "encoding:br", "content-type",
	// "extension", "empty", or "no-response".
	SkipReason string
	// Truncated marks that a body hit a scan size cap, so findings from this
	// message cannot claim to be exhaustive.
	Truncated bool

	// RespBodyStart and ReqBodyStart are where each body begins inside the
	// corresponding raw document, used to turn a body-relative match offset into
	// an offset into the document the UI renders.
	RespBodyStart int
	ReqBodyStart  int
	// RespBodyDecoded records that the body was decompressed for scanning. RespBody
	// and RespRaw then share no coordinate system, so no body offset is reported.
	RespBodyDecoded bool

	// Case-folded copies for the Literal prescreen, built lazily per target. A
	// Message is scanned by one goroutine only, so this needs no synchronization.
	lowerCache map[Target][]byte
}

// headerSep and headerSepLF are the two header terminators Parse accepts.
var (
	headerSep   = []byte("\r\n\r\n")
	headerSepLF = []byte("\n\n")
)

// splitRawAt separates a raw HTTP dump into its header block and body, and
// reports where the body begins within the dump. Accepts both CRLF and LF
// header terminators, so bodyStart is len(hdr)+4 or len(hdr)+2 and must be used
// rather than assumed.
func splitRawAt(raw []byte) (hdr, body []byte, bodyStart int) {
	if i := bytes.Index(raw, headerSep); i >= 0 {
		return raw[:i], raw[i+len(headerSep):], i + len(headerSep)
	}
	if i := bytes.Index(raw, headerSepLF); i >= 0 {
		return raw[:i], raw[i+len(headerSepLF):], i + len(headerSepLF)
	}
	return raw, nil, len(raw)
}

// parseHeaderLines parses a header block whose first line is a request or status
// line, returning the parsed headers and that first line. Uses textproto, which
// handles folded continuation lines and canonicalizes key case.
func parseHeaderLines(block []byte) (http.Header, string) {
	if len(block) == 0 {
		return http.Header{}, ""
	}
	nl := bytes.IndexByte(block, '\n')
	first := block
	rest := []byte(nil)
	if nl >= 0 {
		first = bytes.TrimRight(block[:nl], "\r")
		rest = block[nl+1:]
	}
	if len(rest) == 0 {
		return http.Header{}, string(first)
	}
	// ReadMIMEHeader needs a blank line to terminate the header section.
	buf := make([]byte, 0, len(rest)+2)
	buf = append(buf, rest...)
	if !bytes.HasSuffix(buf, []byte("\n")) {
		buf = append(buf, '\r', '\n')
	}
	buf = append(buf, '\r', '\n')
	mh, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(buf))).ReadMIMEHeader()
	if err != nil && len(mh) == 0 {
		return http.Header{}, string(first)
	}
	return http.Header(mh), string(first)
}

// statusFromLine extracts the status code from a status line, accepting any
// HTTP version token (the h2 capture path synthesizes "HTTP/2 200 OK").
func statusFromLine(line string) int {
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return code
}

// ContentTypeKeywords lists everything ContentTypeKeyword can return, in the order a
// chooser should offer them. Beside the function so adding a branch there is visibly a
// change here too.
var ContentTypeKeywords = []string{"json", "html", "js", "xml", "css", "csv", "plain", "other"}

// ContentTypeKeyword maps a MIME type to the simplified keyword used by
// Rule.ContentTypes.
//
// Exported so a trigger condition on contentType means the same thing as a detect rule's
// gate on it. An operator learns one vocabulary and it holds wherever Joro asks them for
// a content type.
func ContentTypeKeyword(ct string) string {
	c := strings.ToLower(ct)
	switch {
	case strings.Contains(c, "json"):
		return "json"
	case strings.Contains(c, "text/html"), strings.Contains(c, "xhtml"):
		return "html"
	case strings.Contains(c, "javascript"), strings.Contains(c, "ecmascript"):
		return "js"
	case strings.Contains(c, "xml"):
		return "xml"
	case strings.Contains(c, "text/css"):
		return "css"
	case strings.Contains(c, "csv"):
		return "csv"
	case strings.Contains(c, "text/plain"), c == "":
		return "plain"
	case strings.Contains(c, "text/"):
		return "plain"
	default:
		return "other"
	}
}

// encodingSupported reports whether proxy.TryDecompress handles a
// Content-Encoding value. Anything else marks the body unscannable.
func encodingSupported(enc string) bool {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity", "gzip", "deflate", "x-gzip":
		return true
	}
	return false
}

// Parse decomposes a captured request into a Message, applying the
// false-positive and cost gates from cfg. It never returns nil.
func Parse(r *proxy.CapturedRequest, cfg Config) *Message {
	m := &Message{Req: r, Host: r.Host, ContentType: r.ContentType}

	if u, err := url.Parse(r.URL); err == nil && u != nil {
		m.URL = u
		m.Scheme = u.Scheme
		m.Path = u.Path
		if u.Host != "" {
			m.Host = u.Host
		}
	}
	if m.Scheme == "" {
		// CONNECT-tunnelled requests carry an absolute URL, so an empty scheme
		// means a plain-HTTP proxy request.
		m.Scheme = "http"
	}
	if m.Path == "" {
		m.Path = "/"
	}

	// Request side.
	if len(r.ReqRaw) > 0 {
		hdr, reqBody, reqStart := splitRawAt(r.ReqRaw)
		m.ReqRawHdr = hdr
		m.ReqBodyStart = reqStart
		m.ReqHeader, _ = parseHeaderLines(hdr)
		if cfg.ScanRequests {
			body := reqBody
			limit := cfg.MaxRequestBodyScanBytes
			if limit > 0 && len(body) > limit {
				body = body[:limit]
				m.Truncated = true
			}
			m.ReqBody = body
		}
	}

	// Response side.
	if len(r.RespRaw) == 0 {
		m.SkipReason = "no-response"
		return m
	}
	hdr, body, respStart := splitRawAt(r.RespRaw)
	m.RespRawHdr = hdr
	m.RespBodyStart = respStart
	m.RespHeader, m.RespStatus = func() (http.Header, int) {
		h, first := parseHeaderLines(hdr)
		return h, statusFromLine(first)
	}()
	if m.RespStatus == 0 {
		m.RespStatus = r.StatusCode
	}
	if m.ContentType == "" {
		m.ContentType = m.RespHeader.Get("Content-Type")
	}

	m.RespBody, m.BodyScannable, m.SkipReason, m.Truncated = prepareBody(m, body, cfg)
	return m
}

// prepareBody decompresses and gates a response body, returning the scannable
// bytes plus why they are not scannable when that is the case.
func prepareBody(m *Message, body []byte, cfg Config) (out []byte, ok bool, skip string, truncated bool) {
	if len(body) == 0 {
		return nil, false, "empty", false
	}

	if enc := m.RespHeader.Get("Content-Encoding"); !encodingSupported(enc) {
		return nil, false, "encoding:" + strings.ToLower(strings.TrimSpace(enc)), false
	} else if enc != "" {
		if decoded, didDecode := proxy.TryDecompress(enc, body); didDecode {
			body = decoded
			// Decoded bytes no longer correspond to anything in RespRaw, so offsets
			// into them are unmappable.
			m.RespBodyDecoded = true
		}
	}

	// Content-type gate.
	ctLower := strings.ToLower(m.ContentType)
	for _, prefix := range cfg.SkipContentTypes {
		if prefix != "" && strings.Contains(ctLower, prefix) {
			return nil, false, "content-type", false
		}
	}

	// Extension gate. cfg.SkipExtensions does not include .js or .css.
	if ext := pathExt(m.Path); ext != "" {
		for _, skipExt := range cfg.SkipExtensions {
			if strings.EqualFold(ext, skipExt) {
				return nil, false, "extension", false
			}
		}
	}

	// Size cap before the binary sniff so a huge binary is cheap to reject.
	if cfg.MaxBodyScanBytes > 0 && len(body) > cfg.MaxBodyScanBytes {
		body = body[:cfg.MaxBodyScanBytes]
		truncated = true
	}

	if isBinary(body) {
		return nil, false, "binary", truncated
	}
	return body, true, "", truncated
}

// pathExt returns the lowercase extension of a URL path, or "".
func pathExt(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	i := strings.LastIndexByte(p, '.')
	if i <= 0 {
		return ""
	}
	return strings.ToLower(p[i:])
}

// isBinary reports whether a body is not worth scanning as text, from a NUL
// byte in the first kilobyte or a failed UTF-8 check.
func isBinary(body []byte) bool {
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return true
	}
	detected := http.DetectContentType(head)
	switch {
	case strings.HasPrefix(detected, "text/"),
		strings.Contains(detected, "json"),
		strings.Contains(detected, "javascript"),
		strings.Contains(detected, "xml"):
		return false
	}
	return !utf8.Valid(head)
}

// haystack returns the buffer a target is matched against, or nil when the
// message has nothing for that target.
func (m *Message) haystack(t Target) []byte {
	switch t {
	case TargetResponseBody:
		if !m.BodyScannable {
			return nil
		}
		return m.RespBody
	case TargetResponseHeader:
		return m.RespRawHdr
	case TargetRequestHeader:
		return m.ReqRawHdr
	case TargetRequestBody:
		return m.ReqBody
	case TargetURL:
		if m.Req == nil {
			return nil
		}
		return []byte(m.Req.URL)
	}
	return nil
}

// absoluteOffset translates a match offset relative to one scanned buffer into
// an offset within the raw document the UI renders, plus that document's name.
// A body-relative offset is not an offset into the document, which also holds
// the status line, headers, and separator.
//
// ok is false when no faithful mapping exists (a decompressed body, or a URL
// match, which is not a slice of either document). Callers must then report no
// offset at all.
func (m *Message) absoluteOffset(in Target, rel int) (abs int, part string, ok bool) {
	switch in {
	case TargetResponseHeader:
		// The header block starts at byte 0 of the document.
		return rel, "response", true
	case TargetResponseBody:
		if m.RespBodyDecoded {
			return 0, "response", false
		}
		return m.RespBodyStart + rel, "response", true
	case TargetRequestHeader:
		return rel, "request", true
	case TargetRequestBody:
		return m.ReqBodyStart + rel, "request", true
	case TargetURL:
		// Not a slice of either document; naming the request pane lets the
		// client's text-search fallback find it in the request line.
		return 0, "request", false
	}
	return 0, "", false
}

// partName labels which buffer an offset indexes into.
func partName(t Target) string {
	switch t {
	case TargetRequestHeader, TargetRequestBody:
		return "request"
	case TargetURL:
		return "url"
	default:
		return "response"
	}
}

// lowerHaystack returns a case-folded copy of a target's buffer, cached per
// message. Used only by the Literal prescreen, which is case-insensitive.
func (m *Message) lowerHaystack(t Target) []byte {
	if m.lowerCache == nil {
		m.lowerCache = make(map[Target][]byte, 3)
	}
	if v, ok := m.lowerCache[t]; ok {
		return v
	}
	v := bytes.ToLower(m.haystack(t))
	m.lowerCache[t] = v
	return v
}

// SetCookies returns the raw Set-Cookie header values.
func (m *Message) SetCookies() []string {
	if m.RespHeader == nil {
		return nil
	}
	return m.RespHeader.Values("Set-Cookie")
}

// IsHTMLDocument reports whether the response is an HTML page. Document-level
// header analyzers (CSP, frame-options) gate on this.
func (m *Message) IsHTMLDocument() bool {
	if m.RespStatus < 200 || m.RespStatus >= 300 {
		return false
	}
	if len(m.RespBody) == 0 {
		return false
	}
	kw := ContentTypeKeyword(m.ContentType)
	return kw == "html"
}
