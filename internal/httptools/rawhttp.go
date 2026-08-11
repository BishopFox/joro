// Package httptools implements the token-efficient HTTP capabilities Joro exposes
// to automation clients.
//
// The premise is that a 500 KB response body costs a language model on the order of
// 140,000 tokens to read, which is both expensive and worse at the task than a
// summary would be. So no tool here returns a full body by default: they return
// fingerprints, byte ranges, match offsets with context, and diffs. Every one caps
// its own output at a row, hunk or match boundary and says how to get the rest,
// which keeps the output usable rather than merely small — the registry's output
// cap is a blunt backstop behind that, not the primary mechanism.
//
// This package holds pure logic. It knows nothing about HTTP servers or MCP; the
// capability wrappers live in internal/capreg.
package httptools

import (
	"bufio"
	"bytes"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

// headerSepCRLF and headerSepLF are the two header/body separators seen in the
// wild. Captured dumps use CRLF, but an edited request may arrive with bare LF.
var (
	headerSepCRLF = []byte("\r\n\r\n")
	headerSepLF   = []byte("\n\n")
)

// splitRaw separates a raw HTTP dump into its header block and body, and reports
// the byte offset at which the body starts.
//
// This deliberately duplicates the unexported detect.splitRawAt rather than
// exporting it. detect.Parse looks like the obvious reuse, but its gating is tuned
// for the rule engine and is actively wrong here: SkipContentTypes would refuse to
// read an image or an application/octet-stream body — exactly when a hex window is
// most useful — MaxBodyScanBytes truncates with no way to report it in this
// package's terms, and ReqBody is only populated when ScanRequests is set. Taking
// the export instead would also drag the 167-rule engine into this package's
// dependency graph for two helpers. Cross-referenced in internal/detect/parse.go.
//
// When no separator is found the whole input is treated as headers, which is the
// right reading of a truncated capture: there is no body to point at.
func splitRaw(raw []byte) (hdr, body []byte, bodyStart int) {
	if i := bytes.Index(raw, headerSepCRLF); i >= 0 {
		// A bare-LF separator earlier in the buffer wins, matching how
		// UpdateContentLength picks whichever terminator appears first.
		if j := bytes.Index(raw, headerSepLF); j >= 0 && j < i {
			return raw[:j], raw[j+2:], j + 2
		}
		return raw[:i], raw[i+4:], i + 4
	}
	if j := bytes.Index(raw, headerSepLF); j >= 0 {
		return raw[:j], raw[j+2:], j + 2
	}
	return raw, nil, len(raw)
}

// parseHeaderBlock parses a header block into an http.Header, returning the start
// line separately. Malformed lines are skipped rather than failing the parse — a
// capture of a nonconforming server should still be readable.
func parseHeaderBlock(hdr []byte) (startLine string, h http.Header) {
	h = make(http.Header)
	if len(hdr) == 0 {
		return "", h
	}
	// textproto needs a trailing blank line to terminate the header section.
	buf := make([]byte, 0, len(hdr)+2)
	buf = append(buf, hdr...)
	buf = append(buf, '\r', '\n', '\r', '\n')

	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(buf)))
	line, err := r.ReadLine()
	if err != nil {
		return "", h
	}
	startLine = line
	mh, err := r.ReadMIMEHeader()
	if err != nil && len(mh) == 0 {
		return startLine, h
	}
	return startLine, http.Header(mh)
}

// statusFromLine pulls the status code out of a response start line
// ("HTTP/1.1 404 Not Found"). Returns 0 when the line is not a status line.
func statusFromLine(line string) int {
	parts := strings.Fields(line)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}
	return code
}

// requestLine splits a request start line into its three tokens. Editing operates
// on these rather than regexing the line, because a request target may contain
// almost anything and a regex over it is how a mangled request becomes a false
// negative.
func requestLine(line string) (method, target, version string, ok bool) {
	parts := strings.Split(strings.TrimRight(line, "\r"), " ")
	if len(parts) < 3 {
		return "", "", "", false
	}
	// The target may itself contain spaces in a malformed capture; keep the first
	// token as method and the last as version, joining the middle.
	method = parts[0]
	version = parts[len(parts)-1]
	target = strings.Join(parts[1:len(parts)-1], " ")
	return method, target, version, true
}

// contentTypeKeyword collapses a Content-Type to a short token. The full MIME type
// plus charset costs roughly six tokens per row and carries no information a client
// reasons about, so tables carry the keyword instead.
func contentTypeKeyword(ct string) string {
	c := strings.ToLower(ct)
	if i := strings.IndexByte(c, ';'); i >= 0 {
		c = c[:i]
	}
	c = strings.TrimSpace(c)
	switch {
	case c == "":
		return "-"
	case strings.Contains(c, "json"):
		return "json"
	case strings.Contains(c, "javascript"), strings.Contains(c, "ecmascript"):
		return "js"
	case strings.Contains(c, "html"):
		return "html"
	case strings.Contains(c, "xml"):
		return "xml"
	case strings.Contains(c, "css"):
		return "css"
	case strings.HasPrefix(c, "image/"):
		return "img"
	case strings.HasPrefix(c, "font/"), strings.Contains(c, "font"):
		return "font"
	case strings.HasPrefix(c, "text/"):
		return "text"
	default:
		return "bin"
	}
}
