package templatesig

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/BishopFox/joro/internal/httptools"
)

// defaultUA is sent unless a signature overrides User-Agent. A plain browser
// string keeps a probe from standing out from ordinary traffic.
const defaultUA = "Mozilla/5.0 (compatible; Joro)"

// renderRequest builds raw HTTP/1.1 bytes for one probe against origin. The path
// is {{BaseURL}}-relative; a stray {{BaseURL}} prefix or an absolute URL is
// reduced to its path. Content-Length is computed from the body in hand; the
// request never carries Transfer-Encoding.
func renderRequest(origin string, req *Request, path string) ([]byte, error) {
	host, err := hostOf(origin)
	if err != nil {
		return nil, err
	}
	target := normalizePath(path)
	if strings.ContainsAny(target, "\r\n") {
		return nil, fmt.Errorf("illegal path")
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, target)
	fmt.Fprintf(&b, "Host: %s\r\n", host)

	sentUA, sentAccept := false, false
	for k, v := range req.Headers {
		if strings.ContainsAny(k, "\r\n:") || strings.ContainsAny(v, "\r\n") {
			continue
		}
		switch strings.ToLower(k) {
		case "user-agent":
			sentUA = true
		case "accept":
			sentAccept = true
		case "host", "content-length":
			continue // Host is set above; Content-Length is computed below
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	if !sentUA {
		fmt.Fprintf(&b, "User-Agent: %s\r\n", defaultUA)
	}
	if !sentAccept {
		b.WriteString("Accept: */*\r\n")
	}
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	b.WriteString(req.Body)

	return httptools.UpdateContentLength([]byte(b.String())), nil
}

// hostOf returns the host[:port] of an origin.
func hostOf(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("bad origin %q", origin)
	}
	return u.Host, nil
}

// normalizePath reduces a signature path to an origin-form request target.
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "{{BaseURL}}", "")
	p = strings.ReplaceAll(p, "{{Hostname}}", "")
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		p = originPath(p)
	}
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
