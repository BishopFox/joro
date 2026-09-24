package anomaly

import (
	"bytes"
	"net/url"
	"sort"
	"strings"

	"github.com/BishopFox/joro/internal/httptools"
	"github.com/BishopFox/joro/internal/proxy"
)

// record is the light, immutable per-capture summary the baselines are built
// from. One is computed per captured request the first time its sequence number
// is seen, then cached — response fingerprinting is the expensive step and a
// capture never changes after it is stored.
type record struct {
	seq     int
	host    string
	method  string
	rawPath string
	norm    string // templated path (the endpoint key component)
	url     string // full URL of this capture, for the representative request
	reqID   string
	ts      int64 // unix nanos of capture, for picking the most recent

	statusClass int
	majorCT     string
	size        int
	durMs       int64
	hasDur      bool

	params      []string // sorted query parameter names
	ext         string
	tech        string   // X-Powered-By if present, else Server token
	authScheme  string   // first token of WWW-Authenticate, lowercased
	cookieNames []string // Set-Cookie names on this response
}

// buildRecord summarizes one capture, or returns nil for a capture that must not
// enter a baseline: WebSocket upgrades (101) and the synthetic 502 the proxy
// stores for an upstream dial failure, both of which would distort a host's
// status and shape distributions.
func buildRecord(cr *proxy.CapturedRequest) *record {
	if cr.Host == "" {
		return nil
	}
	if cr.StatusCode == 101 {
		return nil
	}
	if cr.StatusCode == 502 && isUpstreamError(cr.RespRaw) {
		return nil
	}

	durMs := cr.Duration.Milliseconds()
	fp := httptools.FingerprintResponse(cr.Seq, cr.RespRaw, durMs, false)

	status := fp.Status
	if status == 0 {
		status = cr.StatusCode
	}
	ct := fp.CT
	if ct == "" {
		ct = cr.ContentType
	}

	var rawPath string
	var params []string
	if u, err := url.Parse(cr.URL); err == nil {
		rawPath = u.Path
		for k := range u.Query() {
			params = append(params, k)
		}
		sort.Strings(params)
	}

	tech, authScheme, cookies := parseRespHeaders(cr.RespRaw)
	if tech == "" {
		tech = fp.Server
	}

	return &record{
		seq:         cr.Seq,
		host:        cr.Host,
		method:      strings.ToUpper(cr.Method),
		rawPath:     rawPath,
		norm:        normalizePath(rawPath),
		url:         cr.URL,
		reqID:       cr.ID,
		ts:          cr.Timestamp.UnixNano(),
		statusClass: statusClass(status),
		majorCT:     majorCT(ct),
		size:        fp.Len,
		durMs:       durMs,
		hasDur:      durMs > 0,
		params:      params,
		ext:         pathExt(rawPath),
		tech:        strings.ToLower(tech),
		authScheme:  authScheme,
		cookieNames: cookies,
	}
}

// isUpstreamError matches the body buildUpstreamErrorCapture writes for a failed
// upstream dial. Kept in sync with that helper by shape, not import.
func isUpstreamError(raw []byte) bool {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return false
	}
	return bytes.HasPrefix(bytes.TrimLeft(raw[i+4:], " \t\r\n"), []byte("upstream error:"))
}

// parseRespHeaders pulls the few headers the tech and header/auth signals need
// out of a raw response, without a full HTTP parse: the framework token
// (X-Powered-By, else the Server product), the auth scheme, and Set-Cookie
// names.
func parseRespHeaders(raw []byte) (tech, authScheme string, cookies []string) {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		end = len(raw)
	}
	var server string
	for _, line := range bytes.Split(raw[:end], []byte("\r\n")) {
		c := bytes.IndexByte(line, ':')
		if c <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(string(line[:c])))
		val := strings.TrimSpace(string(line[c+1:]))
		switch name {
		case "x-powered-by":
			if tech == "" {
				tech = firstToken(val)
			}
		case "server":
			server = firstToken(val)
		case "www-authenticate":
			if authScheme == "" {
				authScheme = strings.ToLower(firstToken(val))
			}
		case "set-cookie":
			if eq := strings.IndexByte(val, '='); eq > 0 {
				cookies = append(cookies, strings.TrimSpace(val[:eq]))
			}
		}
	}
	if tech == "" {
		tech = server
	}
	return tech, authScheme, cookies
}

// firstToken returns the value up to the first space, tab, or semicolon, so
// "Apache/2.4.7 (Ubuntu)" becomes "Apache/2.4.7".
func firstToken(s string) string {
	if i := strings.IndexAny(s, " \t;,"); i > 0 {
		return s[:i]
	}
	return s
}
