package proxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// SendOptions controls behavior of SendRawRequest.
type SendOptions struct {
	FollowRedirects bool
	Decompress      bool
	H2Transport     *http2.Transport
}

// SendResult holds the outcome of a raw send.
type SendResult struct {
	Response       *http.Response
	RawResp        []byte
	Duration       time.Duration
	Hops           int
	ResponseSource string // "wire" | "synthetic" | "fallback-h1"
}

const sendMaxRedirectHops = 10

// SendRawRequest sends raw HTTP request bytes, choosing the wire protocol from
// the version token in the request line. HTTP/1.0 and HTTP/1.1 go on the wire
// byte-for-byte over a raw TCP/TLS socket with ALPN forced to http/1.1. HTTP/2
// is re-encoded by golang.org/x/net/http2 with ALPN forced to h2 (h2 has no
// textual request line on the wire).
func SendRawRequest(ctx context.Context, raw []byte, scheme, host string, opts SendOptions, tc *TransportConfig) (*SendResult, error) {
	proto := protocolFromRequestLine(raw)
	switch proto {
	case "HTTP/1.0", "HTTP/1.1":
		return sendH1Raw(ctx, raw, scheme, host, proto, opts, tc, 0)
	case "HTTP/2", "HTTP/2.0":
		return sendH2(ctx, raw, scheme, host, opts, tc, 0)
	case "":
		return nil, errors.New("could not parse HTTP version from request line")
	default:
		return nil, fmt.Errorf("unsupported HTTP version: %q", proto)
	}
}

// protocolFromRequestLine reads the first line of raw and returns the version
// token (e.g., "HTTP/1.1"), or "" if not present. Returns the parsed token even
// for unsupported versions so the caller can produce a useful error.
func protocolFromRequestLine(raw []byte) string {
	end := bytes.IndexAny(raw, "\r\n")
	if end < 0 {
		end = len(raw)
	}
	parts := bytes.Fields(raw[:end])
	if len(parts) < 3 {
		return ""
	}
	return string(parts[len(parts)-1])
}

func sendH1Raw(ctx context.Context, raw []byte, scheme, host, proto string, opts SendOptions, tc *TransportConfig, hops int) (*SendResult, error) {
	scheme = strings.ToLower(scheme)
	if scheme == "" {
		scheme = "https"
	}
	if host == "" {
		host = hostFromRaw(raw)
		if host == "" {
			return nil, errors.New("host is required")
		}
	}

	dialHost := host
	if !strings.Contains(dialHost, ":") {
		if scheme == "https" {
			dialHost = net.JoinHostPort(dialHost, "443")
		} else {
			dialHost = net.JoinHostPort(dialHost, "80")
		}
	}

	conn, err := dialH1Conn(ctx, scheme, dialHost, tc)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline) //nolint:errcheck

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()

	start := time.Now()
	if _, err := conn.Write(raw); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	duration := time.Since(start)

	if opts.Decompress {
		if decoded, ok := tryDecompress(resp.Header.Get("Content-Encoding"), bodyBytes); ok {
			bodyBytes = decoded
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Transfer-Encoding")
			resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		}
	}

	rawResp := dumpResponseSafe(resp, bodyBytes)
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	if opts.FollowRedirects && hops+1 < sendMaxRedirectHops && isRedirect(resp.StatusCode) {
		if loc := resp.Header.Get("Location"); loc != "" {
			if nextScheme, nextHost, nextPath, err := resolveRedirect(scheme, host, loc); err == nil {
				followRaw := buildSimpleGet(proto, nextHost, nextPath)
				return sendH1Raw(ctx, followRaw, nextScheme, nextHost, proto, opts, tc, hops+1)
			}
		}
	}

	return &SendResult{
		Response:       resp,
		RawResp:        rawResp,
		Duration:       duration,
		Hops:           hops,
		ResponseSource: "synthetic",
	}, nil
}

func sendH2(ctx context.Context, raw []byte, scheme, host string, opts SendOptions, tc *TransportConfig, hops int) (*SendResult, error) {
	parseable := rewriteVersionToH1(raw)
	httpReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(parseable)))
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}

	if scheme == "" {
		scheme = "https"
	}
	if host == "" {
		host = httpReq.Host
		if host == "" {
			return nil, errors.New("host is required")
		}
	}
	httpReq.URL.Scheme = scheme
	httpReq.URL.Host = host
	httpReq.Host = host
	httpReq.RequestURI = ""

	for _, h := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		httpReq.Header.Del(h)
	}

	transport := opts.H2Transport
	closeWhenDone := false
	if transport == nil {
		transport = newH2Transport(tc)
		closeWhenDone = true
	}
	if closeWhenDone {
		defer transport.CloseIdleConnections()
	}

	httpReq = httpReq.WithContext(ctx)
	start := time.Now()
	resp, err := transport.RoundTrip(httpReq)
	if err != nil {
		if isH2NotSupported(err) {
			fallback := bytes.Replace(raw, []byte("HTTP/2.0"), []byte("HTTP/1.1"), 1)
			fallback = bytes.Replace(fallback, []byte("HTTP/2"), []byte("HTTP/1.1"), 1)
			res, ferr := sendH1Raw(ctx, fallback, scheme, host, "HTTP/1.1", opts, tc, hops)
			if ferr == nil && res != nil {
				res.ResponseSource = "fallback-h1"
			}
			return res, ferr
		}
		return nil, fmt.Errorf("send: %w", err)
	}
	duration := time.Since(start)

	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if opts.Decompress {
		if decoded, ok := tryDecompress(resp.Header.Get("Content-Encoding"), bodyBytes); ok {
			bodyBytes = decoded
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Transfer-Encoding")
			resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
		}
	}

	rawResp := dumpResponseSafe(resp, bodyBytes)
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	if opts.FollowRedirects && hops+1 < sendMaxRedirectHops && isRedirect(resp.StatusCode) {
		if loc := resp.Header.Get("Location"); loc != "" {
			if nextScheme, nextHost, nextPath, err := resolveRedirect(scheme, host, loc); err == nil {
				followRaw := buildSimpleGet("HTTP/2", nextHost, nextPath)
				return sendH2(ctx, followRaw, nextScheme, nextHost, opts, tc, hops+1)
			}
		}
	}

	return &SendResult{
		Response:       resp,
		RawResp:        rawResp,
		Duration:       duration,
		Hops:           hops,
		ResponseSource: "synthetic",
	}, nil
}

// dialH1Conn dials TCP/TLS for HTTP/1.x, forcing ALPN to http/1.1 on TLS.
func dialH1Conn(ctx context.Context, scheme, host string, tc *TransportConfig) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var raw net.Conn
	var err error
	if tc != nil {
		if dial := tc.SOCKSDialContext(); dial != nil {
			raw, err = dial(dialCtx, "tcp", host)
		}
	}
	if raw == nil && err == nil {
		var d net.Dialer
		raw, err = d.DialContext(dialCtx, "tcp", host)
	}
	if err != nil {
		return nil, err
	}

	if scheme != "https" {
		return raw, nil
	}

	serverName, _, _ := net.SplitHostPort(host)
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return tlsConn, nil
}

// newH2Transport returns a fresh http2.Transport that prefers ALPN h2 and
// honors SOCKS configuration on tc. Both "h2" and "http/1.1" are advertised so
// the TLS handshake itself doesn't fail against servers that respond with
// http/1.1 in ALPN; if the server picks anything other than h2, the dialer
// returns errH2NotSupported and the caller falls back to the H1 sender.
func newH2Transport(tc *TransportConfig) *http2.Transport {
	t := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			NextProtos:         []string{"h2", "http/1.1"},
		},
		AllowHTTP: false,
	}

	t.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		var rawConn net.Conn
		var err error
		if tc != nil {
			if dial := tc.SOCKSDialContext(); dial != nil {
				rawConn, err = dial(dialCtx, network, addr)
			}
		}
		if rawConn == nil && err == nil {
			var d net.Dialer
			rawConn, err = d.DialContext(dialCtx, network, addr)
		}
		if err != nil {
			return nil, err
		}

		serverName, _, _ := net.SplitHostPort(addr)
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			rawConn.Close()
			return nil, err
		}
		if state := tlsConn.ConnectionState(); state.NegotiatedProtocol != "h2" {
			tlsConn.Close()
			return nil, errH2NotSupported
		}
		return tlsConn, nil
	}
	return t
}

var errH2NotSupported = errors.New("server does not support HTTP/2 (ALPN)")

func isH2NotSupported(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errH2NotSupported) {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, errH2NotSupported.Error()) {
		return true
	}
	// Servers that misbehave in ALPN: pick a protocol the client never offered,
	// or send TLS 1.3 alert 120 (no_application_protocol). Treat both as
	// "no h2 here" so the H1 fallback path can take over instead of bubbling
	// up as a 502.
	if strings.Contains(msg, "unadvertised ALPN protocol") {
		return true
	}
	if strings.Contains(msg, "no application protocol") {
		return true
	}
	return false
}

// rewriteVersionToH1 swaps " HTTP/2" or " HTTP/2.0" → " HTTP/1.1" in the
// request line so http.ReadRequest can parse it. Used only as a parsing-time
// concession; the wire protocol is chosen by the caller.
func rewriteVersionToH1(raw []byte) []byte {
	eol := bytes.IndexAny(raw, "\r\n")
	if eol < 0 {
		return raw
	}
	line := raw[:eol]
	rest := raw[eol:]
	for _, suffix := range []string{" HTTP/2.0", " HTTP/2"} {
		if bytes.HasSuffix(line, []byte(suffix)) {
			fixed := append([]byte{}, line[:len(line)-len(suffix)]...)
			fixed = append(fixed, " HTTP/1.1"...)
			return append(fixed, rest...)
		}
	}
	return raw
}

// hostFromRaw extracts the Host header value from raw HTTP/1 bytes.
func hostFromRaw(raw []byte) string {
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = bytes.Index(raw, []byte("\n\n"))
		if headerEnd < 0 {
			return ""
		}
	}
	headers := bytes.ReplaceAll(raw[:headerEnd], []byte("\r\n"), []byte("\n"))
	for _, line := range bytes.Split(headers, []byte("\n")) {
		if i := bytes.IndexByte(line, ':'); i > 0 {
			if strings.EqualFold(string(line[:i]), "Host") {
				return strings.TrimSpace(string(line[i+1:]))
			}
		}
	}
	return ""
}

func isRedirect(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func resolveRedirect(scheme, host, location string) (string, string, string, error) {
	base := &url.URL{Scheme: scheme, Host: host}
	loc, err := url.Parse(location)
	if err != nil {
		return "", "", "", err
	}
	final := base.ResolveReference(loc)
	if final.Scheme == "" {
		final.Scheme = scheme
	}
	if final.Host == "" {
		final.Host = host
	}
	return final.Scheme, final.Host, final.RequestURI(), nil
}

func buildSimpleGet(proto, host, path string) []byte {
	if path == "" {
		path = "/"
	}
	return fmt.Appendf(nil, "GET %s %s\r\nHost: %s\r\nAccept: */*\r\n\r\n", path, proto, host)
}

// tryDecompress decodes gzip / deflate response bodies. Returns (decoded, true)
// on success, or (original, false) if the encoding is empty or unsupported.
func tryDecompress(encoding string, body []byte) ([]byte, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" {
		return body, false
	}
	var reader io.ReadCloser
	var err error
	switch enc {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		reader = flate.NewReader(bytes.NewReader(body))
	default:
		return body, false
	}
	if err != nil {
		return body, false
	}
	decoded, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		return body, false
	}
	return decoded, true
}

// dumpResponseSafe emits a Content-Length-framed dump of resp with the supplied
// body. It clears chunked transfer encoding so the captured bytes show the
// already-decoded body rather than re-encoded chunk markers.
func dumpResponseSafe(resp *http.Response, body []byte) []byte {
	captured := *resp
	captured.TransferEncoding = nil
	captured.ContentLength = int64(len(body))
	captured.Body = io.NopCloser(bytes.NewReader(body))
	out, _ := httputil.DumpResponse(&captured, true)
	return out
}

// H2TransportCache provides per-host h2 transport reuse for high-throughput
// callers (e.g., the fuzzer).
type H2TransportCache struct {
	mu         sync.Mutex
	transports map[string]*http2.Transport
	tc         *TransportConfig
}

// NewH2TransportCache returns a cache parameterized over the given TransportConfig.
func NewH2TransportCache(tc *TransportConfig) *H2TransportCache {
	return &H2TransportCache{
		transports: make(map[string]*http2.Transport),
		tc:         tc,
	}
}

// Get returns a cached or freshly built h2 transport keyed by host.
func (c *H2TransportCache) Get(host string) *http2.Transport {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.transports[host]; ok {
		return t
	}
	t := newH2Transport(c.tc)
	c.transports[host] = t
	return t
}

// Close releases all cached transports.
func (c *H2TransportCache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range c.transports {
		t.CloseIdleConnections()
	}
	c.transports = make(map[string]*http2.Transport)
}
