package httptools

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/BishopFox/joro/internal/cert"
	"github.com/BishopFox/joro/internal/proxy"
)

const (
	// maxProxyRespBody bounds what a single automation send will read. The fuzzer
	// uses 10 MB; we need only enough to fingerprint, and a fifty-item batch at
	// 10 MB each would be half a gigabyte of transient allocation.
	maxProxyRespBody = 2 << 20

	// correlateWindow is how long to wait for the capture to appear in the store
	// after the response arrives. Capture happens on the proxy's goroutine, so it
	// races this one by a small margin.
	correlateWindow = 250 * time.Millisecond
	correlatePoll   = 5 * time.Millisecond
)

// ProxySendResult is the outcome of one automation send.
type ProxySendResult struct {
	// Seq is the history sequence number of the resulting capture, or 0 when the
	// request could not be correlated — see SendViaProxy for when that happens.
	Seq        int
	SeqNote    string
	RespRaw    []byte
	StatusCode int
	Duration   time.Duration
	Method     string
	URL        string
}

// SendDeps is what a send needs from the host process.
type SendDeps struct {
	// ProxyAddr is Joro's own proxy listener, e.g. "127.0.0.1:8080".
	ProxyAddr string
	// CA verifies the MITM leaf the proxy presents. We know exactly who we are
	// talking to, so this is a real verification rather than InsecureSkipVerify.
	CA    *cert.CA
	Store *proxy.Store
	// Claims is optional and only needed where sends run concurrently: it stops
	// two batch workers correlating to the same history row. A single send passes
	// nil, for which claim is a no-op.
	Claims *claimSet
}

// SendViaProxy writes raw request bytes through Joro's own proxy listener.
//
// This is deliberately not proxy.SendRawRequest, which dials the target directly.
// That function backs POST /manipulate/send and the fuzzer, and its behavior is
// unchanged by this package — including its SOCKS handling, since dialH1Conn
// routes through TransportConfig.SOCKSDialContext.
//
// Going through the proxy means an automation send is treated exactly like browser
// traffic: it is captured into History, scanned by the detect engine, entered into
// the site map, filtered by scope at both levels, and rewritten by Match & Replace
// and Custom Data. SOCKS still applies, one hop later, because the proxy's own
// upstream dial uses the same shared TransportConfig. The consequences an operator
// should expect are listed in CLAUDE.md; the notable ones are that M&R may rewrite
// what the client asked to send, and that an enabled request intercept will pause
// the send in the operator's queue until it is forwarded or this call times out.
//
// HTTP/1.1 only. ALPN is pinned to http/1.1 rather than negotiating h2: driving
// the h2 MITM path as a client through a CONNECT tunnel is materially more work
// for no benefit to the tools built on this.
func SendViaProxy(ctx context.Context, raw []byte, scheme, host string, d SendDeps) (*ProxySendResult, error) {
	if d.ProxyAddr == "" {
		return nil, fmt.Errorf("proxy address is not configured")
	}
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		scheme = "https"
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	hostPort := withDefaultPort(host, scheme)

	// Watermark the store before sending so correlation only has to look at what
	// arrived after this point.
	var lo int
	if d.Store != nil {
		lo = d.Store.LastSeq()
	}

	start := time.Now()
	resp, err := roundTripViaProxy(ctx, raw, scheme, hostPort, d)
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(start)

	respRaw, err := httputil.DumpResponse(resp, false)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("dumping response: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProxyRespBody))
	resp.Body.Close()
	respRaw = append(respRaw, body...)

	method, target, _, _ := requestLine(firstLine(raw))
	res := &ProxySendResult{
		RespRaw:    respRaw,
		StatusCode: resp.StatusCode,
		Duration:   elapsed,
		Method:     method,
		URL:        scheme + "://" + urlHost(hostPort, scheme) + target,
	}
	res.Seq, res.SeqNote = correlate(d.Store, lo, res, body, d.Claims)
	return res, nil
}

// roundTripViaProxy establishes the hop to Joro's proxy and performs the exchange.
func roundTripViaProxy(ctx context.Context, raw []byte, scheme, hostPort string, d SendDeps) (*http.Response, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connecting to Joro's proxy at %s: %w", d.ProxyAddr, err)
	}

	// Close the connection if the context ends, so a caller's timeout actually
	// interrupts a blocked read rather than waiting on the deadline below.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl) //nolint:errcheck
	} else {
		conn.SetDeadline(time.Now().Add(60 * time.Second)) //nolint:errcheck
	}

	wire := normalizeHTTP11(raw)
	if scheme == "https" {
		tlsConn, err := connectTunnel(conn, hostPort, d.CA)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	} else {
		// Plain HTTP through a proxy uses absolute-form request targets, which is
		// what internal/proxy/handler.go's non-CONNECT path expects.
		wire = toAbsoluteForm(wire, hostPort)
	}

	if _, err := conn.Write(wire); err != nil {
		conn.Close()
		return nil, fmt.Errorf("writing request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading response: %w", err)
	}
	resp.Body = &connBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// connectTunnel issues CONNECT and completes the TLS handshake against Joro's own
// MITM leaf, verifying it against Joro's CA.
func connectTunnel(conn net.Conn, hostPort string, ca *cert.CA) (net.Conn, error) {
	req := "CONNECT " + hostPort + " HTTP/1.1\r\nHost: " + hostPort + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("writing CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("reading CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy refused CONNECT to %s: %s", hostPort, resp.Status)
	}
	if br.Buffered() > 0 {
		// A well-behaved proxy sends nothing after the 200 until we speak, and
		// silently dropping buffered bytes would corrupt the handshake.
		return nil, fmt.Errorf("proxy sent %d unexpected bytes after CONNECT", br.Buffered())
	}

	serverName, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		serverName = hostPort
	}
	cfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
	if ca != nil && ca.Cert != nil {
		pool := x509.NewCertPool()
		pool.AddCert(ca.Cert)
		cfg.RootCAs = pool
	} else {
		// Without the CA there is nothing to verify against. This should not
		// happen in proxy mode, where the CA is loaded before anything starts.
		cfg.InsecureSkipVerify = true //nolint:gosec
	}

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake through proxy (is Joro's CA loaded?): %w", err)
	}
	return tlsConn, nil
}

// connBody closes the underlying connection when the body is closed. Automation
// sends are one-shot, so there is no keep-alive pool to return to.
type connBody struct {
	io.ReadCloser
	conn net.Conn
}

func (c *connBody) Close() error {
	err := c.ReadCloser.Close()
	c.conn.Close()
	return err
}

// toAbsoluteForm rewrites an origin-form request target ("/a/b") to absolute form
// ("http://host/a/b"). A target that is already absolute is left alone.
func toAbsoluteForm(raw []byte, hostPort string) []byte {
	hdr, body, _ := splitRaw(raw)
	lines := splitHeaderLines(hdr)
	if len(lines) == 0 {
		return raw
	}
	method, target, version, ok := requestLine(lines[0])
	if !ok || strings.Contains(target, "://") {
		return raw
	}
	lines[0] = method + " http://" + urlHost(hostPort, "http") + target + " " + version

	var out bytes.Buffer
	for _, ln := range lines {
		out.WriteString(ln)
		out.WriteString("\r\n")
	}
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes()
}

// claimSet tracks capture sequence numbers already handed to a send, so two
// concurrent batch workers cannot correlate to the same history row.
type claimSet struct {
	mu sync.Mutex
	m  map[int]struct{}
}

func newClaimSet() *claimSet { return &claimSet{m: map[int]struct{}{}} }

// claim takes seq if it is unclaimed, reporting whether it succeeded.
func (c *claimSet) claim(seq int) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, taken := c.m[seq]; taken {
		return false
	}
	c.m[seq] = struct{}{}
	return true
}

// correlate finds the history row the proxy created for this send.
//
// A unique correlation header would be simpler, but it would be sent to the
// target — an unacceptable tell during an engagement — so correlation uses only
// data we already hold. Watermark the store's sequence before sending, then match
// candidates that arrived after it.
//
// Matching is deliberately not on the raw response bytes. We reconstruct those
// with httputil.DumpResponse, which reorders headers and re-frames a chunked body,
// so a byte or length comparison against the proxy's own capture fails on
// perfectly good responses — which is exactly what it did the first time this ran.
// Instead:
//
//  1. method, URL and status must all match; then
//  2. prefer a candidate whose captured bytes end with the body we received.
//
// Step 2 is what disambiguates a concurrent batch, and it disambiguates precisely
// when it matters: variants that produced different responses. Variants whose
// responses are byte-identical fall through to claim order, which is acceptable
// because reading either row yields the same answer.
//
// Returning 0 is a normal outcome, not a failure: a noise-filtered host is
// tunneled with no capture anywhere, and a host outside the proxy's own capture
// scope is forwarded without one. The note says so rather than leaving a client to
// guess why a seq it was given does not resolve.
func correlate(store *proxy.Store, lo int, res *ProxySendResult, body []byte, claims *claimSet) (int, string) {
	if store == nil {
		return 0, "no capture store"
	}
	deadline := time.Now().Add(correlateWindow)
	for {
		var fallback *proxy.CapturedRequest
		for _, c := range store.SinceSeq(lo, 0) {
			if c.Method != res.Method || c.URL != res.URL || c.StatusCode != res.StatusCode {
				continue
			}
			if len(body) > 0 && bytes.HasSuffix(c.RespRaw, body) {
				if claims.claim(c.Seq) {
					return c.Seq, ""
				}
				continue
			}
			if fallback == nil {
				fallback = c
			}
		}
		if fallback != nil && claims.claim(fallback.Seq) {
			return fallback.Seq, ""
		}
		if time.Now().After(deadline) {
			return 0, "not captured (host may be noise-filtered or outside the proxy's capture scope)"
		}
		time.Sleep(correlatePoll)
	}
}

func firstLine(raw []byte) string {
	if i := bytes.IndexByte(raw, '\n'); i >= 0 {
		return strings.TrimRight(string(raw[:i]), "\r")
	}
	return string(raw)
}

func withDefaultPort(host, scheme string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if scheme == "https" {
		return host + ":443"
	}
	return host + ":80"
}

// urlHost strips the default port for the scheme, so a correlated URL matches the
// form the proxy records.
func urlHost(hostPort, scheme string) string {
	h, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	if (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
		return h
	}
	return hostPort
}

// hostFromCapture derives scheme and host from a captured request's URL, so a
// resend defaults to the same target the capture came from.
func hostFromCapture(rawURL string) (scheme, host string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", ""
	}
	return u.Scheme, u.Host
}
