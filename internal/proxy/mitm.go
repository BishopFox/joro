package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/BishopFox/joro/sdk"
)

// mitm performs TLS termination for CONNECT-tunnelled HTTPS traffic. hostPort
// is the original CONNECT target (e.g. "example.com:443"); hostname is the
// bare host used for cert lookup, scope, and the captured Host field. The
// connect-target port is preserved on req.URL.Host so non-default ports show
// up in History.
func (h *Handler) mitm(clientConn net.Conn, hostname, hostPort string) {
	defer clientConn.Close()

	tlsCert, err := h.certCache.Get(hostname)
	if err != nil {
		return
	}

	nextProtos := []string{"http/1.1"}
	if h.transport != nil && h.transport.HTTP2() {
		nextProtos = []string{"h2", "http/1.1"}
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   nextProtos,
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h.serveH2(tlsConn, hostname, hostPort)
		return
	}

	urlHost := urlHostWithPort(hostPort, "https")

	reader := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = urlHost
		req.RequestURI = ""

		// WebSocket upgrade: branch into WS relay.
		if isWebSocketUpgrade(req) {
			h.handleWSUpgradeMITM(tlsConn, req, hostname)
			return
		}

		if !h.scope.InScope(hostname, req.Method, req.URL.Path) {
			transport := h.transport.Transport()
			resp, err := transport.RoundTrip(req)
			if err != nil {
				writeSimpleResponse(tlsConn, http.StatusBadGateway, fmt.Sprintf("upstream error: %v", err))
				continue
			}
			stripHopHeaders(resp)
			resp.Proto = "HTTP/1.1"
			resp.ProtoMajor = 1
			resp.ProtoMinor = 1
			if resp.ContentLength < 0 {
				resp.TransferEncoding = []string{"chunked"}
			}
			if err := resp.Write(tlsConn); err != nil {
				resp.Body.Close()
				return
			}
			resp.Body.Close()
			if req.Close {
				return
			}
			continue
		}

		id := GenerateID()
		start := timeNow()

		rawReq, _ := dumpRequest(req, true)

		if h.intercept.IsEnabled() {
			h.emit(eventInterceptQueued(id, req.Method, req.URL.String(), hostname, "HTTP/1.1", rawReq))
			decision, _ := h.intercept.Pause(id, req.Method, req.URL.String(), hostname, "HTTP/1.1", rawReq)
			h.emit(eventInterceptResolved(id, decision.Action))

			if decision.Action == ActionDrop {
				writeSimpleResponse(tlsConn, http.StatusForbidden, "request dropped by intercept")
				continue
			}

			if len(decision.ReqData) > 0 {
				modified, parseErr := parseRequest(decision.ReqData)
				if parseErr == nil {
					modified.URL.Scheme = "https"
					modified.URL.Host = urlHost
					modified.RequestURI = ""
					req = modified
					rawReq = decision.ReqData
				}
			}
		}

		// Apply request match/replace rules.
		if h.replace != nil && h.replace.IsEnabled() {
			req = applyRequestReplace(h.replace, req)
			req.URL.Scheme = "https"
			req.URL.Host = urlHost
			req.RequestURI = ""
			rawReq, _ = dumpRequest(req, true)
		}

		// Apply custom data additions.
		req = applyCustomData(h.customData, req)
		rawReq, _ = dumpRequest(req, true)

		// Run plugin request hooks.
		if h.hookRunner != nil {
			hookInfo := sdk.RequestInfo{ID: id, Method: req.Method, URL: req.URL.String(), Host: hostname}
			modified, hookErr := h.hookRunner.RunRequestHook(req.Context(), hookInfo, rawReq)
			if hookErr == nil && modified == nil {
				writeSimpleResponse(tlsConn, http.StatusForbidden, "request dropped by plugin")
				continue
			}
			if hookErr == nil && modified != nil {
				if parsed, parseErr := parseRequest(modified); parseErr == nil {
					parsed.URL.Scheme = "https"
					parsed.URL.Host = urlHost
					parsed.RequestURI = ""
					req = parsed
					rawReq = modified
				}
			}
		}

		req.Header.Del("Accept-Encoding")
		transport := h.transport.Transport()
		resp, err := transport.RoundTrip(req)
		if err != nil {
			writeSimpleResponse(tlsConn, http.StatusBadGateway, fmt.Sprintf("upstream error: %v", err))
			captured := buildUpstreamErrorCapture(id, start, req.Method, req.URL.String(), hostname, "HTTP/1.1", rawReq, err.Error())
			h.store.Add(captured)
			h.emit(eventRequestCaptured(captured))
			if req.Close {
				return
			}
			continue
		}

		// Strip hop-by-hop and proxy-interfering headers. The proxy manages its
		// own connection semantics with the browser independently of upstream.
		stripHopHeaders(resp)

		var rawResp []byte
		connClose := req.Close

		if h.replace != nil && h.replace.IsEnabled() && h.replace.HasResponseRules() {
			// Buffered path: need full body to apply response replace rules.
			resp = applyResponseReplace(h.replace, resp)
			rawResp = readAndCaptureResponse(resp)

			resp.Proto = "HTTP/1.1"
			resp.ProtoMajor = 1
			resp.ProtoMinor = 1
			resp.Close = false
			resp.Header.Del("Connection")
			if resp.ContentLength < 0 {
				resp.TransferEncoding = []string{"chunked"}
			}
			if err := resp.Write(tlsConn); err != nil {
				resp.Body.Close()
				return
			}
			resp.Body.Close()
		} else {
			// Streaming path: forward headers+body immediately.
			rawResp = streamAndCaptureResponse(resp, tlsConn)
		}

		// Run plugin response hooks.
		if h.hookRunner != nil {
			hookInfo := sdk.RequestInfo{ID: id, Method: req.Method, URL: req.URL.String(), Host: hostname}
			if modified, hookErr := h.hookRunner.RunResponseHook(req.Context(), hookInfo, rawResp); hookErr == nil && modified != nil {
				rawResp = modified
			}
		}

		duration := timeSince(start)
		captured := &CapturedRequest{
			ID:           id,
			Timestamp:    start,
			Method:       req.Method,
			URL:          req.URL.String(),
			Host:         hostname,
			Protocol:     "HTTP/1.1",
			StatusCode:   resp.StatusCode,
			ContentType:  resp.Header.Get("Content-Type"),
			Duration:     duration,
			ResponseSize: len(rawResp),
			ReqRaw:       rawReq,
			RespRaw:      rawResp,
		}
		h.store.Add(captured)
		h.emit(eventRequestCaptured(captured))

		if connClose {
			return
		}
	}
}

// writeSimpleResponse sends a minimal HTTP response over conn.
func writeSimpleResponse(conn net.Conn, status int, body string) {
	resp := &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": {"text/plain"}, "Connection": {"close"}},
		Body:       nopReadCloser([]byte(body)),
		Close:      true,
	}
	resp.ContentLength = int64(len(body))
	resp.Write(conn) //nolint:errcheck
}

// nopReadCloser wraps a byte slice as an io.ReadCloser.
func nopReadCloser(b []byte) *bytesReadCloser {
	return &bytesReadCloser{r: bytes.NewReader(b)}
}

type bytesReadCloser struct{ r *bytes.Reader }

func (b *bytesReadCloser) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *bytesReadCloser) Close() error               { return nil }

// timeNow and timeSince are vars so tests can override them.
var timeNow = time.Now
var timeSince = time.Since
