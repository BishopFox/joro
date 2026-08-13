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
			meta := InterceptMeta{
				ID: id, Method: req.Method, URL: req.URL.String(), Host: hostname,
				Protocol: "HTTP/1.1", ReqRaw: rawReq,
			}
			h.emit(eventInterceptQueued(KindRequest, meta))
			decision, _ := h.intercept.Pause(meta)
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

		hasRespRules := h.replace != nil && h.replace.IsEnabled() && h.replace.HasResponseRules()
		wantPause := h.intercept.IsResponseEnabled() && responseIsPausable(resp) &&
			h.intercept.HasCapacityForResponse()

		if hasRespRules {
			resp = applyResponseReplace(h.replace, resp)
		}
		if hasRespRules || wantPause {
			// Buffered path: both response rules and the intercept pause need the
			// full body in hand. nil means the body was too large to buffer, so
			// fall through to streaming with the body restored intact.
			rawResp = readAndCaptureResponse(resp)
		}

		if rawResp == nil {
			// Streaming path: forward headers+body immediately.
			rawResp = streamAndCaptureResponse(resp, tlsConn)
		} else {
			if wantPause {
				meta := InterceptMeta{
					ID: id, Method: req.Method, URL: req.URL.String(), Host: hostname,
					Protocol: "HTTP/1.1", Status: resp.StatusCode, ReqRaw: rawReq, RespRaw: rawResp,
				}
				h.emit(eventInterceptQueued(KindResponse, meta))
				decision, _ := h.intercept.PauseResponse(meta)
				h.emit(eventInterceptResolved(id, decision.Action))

				if decision.Action == ActionDrop {
					resp.Body.Close()
					// writeSimpleResponse announces Connection: close, so return
					// rather than continue: looping would block in ReadRequest
					// until the client hangs up, contradicting our own header.
					writeSimpleResponse(tlsConn, http.StatusForbidden, "response dropped by intercept")
					return
				}
				if len(decision.RespData) > 0 {
					// A rejected edit forwards the original unmodified, matching
					// the request path's parse-failure fallback.
					if edited, ok := adoptEditedResponse(decision.RespData); ok {
						resp = edited
						rawResp = decision.RespData
					}
				}
			}
			if err := writeBufferedResponse(tlsConn, resp); err != nil {
				return
			}
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

// writeBufferedResponse writes a fully-buffered response to the client and
// closes its body. The proxy controls connection framing to the browser: the
// MITM loop keeps the conn alive, so never rely on connection-close to delimit
// the body, and force chunked when the length is unknown.
func writeBufferedResponse(dst net.Conn, resp *http.Response) error {
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	resp.Close = false
	resp.Header.Del("Connection")
	if resp.ContentLength < 0 {
		resp.TransferEncoding = []string{"chunked"}
	}
	err := resp.Write(dst)
	resp.Body.Close()
	return err
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

// timeNow and timeSince are the package's time source for request timing,
// indirected through vars so every call site shares one clock.
var timeNow = time.Now
var timeSince = time.Since
