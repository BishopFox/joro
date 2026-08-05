package proxy

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/event"
)

// urlHostWithPort returns hostPort with the default port for scheme stripped
// so URL.String() omits :443 for https and :80 for http while preserving any
// non-default port. e.g. ("example.com:443", "https") -> "example.com";
// ("example.com:8443", "https") -> "example.com:8443".
func urlHostWithPort(hostPort, scheme string) string {
	h, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	if (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
		return h
	}
	return hostPort
}

// stripHopHeaders removes hop-by-hop headers and proxy-interfering headers
// from an upstream response so the proxy manages its own connection semantics
// with the browser independently. It also resets resp.Close so that
// resp.Write uses proper framing (Content-Length or chunked) instead of
// relying on connection close to delimit the body.
func stripHopHeaders(resp *http.Response) {
	resp.Header.Del("Connection")
	resp.Header.Del("Keep-Alive")
	resp.Header.Del("Proxy-Authenticate")
	resp.Header.Del("Proxy-Authorization")
	resp.Header.Del("Te")
	resp.Header.Del("Trailer")
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Del("Upgrade")
	resp.Header.Del("Alt-Svc")
	resp.Close = false
	// Nil out the upstream request reference so resp.Write does not inherit
	// the transport's Close flag from it (Go sets Request.Close = true when
	// DisableKeepAlives is enabled).
	resp.Request = nil
}

// maxCaptureBody is the maximum response body size to capture (10 MB).
const maxCaptureBody = 10 << 20

// multiReadCloser reads from r while closing c, so a partially-consumed body can
// be restored as "buffered prefix + unread remainder" without losing the closer.
type multiReadCloser struct {
	io.Reader
	c io.Closer
}

func (m multiReadCloser) Close() error { return m.c.Close() }

// readAndCaptureResponse buffers the response body for a transform that needs it
// in hand (response Match & Replace, response interception), builds rawResp bytes
// for capture, and restores resp.Body for forwarding. This avoids the double-read
// pattern of dumpResponse + resp.Write.
//
// Returns nil when the body exceeds maxCaptureBody. resp.Body is then restored
// intact — buffered prefix plus unread remainder — so the caller must stream it
// through rather than buffering. Truncating and forwarding anyway would send
// fewer bytes than Content-Length advertises, desyncing the keep-alive
// connection so that the *next* request on it is misparsed.
func readAndCaptureResponse(resp *http.Response) []byte {
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxCaptureBody+1))

	if len(bodyBytes) > maxCaptureBody {
		// Do not close: the remainder is still needed for the streaming path.
		resp.Body = multiReadCloser{
			Reader: io.MultiReader(bytes.NewReader(bodyBytes), resp.Body),
			c:      resp.Body,
		}
		return nil
	}
	resp.Body.Close()

	// Restore body for forwarding (caller re-establishes framing).
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Build rawResp from a shallow copy with chunked encoding cleared and
	// content length set, so DumpResponse emits a Content-Length-framed dump
	// instead of re-encoding the already-decoded body as chunked.
	capturedResp := *resp
	capturedResp.TransferEncoding = nil
	capturedResp.ContentLength = int64(len(bodyBytes))
	capturedResp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	rawResp, _ := httputil.DumpResponse(&capturedResp, true)
	return rawResp
}

// limitWriter wraps a writer and silently stops writing after n bytes.
// It always reports success to the caller so the TeeReader stream is not interrupted.
type limitWriter struct {
	w io.Writer
	n int
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	if lw.n <= 0 {
		return len(p), nil // discard, but report full write
	}
	if len(p) > lw.n {
		p = p[:lw.n]
	}
	n, err := lw.w.Write(p)
	lw.n -= n
	if err != nil {
		// Don't propagate write errors to the tee stream.
		return len(p), nil
	}
	return len(p), nil
}

// streamAndCaptureResponse streams the response to dst (a MITM TLS conn) while
// simultaneously capturing the raw response (headers + body up to maxCaptureBody).
// Returns the captured raw response bytes.
func streamAndCaptureResponse(resp *http.Response, dst net.Conn) []byte {
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1

	// Ensure the proxy controls connection framing to the browser: never rely
	// on connection-close to delimit the body (the MITM loop keeps the conn
	// alive). Force chunked when Content-Length is unknown.
	resp.Close = false
	resp.Header.Del("Connection")
	if resp.ContentLength < 0 {
		resp.TransferEncoding = []string{"chunked"}
	}

	var captureBuf bytes.Buffer
	origBody := resp.Body
	resp.Body = io.NopCloser(io.TeeReader(origBody, &limitWriter{w: &captureBuf, n: maxCaptureBody}))

	// Write full response (headers + streaming body) to the client.
	writeErr := resp.Write(dst)
	origBody.Close()

	// Build rawResp from captured data. The body in captureBuf is already
	// dechunked, so clear TransferEncoding to prevent DumpResponse from
	// re-emitting chunked framing in the stored bytes.
	capturedResp := *resp
	capturedResp.TransferEncoding = nil
	capturedResp.Body = io.NopCloser(bytes.NewReader(captureBuf.Bytes()))
	capturedResp.ContentLength = int64(captureBuf.Len())
	rawResp, _ := httputil.DumpResponse(&capturedResp, true)

	_ = writeErr
	return rawResp
}

// streamAndCaptureHTTP streams the response through an http.ResponseWriter while
// capturing raw response bytes (headers + body up to maxCaptureBody).
func streamAndCaptureHTTP(resp *http.Response, w http.ResponseWriter) []byte {
	// Copy response headers.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Tee the body to both the client and a capture buffer.
	var captureBuf bytes.Buffer
	tee := io.TeeReader(resp.Body, &limitWriter{w: &captureBuf, n: maxCaptureBody})
	io.Copy(w, tee) //nolint:errcheck
	resp.Body.Close()

	// Build rawResp for capture. Body in captureBuf is already dechunked, so
	// clear TransferEncoding to avoid re-emitting chunked framing.
	capturedResp := *resp
	capturedResp.Proto = "HTTP/1.1"
	capturedResp.ProtoMajor = 1
	capturedResp.ProtoMinor = 1
	capturedResp.TransferEncoding = nil
	capturedResp.Body = io.NopCloser(bytes.NewReader(captureBuf.Bytes()))
	capturedResp.ContentLength = int64(captureBuf.Len())
	rawResp, _ := httputil.DumpResponse(&capturedResp, true)

	return rawResp
}

// readRand fills b with cryptographically random bytes.
func readRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
}

// toHexID formats a 16-byte slice into a UUID-like hex string.
func toHexID(b []byte) string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}

// dumpRequest serialises an http.Request to bytes, restoring the body.
func dumpRequest(r *http.Request, withBody bool) ([]byte, error) {
	return httputil.DumpRequest(r, withBody)
}

// dumpResponse serialises an http.Response to bytes, restoring the body.
func dumpResponse(r *http.Response, withBody bool) ([]byte, error) {
	return httputil.DumpResponse(r, withBody)
}

// parseRequest reconstructs an *http.Request from raw bytes.
func parseRequest(raw []byte) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
}

// parseResponse reconstructs an *http.Response from raw bytes.
func parseResponse(raw []byte) (*http.Response, error) {
	return http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
}

// adoptEditedResponse turns operator-edited raw response bytes into a response
// ready to write, returning false if the edit cannot be used.
//
// Content-Length is recomputed from the actual body first, so the common edit —
// changing body text without touching the header — cannot advertise the wrong
// length and desync the connection. The body is then read eagerly: any framing
// the edit implies but does not satisfy (a hand-typed Transfer-Encoding: chunked
// over a plain body) fails here, before anything has been written, so the caller
// can fall back to the original response instead of dying mid-write with a
// half-sent message.
func adoptEditedResponse(raw []byte) (*http.Response, bool) {
	resp, err := parseResponse(UpdateContentLength(raw))
	if err != nil {
		return nil, false
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, false
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	return resp, true
}

// responseIsPausable reports whether a response can be buffered for an intercept
// pause without stalling. Indefinite streams would never finish buffering, and
// bodiless statuses have nothing to edit (rewriting their framing is a spec
// hazard). Callers still handle the oversized case via readAndCaptureResponse.
func responseIsPausable(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	for _, streaming := range []string{"text/event-stream", "multipart/x-mixed-replace", "application/grpc"} {
		if strings.Contains(ct, streaming) {
			return false
		}
	}
	return true
}

// copyBody copies src to dst, discarding any error.
func copyBody(dst io.Writer, src io.Reader) {
	io.Copy(dst, src) //nolint:errcheck
}

// UpdateContentLength recalculates the Content-Length header from the body size
// in a raw HTTP message. Used by the manipulate handler, the fuzzer, and
// adoptEditedResponse — it parses no start line, so it serves requests and
// responses alike.
//
// Accepts either CRLF or LF header terminators (CodeMirror normalizes edits to
// LF), but always emits canonical CRLF. The body is preserved byte-for-byte —
// line endings inside the body are never touched.
func UpdateContentLength(raw []byte) []byte {
	// Locate the header/body boundary: whichever of \r\n\r\n or \n\n appears
	// first wins. This handles pure-CRLF (unedited), pure-LF (edited in
	// CodeMirror), and mixed inputs.
	crlfIdx := bytes.Index(raw, []byte("\r\n\r\n"))
	lfIdx := bytes.Index(raw, []byte("\n\n"))
	var headerEnd, sepLen int
	switch {
	case crlfIdx >= 0 && (lfIdx < 0 || crlfIdx <= lfIdx):
		headerEnd, sepLen = crlfIdx, 4
	case lfIdx >= 0:
		headerEnd, sepLen = lfIdx, 2
	default:
		return raw
	}

	headers := raw[:headerEnd]
	body := raw[headerEnd+sepLen:]

	// Normalize header line endings so we can split cleanly regardless of input.
	normalized := bytes.ReplaceAll(headers, []byte("\r\n"), []byte("\n"))
	lines := bytes.Split(normalized, []byte("\n"))

	var rebuilt [][]byte
	found := false
	for _, line := range lines {
		if len(line) > 0 && strings.HasPrefix(strings.ToLower(string(line)), "content-length:") {
			rebuilt = append(rebuilt, []byte("Content-Length: "+strconv.Itoa(len(body))))
			found = true
		} else {
			rebuilt = append(rebuilt, line)
		}
	}
	if !found && len(body) > 0 {
		rebuilt = append(rebuilt, []byte("Content-Length: "+strconv.Itoa(len(body))))
	}

	result := bytes.Join(rebuilt, []byte("\r\n"))
	result = append(result, []byte("\r\n\r\n")...)
	result = append(result, body...)
	return result
}

// buildUpstreamErrorCapture constructs a CapturedRequest representing the
// synthetic 502 the proxy returns to the client when an upstream RoundTrip
// fails (e.g. H2 RST_STREAM, dial error, TLS handshake failure). Without this,
// failed proxy attempts are invisible in History — the worst case for the
// operator, since the only missing requests are the ones joro itself rejected.
func buildUpstreamErrorCapture(id string, start time.Time, method, url, host, protocol string, rawReq []byte, errMsg string) *CapturedRequest {
	body := "upstream error: " + errMsg + "\n"
	statusLine := protocol
	if statusLine == "" {
		statusLine = "HTTP/1.1"
	}
	rawResp := fmt.Appendf(nil, "%s 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s",
		statusLine, len(body), body)
	return &CapturedRequest{
		ID:           id,
		Timestamp:    start,
		Method:       method,
		URL:          url,
		Host:         host,
		Protocol:     statusLine,
		StatusCode:   http.StatusBadGateway,
		ContentType:  "text/plain; charset=utf-8",
		Duration:     timeSince(start),
		ResponseSize: len(rawResp),
		ReqRaw:       rawReq,
		RespRaw:      rawResp,
	}
}

func eventRequestCaptured(r *CapturedRequest) event.WSEvent {
	return event.WSEvent{Type: "request.captured", Data: r}
}

// eventInterceptQueued announces a paused request or response. It takes the same
// InterceptMeta the queue does, so the bytes the operator sees cannot drift from
// the bytes the queue holds. reqRaw is populated for both kinds, so the payload
// stays well-formed for any consumer that predates response interception.
func eventInterceptQueued(kind InterceptKind, m InterceptMeta) event.WSEvent {
	return event.WSEvent{Type: "intercept.queued", Data: map[string]any{
		"id":       m.ID,
		"kind":     string(kind),
		"method":   m.Method,
		"url":      m.URL,
		"host":     m.Host,
		"protocol": m.Protocol,
		"status":   m.Status,
		"reqRaw":   m.ReqRaw,
		"respRaw":  m.RespRaw,
	}}
}

func eventWSMessage(m *CapturedWSMessage) event.WSEvent {
	return event.WSEvent{Type: "ws.message", Data: m}
}

func eventInterceptResolved(id string, action InterceptAction) event.WSEvent {
	a := "forward"
	if action == ActionDrop {
		a = "drop"
	}
	return event.WSEvent{Type: "intercept.resolved", Data: map[string]any{
		"id":     id,
		"action": a,
	}}
}
