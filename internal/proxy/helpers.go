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

// readAndCaptureResponse reads the response body once (with a size limit),
// builds rawResp bytes for capture, and restores resp.Body for forwarding.
// This avoids the double-read pattern of dumpResponse + resp.Write and
// prevents indefinite hangs on streaming responses.
func readAndCaptureResponse(resp *http.Response) []byte {
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxCaptureBody+1))
	resp.Body.Close()

	if len(bodyBytes) > maxCaptureBody {
		bodyBytes = bodyBytes[:maxCaptureBody]
	}

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

// copyBody copies src to dst, discarding any error.
func copyBody(dst io.Writer, src io.Reader) {
	io.Copy(dst, src) //nolint:errcheck
}

// UpdateContentLength recalculates the Content-Length header from the body size
// in a raw HTTP request. Used by the manipulate handler and fuzzer.
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

func eventInterceptQueued(id, method, url, host, protocol string, raw []byte) event.WSEvent {
	return event.WSEvent{Type: "intercept.queued", Data: map[string]any{
		"id":       id,
		"method":   method,
		"url":      url,
		"host":     host,
		"protocol": protocol,
		"reqRaw":   raw,
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
