package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/BishopFox/joro/sdk"
	"golang.org/x/net/http2"
)

// serveH2 dispatches an HTTP/2 connection by handing it to golang.org/x/net/http2's
// server, which decodes streams and invokes h.h2Stream for each request.
func (h *Handler) serveH2(tlsConn *tls.Conn, hostname, hostPort string) {
	srv := &http2.Server{}
	srv.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.h2Stream(w, r, hostname, hostPort)
		}),
	})
}

// h2Stream runs the proxy pipeline for a single HTTP/2 stream. The request and
// response are exchanged in HTTP/2 frames with the browser; the upstream call
// goes through the protocol-aware sender so HTTP/2 is preserved end-to-end.
func (h *Handler) h2Stream(w http.ResponseWriter, r *http.Request, hostname, hostPort string) {
	if r.URL.Scheme == "" {
		r.URL.Scheme = "https"
	}
	if r.URL.Host == "" {
		r.URL.Host = urlHostWithPort(hostPort, "https")
	}
	r.RequestURI = ""

	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Match the h1 path: strip Accept-Encoding so the upstream returns
	// uncompressed bodies that capture cleanly and render as text in the UI.
	r.Header.Del("Accept-Encoding")

	rawReq := dumpH2Request(r, bodyBytes)
	id := GenerateID()
	start := timeNow()

	if h.intercept.IsEnabled() {
		h.emit(eventInterceptQueued(id, r.Method, r.URL.String(), hostname, "HTTP/2", rawReq))
		decision, _ := h.intercept.Pause(id, r.Method, r.URL.String(), hostname, "HTTP/2", rawReq)
		h.emit(eventInterceptResolved(id, decision.Action))

		if decision.Action == ActionDrop {
			http.Error(w, "request dropped by intercept", http.StatusForbidden)
			return
		}
		if len(decision.ReqData) > 0 {
			rawReq = decision.ReqData
		}
	}

	if h.replace != nil && h.replace.IsEnabled() {
		rawReq = applyRequestReplaceRaw(h.replace, rawReq)
	}

	rawReq = applyCustomDataRaw(h.customData, rawReq)

	if h.hookRunner != nil {
		hookInfo := sdk.RequestInfo{ID: id, Method: r.Method, URL: r.URL.String(), Host: hostname}
		modified, hookErr := h.hookRunner.RunRequestHook(r.Context(), hookInfo, rawReq)
		if hookErr == nil && modified == nil {
			http.Error(w, "request dropped by plugin", http.StatusForbidden)
			return
		}
		if hookErr == nil && modified != nil {
			rawReq = modified
		}
	}

	scheme := r.URL.Scheme
	host := r.URL.Host
	if h.transport != nil && h.transport.HTTP2() {
		// h2Cache could be plumbed through Handler if reuse becomes important;
		// per-stream fresh transports are fine for proxy traffic since the
		// http2.Transport caches connections internally per host.
	}

	res, err := SendRawRequest(r.Context(), rawReq, scheme, host, SendOptions{
		Decompress: false,
	}, h.transport)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		captured := buildUpstreamErrorCapture(id, start, r.Method, r.URL.String(), hostname, "HTTP/2", rawReq, err.Error())
		h.store.Add(captured)
		h.emit(eventRequestCaptured(captured))
		return
	}
	resp := res.Response
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	if h.replace != nil && h.replace.IsEnabled() && h.replace.HasResponseRules() {
		stripped := stripResponseHopHeaders(resp)
		newHeaders, newBody := applyResponseReplaceRaw(h.replace, stripped, respBody)
		copyHeadersToWriter(w, newHeaders)
		w.WriteHeader(resp.StatusCode)
		w.Write(newBody) //nolint:errcheck
		respBody = newBody
		resp.Header = newHeaders
	} else {
		stripHopHeaders(resp)
		copyHeadersToWriter(w, resp.Header)
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody) //nolint:errcheck
	}

	rawResp := dumpH2Response(resp, respBody)

	if h.hookRunner != nil {
		hookInfo := sdk.RequestInfo{ID: id, Method: r.Method, URL: r.URL.String(), Host: hostname}
		if modified, hookErr := h.hookRunner.RunResponseHook(r.Context(), hookInfo, rawResp); hookErr == nil && modified != nil {
			rawResp = modified
		}
	}

	duration := timeSince(start)
	captured := &CapturedRequest{
		ID:           id,
		Timestamp:    start,
		Method:       r.Method,
		URL:          r.URL.String(),
		Host:         hostname,
		Protocol:     "HTTP/2",
		StatusCode:   resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		Duration:     duration,
		ResponseSize: len(rawResp),
		ReqRaw:       rawReq,
		RespRaw:      rawResp,
	}
	h.store.Add(captured)
	h.emit(eventRequestCaptured(captured))
}

// dumpH2Request serializes an h2 *http.Request as HTTP/1-syntax text with
// "HTTP/2" in the request line. This is the synthetic representation operators
// see in the History/Intercept/Manipulate UIs.
//
// Headers are emitted in canonical case and alphabetical order so the same
// request renders identically across views. Content-Length is always written
// based on the actual body length so that re-parsing the synthesized bytes via
// http.ReadRequest preserves the body.
func dumpH2Request(r *http.Request, body []byte) []byte {
	var buf bytes.Buffer
	target := r.URL.RequestURI()
	if target == "" {
		target = "/"
	}
	fmt.Fprintf(&buf, "%s %s HTTP/2\r\n", r.Method, target)
	if r.Host != "" {
		fmt.Fprintf(&buf, "Host: %s\r\n", r.Host)
	}

	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		canonical := http.CanonicalHeaderKey(k)
		switch canonical {
		case "Host", "Content-Length":
			continue
		}
		if strings.HasPrefix(k, ":") { // defensive: pseudo-headers should be filtered by net/http2
			continue
		}
		keys = append(keys, canonical)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header.Values(k) {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}

	if len(body) > 0 || requestMethodHasBody(r.Method) {
		fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

// requestMethodHasBody reports whether the method conventionally carries a
// request body (so Content-Length: 0 is meaningful even for empty bodies).
func requestMethodHasBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// dumpH2Response synthesizes an HTTP/2-tagged response dump. h2 has no textual
// status line on the wire; this output is for display only.
func dumpH2Response(resp *http.Response, body []byte) []byte {
	var buf bytes.Buffer
	statusText := resp.Status
	if statusText == "" {
		statusText = strconv.Itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode)
	}
	fmt.Fprintf(&buf, "HTTP/2 %s\r\n", statusText)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

// applyRequestReplaceRaw applies request_header / request_body match-replace
// rules to raw HTTP request bytes (synthetic for h2). Header/body split is on
// the first \r\n\r\n; fall back to \n\n.
func applyRequestReplaceRaw(mr *MatchReplace, raw []byte) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		sep = []byte("\n\n")
		idx = bytes.Index(raw, sep)
		if idx < 0 {
			return raw
		}
	}
	headers := mr.Apply("request_header", raw[:idx])
	body := mr.Apply("request_body", raw[idx+len(sep):])
	out := make([]byte, 0, len(headers)+4+len(body))
	out = append(out, headers...)
	out = append(out, []byte("\r\n\r\n")...)
	out = append(out, body...)
	return out
}

// applyResponseReplaceRaw applies response_header / response_body rules to a
// pre-stripped header set and body, returning the modified header map and body.
func applyResponseReplaceRaw(mr *MatchReplace, headers http.Header, body []byte) (http.Header, []byte) {
	// Render headers, run header rules, parse back.
	var hbuf bytes.Buffer
	for k, vs := range headers {
		for _, v := range vs {
			fmt.Fprintf(&hbuf, "%s: %s\r\n", k, v)
		}
	}
	rendered := mr.Apply("response_header", hbuf.Bytes())
	parsed := parseHeaderBlock(rendered)
	newBody := mr.Apply("response_body", body)
	if parsed.Get("Content-Length") != "" {
		parsed.Set("Content-Length", strconv.Itoa(len(newBody)))
	}
	return parsed, newBody
}

// applyCustomDataRaw applies CustomData additions to raw HTTP/2 request bytes.
func applyCustomDataRaw(cd *CustomData, raw []byte) []byte {
	if cd == nil || !cd.IsEnabled() {
		return raw
	}
	items := cd.Items()
	if len(items) == 0 {
		return raw
	}

	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	// Copy out of raw so subsequent appends don't alias and overwrite the
	// separator + body that still live in raw's underlying array.
	headerBlock := append([]byte(nil), raw[:idx]...)
	body := append([]byte(nil), raw[idx+len(sep):]...)
	bodyMutated := false

	for _, item := range items {
		switch item.Type {
		case "header":
			full := fmt.Sprintf("%s: %s", item.Name, item.Value)
			if !bytes.Contains(headerBlock, []byte(full)) {
				headerBlock = append(headerBlock, '\r', '\n')
				headerBlock = append(headerBlock, full...)
			}
		case "body":
			if !bytes.Contains(body, []byte(item.Value)) {
				body = append(body, []byte(item.Value)...)
				bodyMutated = true
			}
		case "query":
			// Mutate request line: METHOD path?query HTTP/2
			lineEnd := bytes.IndexAny(headerBlock, "\r\n")
			if lineEnd < 0 {
				continue
			}
			parts := bytes.Fields(headerBlock[:lineEnd])
			if len(parts) < 3 {
				continue
			}
			pathPart := parts[1]
			joiner := "?"
			if bytes.Contains(pathPart, []byte("?")) {
				joiner = "&"
			}
			updated := append([]byte{}, pathPart...)
			updated = append(updated, []byte(joiner+item.Name+"="+item.Value)...)
			rebuilt := bytes.Join([][]byte{parts[0], updated, parts[2]}, []byte(" "))
			headerBlock = append(rebuilt, headerBlock[lineEnd:]...)
		}
	}

	out := make([]byte, 0, len(headerBlock)+4+len(body))
	out = append(out, headerBlock...)
	out = append(out, []byte("\r\n\r\n")...)
	out = append(out, body...)
	if bodyMutated {
		out = UpdateContentLength(out)
	}
	return out
}

// parseHeaderBlock parses a CRLF-separated header section back into http.Header.
func parseHeaderBlock(raw []byte) http.Header {
	h := http.Header{}
	for _, line := range bytes.Split(raw, []byte("\r\n")) {
		if len(line) == 0 {
			continue
		}
		idx := bytes.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := string(bytes.TrimSpace(line[:idx]))
		val := string(bytes.TrimSpace(line[idx+1:]))
		h.Add(key, val)
	}
	return h
}

// stripResponseHopHeaders is a non-mutating variant of stripHopHeaders that
// returns a cleaned http.Header copy (used when we want to apply response rules
// before writing to the client).
func stripResponseHopHeaders(resp *http.Response) http.Header {
	out := http.Header{}
	skip := map[string]struct{}{
		"Connection": {}, "Keep-Alive": {}, "Proxy-Authenticate": {}, "Proxy-Authorization": {},
		"Te": {}, "Trailer": {}, "Transfer-Encoding": {}, "Upgrade": {}, "Alt-Svc": {},
	}
	for k, vs := range resp.Header {
		if _, drop := skip[http.CanonicalHeaderKey(k)]; drop {
			continue
		}
		for _, v := range vs {
			out.Add(k, v)
		}
	}
	return out
}

// copyHeadersToWriter writes h to w.Header(). Skips headers the http2.Server
// will set itself.
func copyHeadersToWriter(w http.ResponseWriter, h http.Header) {
	for k, vs := range h {
		// http2.responseWriter manages these.
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Date":
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
}
