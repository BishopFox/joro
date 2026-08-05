package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/BishopFox/joro/internal/cert"
	"github.com/BishopFox/joro/sdk"
)

// HookRunner is implemented by the plugin manager to run proxy pipeline hooks.
type HookRunner interface {
	RunRequestHook(ctx context.Context, info sdk.RequestInfo, rawReq []byte) ([]byte, error)
	RunResponseHook(ctx context.Context, info sdk.RequestInfo, rawResp []byte) ([]byte, error)
}

// Handler is the main http.Handler for the intercepting proxy.
// It routes CONNECT requests to the MITM engine and plain HTTP to the forwarder.
type Handler struct {
	certCache  *cert.Cache
	store      *Store
	intercept  *InterceptQueue
	scope      *Scope
	noise      *NoiseFilter
	replace    *MatchReplace
	customData *CustomData
	transport  *TransportConfig
	wsStore    *WSStore
	broadcast  chan<- any
	hookRunner HookRunner // nil when no proxy hook plugins are loaded
}

// NewHandler creates a proxy Handler.
func NewHandler(certCache *cert.Cache, store *Store, intercept *InterceptQueue, scope *Scope, noise *NoiseFilter, replace *MatchReplace, customData *CustomData, transport *TransportConfig, wsStore *WSStore, broadcast chan<- any) *Handler {
	return &Handler{
		certCache:  certCache,
		store:      store,
		intercept:  intercept,
		scope:      scope,
		noise:      noise,
		replace:    replace,
		customData: customData,
		transport:  transport,
		wsStore:    wsStore,
		broadcast:  broadcast,
	}
}

// SetHookRunner sets the plugin hook runner for proxy pipeline hooks.
func (h *Handler) SetHookRunner(hr HookRunner) {
	h.hookRunner = hr
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
	} else {
		h.handleHTTP(w, r)
	}
}

// handleConnect processes HTTPS CONNECT tunnelling.
func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Acknowledge the CONNECT before hijacking. Set Content-Length to
	// prevent Go's server from adding Transfer-Encoding: chunked, which
	// violates RFC 9110 §9.3.6 for CONNECT responses.
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}

	hostname := strings.Split(host, ":")[0]
	if h.noise.IsNoisy(hostname) || !h.scope.HostInScope(hostname) {
		go h.tunnel(clientConn, host)
		return
	}
	go h.mitm(clientConn, hostname, host)
}

// tunnel passes raw TCP traffic without MITM for out-of-scope hosts.
func (h *Handler) tunnel(clientConn net.Conn, host string) {
	defer clientConn.Close()

	var upstream net.Conn
	var err error
	if dialCtx := h.transport.SOCKSDialContext(); dialCtx != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		upstream, err = dialCtx(ctx, "tcp", host)
	} else {
		upstream, err = net.DialTimeout("tcp", host, 10*time.Second)
	}
	if err != nil {
		return
	}
	defer upstream.Close()
	go io.Copy(upstream, clientConn) //nolint:errcheck
	io.Copy(clientConn, upstream)    //nolint:errcheck
}

// handleHTTP processes plain (non-CONNECT) HTTP proxy requests.
func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Remove proxy-specific headers.
	r.Header.Del("Proxy-Connection")
	r.RequestURI = ""

	if h.noise.IsNoisy(r.Host) || !h.scope.InScope(r.Host, r.Method, r.URL.Path) {
		transport := h.transport.Transport()
		resp, err := transport.RoundTrip(r)
		if err != nil {
			http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		copyBody(w, resp.Body)
		return
	}

	id := GenerateID()

	// WebSocket upgrade: branch into WS relay.
	if isWebSocketUpgrade(r) {
		h.handleWSUpgradeHTTP(w, r, id)
		return
	}
	start := timeNow()

	rawReq, _ := dumpRequest(r, true)

	// Captured before any re-parse: dumpRequest emits server-form, so a request
	// rebuilt from those bytes loses the upstream target.
	origScheme, origHost := r.URL.Scheme, r.URL.Host

	if h.intercept.IsEnabled() {
		meta := InterceptMeta{
			ID: id, Method: r.Method, URL: r.URL.String(), Host: r.Host,
			Protocol: "HTTP/1.1", ReqRaw: rawReq,
		}
		h.emit(eventInterceptQueued(KindRequest, meta))
		decision, _ := h.intercept.Pause(meta)
		h.emit(eventInterceptResolved(id, decision.Action))
		if decision.Action == ActionDrop {
			http.Error(w, "request dropped by intercept", http.StatusForbidden)
			return
		}
		if len(decision.ReqData) > 0 {
			modified, err := parseRequest(decision.ReqData)
			if err != nil {
				http.Error(w, "invalid modified request", http.StatusBadRequest)
				return
			}
			// The raw dump is server-form (path only), so the re-parsed URL has
			// no scheme or host and RoundTrip would fail with "unsupported
			// protocol scheme". Restore them from the original request, as the
			// HTTPS MITM path does.
			modified.URL.Scheme = origScheme
			modified.URL.Host = origHost
			modified.RequestURI = ""
			r = modified
			rawReq = decision.ReqData
		}
	}

	// Apply request match/replace rules.
	if h.replace != nil && h.replace.IsEnabled() {
		r = applyRequestReplace(h.replace, r)
		rawReq, _ = dumpRequest(r, true)
	}

	// Apply custom data additions.
	r = applyCustomData(h.customData, r)
	rawReq, _ = dumpRequest(r, true)

	// Run plugin request hooks.
	if h.hookRunner != nil {
		hookInfo := sdk.RequestInfo{ID: id, Method: r.Method, URL: r.URL.String(), Host: r.Host}
		modified, err := h.hookRunner.RunRequestHook(r.Context(), hookInfo, rawReq)
		if err == nil && modified == nil {
			http.Error(w, "request dropped by plugin", http.StatusForbidden)
			return
		}
		if err == nil && modified != nil {
			if parsed, parseErr := parseRequest(modified); parseErr == nil {
				r = parsed
				rawReq = modified
			}
		}
	}

	r.Header.Del("Accept-Encoding")
	transport := h.transport.Transport()
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		captured := buildUpstreamErrorCapture(id, start, r.Method, r.URL.String(), r.Host, "HTTP/1.1", rawReq, err.Error())
		h.store.Add(captured)
		h.emit(eventRequestCaptured(captured))
		return
	}
	defer resp.Body.Close()

	// Strip headers that can cause browsers to bypass the proxy (e.g. HTTP/3 via QUIC).
	resp.Header.Del("Alt-Svc")

	var rawResp []byte

	hasRespRules := h.replace != nil && h.replace.IsEnabled() && h.replace.HasResponseRules()
	wantPause := h.intercept.IsResponseEnabled() && responseIsPausable(resp) &&
		h.intercept.HasCapacityForResponse()

	if hasRespRules {
		resp = applyResponseReplace(h.replace, resp)
	}
	if hasRespRules || wantPause {
		// Buffered path: both response rules and the intercept pause need the
		// full body in hand. nil means the body was too large to buffer, so fall
		// through to streaming with the body restored intact.
		rawResp = readAndCaptureResponse(resp)
	}

	if rawResp == nil {
		// Streaming path: forward headers+body immediately.
		rawResp = streamAndCaptureHTTP(resp, w)
	} else {
		if wantPause {
			meta := InterceptMeta{
				ID: id, Method: r.Method, URL: r.URL.String(), Host: r.Host,
				Protocol: "HTTP/1.1", Status: resp.StatusCode, ReqRaw: rawReq, RespRaw: rawResp,
			}
			h.emit(eventInterceptQueued(KindResponse, meta))
			decision, _ := h.intercept.PauseResponse(meta)
			h.emit(eventInterceptResolved(id, decision.Action))

			if decision.Action == ActionDrop {
				// Nothing has been written to w yet, so this is a clean drop.
				http.Error(w, "response dropped by intercept", http.StatusForbidden)
				return
			}
			if len(decision.RespData) > 0 {
				if edited, ok := adoptEditedResponse(decision.RespData); ok {
					resp = edited
					rawResp = decision.RespData
				}
			}
		}
		// Let net/http compute framing from the buffered body: it sets
		// Content-Length or chunks as appropriate, so a stale upstream value
		// (or a chunked upstream's Transfer-Encoding, which this path never
		// strips) cannot desync the response.
		resp.Header.Del("Content-Length")
		resp.Header.Del("Transfer-Encoding")
		resp.Header.Del("Connection")
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		copyBody(w, resp.Body)
	}

	// Run plugin response hooks.
	if h.hookRunner != nil {
		hookInfo := sdk.RequestInfo{ID: id, Method: r.Method, URL: r.URL.String(), Host: r.Host}
		if modified, err := h.hookRunner.RunResponseHook(r.Context(), hookInfo, rawResp); err == nil && modified != nil {
			rawResp = modified
		}
	}

	duration := timeSince(start)
	captured := &CapturedRequest{
		ID:           id,
		Timestamp:    start,
		Method:       r.Method,
		URL:          r.URL.String(),
		Host:         r.Host,
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
}

// emit sends an event on the broadcast channel without blocking.
func (h *Handler) emit(e any) {
	if h.broadcast == nil {
		return
	}
	select {
	case h.broadcast <- e:
	default:
	}
}

// GenerateID returns a new unique hex string ID.
func GenerateID() string {
	b := make([]byte, 16)
	readRand(b)
	return toHexID(b)
}

