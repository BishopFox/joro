package api

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// originGuard restricts the proxy-mode API to same-origin browser requests.
//
// State-changing requests and the WebSocket upgrade must carry a same-origin (or
// none) Sec-Fetch-Site and a matching Origin; every request must target a loopback
// or the exact bind Host. Requests without these browser headers (non-browser local
// tooling) are allowed. Proxy mode only — listener/teamserver mode uses
// team.AuthMiddleware's bearer token.
func originGuard(bindAddr string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Host must be loopback or the exact bind address.
		if !hostAllowed(r.Host, bindAddr) {
			writeError(w, http.StatusForbidden, "forbidden: unexpected Host header")
			return
		}

		// Same-origin check on state-changing requests and the WebSocket upgrade.
		// GET endpoints carry Sec-Fetch-Site: none on direct navigation, so they
		// are not checked here.
		if isMutating(r.Method) || r.URL.Path == "/ws" {
			if !sameOrigin(r) {
				writeError(w, http.StatusForbidden, "forbidden: cross-origin request rejected")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	default:
		return false
	}
}

// sameOrigin reports whether a request's browser-asserted provenance is
// same-origin, or absent entirely (a non-browser client). It rejects when
// Sec-Fetch-Site indicates a cross-origin initiator or when the Origin host
// differs from the request Host.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		// Same-origin, a direct user navigation, or a non-browser client (header
		// absent). Fall through to the Origin cross-check.
	default: // "cross-site", "same-site"
		return false
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		if origin == "null" {
			return false // opaque/sandboxed cross-origin context
		}
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(reqHostname(u.Host), reqHostname(r.Host)) {
			return false
		}
	}
	return true
}

// hostAllowed reports whether the request Host is loopback or the exact configured
// bind address. A request whose Host matches neither is rejected.
func hostAllowed(reqHost, bindAddr string) bool {
	h := reqHostname(reqHost)
	if h == "" {
		return false
	}
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.EqualFold(h, reqHostname(bindAddr))
}

// reqHostname strips an optional :port from a host[:port] value, tolerating
// inputs that have no port and bare IPv6 literals.
func reqHostname(hostport string) string {
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}
