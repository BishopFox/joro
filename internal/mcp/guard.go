package mcp

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

// loopbackGuard rejects anything that looks like a browser reaching this listener.
//
// It is stricter than internal/api's originGuard, deliberately: that one protects
// a surface a browser is supposed to use, whereas nothing legitimate reaches this
// one from a page. The threat is DNS rebinding — a page the operator visits
// resolving a name to 127.0.0.1 and then driving the local MCP server with the
// browser's own credentials. Three checks close it:
//
//   - the Host header must be a loopback name, with no --allowed-host escape
//     hatch, so a rebound hostname does not match
//   - any Origin header at all is a rejection; a real MCP client is not a browser
//     and sends none, so its presence is itself the signal
//   - a Sec-Fetch-Site other than "none" means a browser initiated the request
//
// This runs before authentication, so a rebinding attempt never reaches the token
// lookup and cannot be used to probe for one.
func loopbackGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			writeGuardError(w, "forbidden: this listener only accepts loopback Host headers")
			return
		}
		if r.Header.Get("Origin") != "" {
			writeGuardError(w, "forbidden: browser-originated requests are not accepted here")
			return
		}
		if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "none" {
			writeGuardError(w, "forbidden: browser-originated requests are not accepted here")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackHost(hostport string) bool {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	// Any other loopback literal (127.0.0.2, say) is still local.
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func writeGuardError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
