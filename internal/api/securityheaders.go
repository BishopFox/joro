package api

import (
	"net/http"
	"strings"
)

// The Content-Security-Policy Joro serves its own UI under.
//
// # Why it matters more than it looks
//
// Everything on this origin is fully privileged. Any script running here can call the whole
// API same-origin — which includes installing an automation and arming it, and therefore,
// on an instance started with --automation-commands, running a program on the operator's
// machine. It does not need a package to already be armed; it can install its own. So a
// single injection anywhere on this origin is not "an XSS in a local tool", it is local code
// execution, and this header is the layer that stops one from getting that far.
//
// It also covers a case that is easy to miss. The response viewer renders captured HTML into
// a blob: URL and frames it with sandbox="allow-same-origin" and no allow-scripts, which is
// what keeps that markup inert. But a blob: URL is a real navigable URL on this origin, so
// opening the frame on its own — a browser's "open frame in new tab" — leaves the sandbox
// behind. A blob: document inherits the creating document's policy, so script-src here
// follows the captured bytes out of the frame and keeps them inert there too.
//
// # Why each directive is what it is
//
// script-src 'self' with no 'unsafe-inline': the built index.html carries no inline script,
// only a module tag pointing at a hashed asset, so nothing legitimate needs it.
//
// style-src keeps 'unsafe-inline' because React writes styles as inline attributes in
// places. Inline style is not an execution primitive, and buying its removal would mean
// rewriting component styling for no security gain.
//
// img-src allows data: for the XSS Hunter screenshots, which arrive as data:image URLs, and
// blob: for images the response viewer renders. Notably it does *not* allow arbitrary
// remote hosts, so a hostile value that named one would not be fetched — no beacon telling
// an attacker when the operator opened their finding.
//
// frame-src allows blob: for the response viewer and 'self' for plugin UIs. frame-ancestors
// is 'self' rather than 'none' precisely because Joro frames its own plugin pages.
//
// connect-src names ws: and wss: explicitly rather than trusting 'self' to cover the
// WebSocket upgrade across browsers.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; " +
	"font-src 'self'; " +
	"connect-src 'self' ws: wss:; " +
	"frame-src 'self' blob:; " +
	"frame-ancestors 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'"

// pluginPathPrefix is the mount point for plugin UI assets; see securityHeaders.
const pluginPathPrefix = "/plugin/"

// securityHeaders adds the UI's own policy to every response it serves.
//
// # The two exemptions, both deliberate
//
// **Plugin UIs are exempt.** A plugin's pages are served from /plugin/<name>/ and are
// written by whoever wrote the plugin, and inline <script> is the ordinary way to write a
// small one — every example plugin does it. A strict script-src would break all of them.
// That concedes nothing that was ever held: a plugin is native Go code already running
// inside this process, so it is trusted before its UI is ever loaded, which is the same
// reason those iframes carry allow-same-origin. Removing this exemption looks like
// hardening and breaks every plugin UI with errors that point nowhere near the cause.
//
// The consequence worth stating: a plugin UI that renders captured bytes as HTML is a
// Joro-origin XSS, and no policy here will catch it. That is a rule for plugin authors,
// not something this middleware can enforce.
//
// **Dev mode is exempt.** With --dev the UI is proxied from Vite, whose hot reloading needs
// inline script and eval. Gating on the flag keeps the shipped posture strict without
// making the development one unusable.
func securityHeaders(devMode bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Applies to every response either way: these cost nothing and want no exemption.
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")

		if !devMode && !strings.HasPrefix(r.URL.Path, pluginPathPrefix) {
			h.Set("Content-Security-Policy", contentSecurityPolicy)
		}
		next.ServeHTTP(w, r)
	})
}
