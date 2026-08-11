// Package capreg is the single place capabilities are declared.
//
// It exists as its own package for one structural reason: it imports neither
// internal/automation nor internal/api, and a test asserts that transitively. A
// capability body therefore cannot reach the token store, the APIServer's settings
// or config store, the WebSocket hub, or the plugin manager — not by convention,
// but because those types are not in scope and adding them would fail the build.
//
// Everything a capability may touch arrives through Deps. Keep that struct small
// and specific; the temptation to pass *api.APIServer "just for one thing" is
// exactly what this package is arranged to prevent.
package capreg

import (
	"context"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/cert"
	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/notes"
	"github.com/BishopFox/joro/internal/proxy"
)

// Deps carries exactly the components capabilities may touch.
//
// Deliberately absent: the automation token store, *api.APIServer, the WebSocket
// hub, the config store, and the plugin manager. A capability cannot reach what it
// is not handed.
type Deps struct {
	Store     *proxy.Store
	Scope     *proxy.Scope
	Findings  *detect.Store
	Engine    *detect.Engine
	Notes     *notes.Store
	CA        *cert.CA
	ProxyAddr string // Joro's own proxy listener, e.g. "127.0.0.1:8080"

	// The proxy's behavioral rule stores, for the config-class capabilities. These
	// are what "modify the proxy configuration" means here: Settings itself lives on
	// *api.APIServer and stays unreachable, which is also where the genuinely
	// dangerous knobs are — bind address, ports, SOCKS, the team token.
	Replace    *proxy.MatchReplace
	CustomData *proxy.CustomData
	Noise      *proxy.NoiseFilter
	Intercept  *proxy.InterceptQueue

	// Scanner backs detect.rescan. BgCtx must yield the server-lifetime context: a
	// rescan outlives the invocation that started it, and a capability's own ctx
	// carries a 30s timeout that would cancel the job partway.
	//
	// It is a getter, not a context, because SetAutomation runs before
	// StartDetectLoop (main.go:395 vs :401) — capturing the value here would pin the
	// nil that detectCtx still holds at that point.
	Scanner *detect.Scanner
	BgCtx   func() context.Context

	// Broadcast is the hub's channel, so a mutating capability can push the same WS
	// events the REST handlers do — an agent editing the operator's configuration
	// should be visible while it happens, not on next reload. Typed as chan<- any
	// rather than *api.Hub to keep this package clear of internal/api. Sends must be
	// non-blocking; see broadcast in caps_write.go.
	Broadcast chan<- any
}

// Build assembles the registry.
//
// It tolerates zero-valued Deps so a test can build the real registry and assert
// over its shape without standing up a proxy; the handlers nil-check what they
// need and return an error rather than panicking.
func Build(d Deps, audit *capability.AuditLog) *capability.Registry {
	var scope capability.ScopeChecker
	if d.Scope != nil {
		scope = d.Scope
	}
	r := capability.NewRegistry(scope, audit)

	registerHistory(r, d)
	registerSitemap(r, d)
	registerScope(r, d)
	registerScopeWrite(r, d)
	registerFindings(r, d)
	registerNotes(r, d)
	registerHTTP(r, d)
	registerWrites(r, d)
	registerConfig(r, d)
	registerDetect(r, d)

	validateProfiles(r)
	r.Seal()
	return r
}
