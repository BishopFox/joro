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
	registerFindings(r, d)
	registerNotes(r, d)
	registerHTTP(r, d)

	r.Seal()
	return r
}
