// Package capreg is the single place capabilities are declared.
//
// It exists as its own package for one structural reason: it imports neither
// internal/automation nor internal/api, transitively. A capability body therefore
// cannot reach the token store, the APIServer's settings or config store, the
// WebSocket hub, or the plugin manager.
//
// The two halves are enforced differently, which is worth knowing before trusting
// either. Importing internal/api here is an import cycle, because api imports this
// package to build the registry — so the compiler rejects it outright. Importing
// internal/automation is not a cycle and would compile, so that half rests on review
// alone; adding a field to Deps is the change that would break it.
//
// Everything a capability may touch arrives through Deps. Keep that struct small and
// specific; the temptation to pass *api.APIServer "just for one thing" is exactly
// what this package is arranged to prevent.
package capreg

import (
	"context"

	"github.com/BishopFox/joro/internal/capability"
	"github.com/BishopFox/joro/internal/cert"
	"github.com/BishopFox/joro/internal/detect"
	"github.com/BishopFox/joro/internal/fuzzer"
	"github.com/BishopFox/joro/internal/httptools"
	"github.com/BishopFox/joro/internal/mythic"
	"github.com/BishopFox/joro/internal/notes"
	"github.com/BishopFox/joro/internal/proxy"
	"github.com/BishopFox/joro/internal/sliver"
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
	WSStore   *proxy.WSStore
	CA        *cert.CA
	ProxyAddr string // Joro's own proxy listener, e.g. "127.0.0.1:8080"
	Version   string

	// ActiveProject names the loaded project. A getter because it changes at
	// runtime and this package must not reach into internal/api to read it.
	ActiveProject func() string

	// SetHighlight colours a History row, keyed on the capture's ID; an empty colour
	// clears it. A func for the same reason ActiveProject is one — the map lives on
	// *api.APIServer behind its mutex.
	SetHighlight func(requestID, color string)

	// Contexts holds one cookie jar per automation principal, so a send can stay
	// authenticated across calls.
	Contexts *httptools.Contexts

	// Fuzzer backs the fuzzer capabilities. Transport is the same dialer the Fuzz
	// tab uses, so an agent-started campaign honors SOCKS and HTTP/2 identically —
	// and, like the UI's, its traffic does not pass through Joro's own proxy.
	Fuzzer    *fuzzer.Store
	Transport *proxy.TransportConfig

	// Privileged enables the execution and C2 capabilities, from
	// --automation-privileged. When false they are not registered at all, so they
	// cannot be granted, listed or invoked.
	Privileged bool
	Sliver     *sliver.Client
	Mythic     *mythic.Client

	// Scripting enables script.run, from --automation-scripting. A separate flag from
	// Privileged, which means web shell and C2 specifically; this is a different axis
	// and an operator should be able to take one without the other.
	//
	// Script is the runner behind it, held as a narrow interface so a capability body
	// gets no more than "execute this source and tell me what happened". Zero when
	// scripting is off, and the handler reports that rather than panicking.
	Scripting bool
	Script    ScriptRunner

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

	// Webhooks fires an endpoint the operator already configured, and lists the ones they
	// opened to automation. Fire-only and ID-addressed: see caps_webhook.go for why there is
	// no create, edit or resolve here, and why the interface is this narrow rather than the
	// store itself. Zero when Joro was started with --no-webhooks, and the handlers report
	// that rather than panicking.
	Webhooks WebhookFirer

	// Broadcast is the hub's channel, so a mutating capability can push the same WS
	// events the REST handlers do — an agent editing the operator's configuration
	// should be visible while it happens, not on next reload. Typed as chan<- any
	// rather than *api.Hub to keep this package clear of internal/api. Sends must be
	// non-blocking; see broadcast in caps_write.go.
	Broadcast chan<- any
}

// Build assembles the registry.
//
// It tolerates zero-valued Deps: the handlers nil-check what they need and return
// an error rather than panicking, so a partially wired registry degrades one
// capability at a time instead of failing at startup.
func Build(d Deps, audit *capability.AuditLog) *capability.Registry {
	var scope capability.ScopeChecker
	if d.Scope != nil {
		scope = d.Scope
	}
	r := capability.NewRegistry(scope, audit)

	registerInstance(r, d)
	registerHistory(r, d)
	registerHighlight(r, d)
	registerSitemap(r, d)
	registerScope(r, d)
	registerScopeWrite(r, d)
	registerFindings(r, d)
	registerNotes(r, d)
	registerHTTP(r, d)
	registerExecContext(r, d)
	registerWebSocket(r, d)
	registerFuzzer(r, d)
	registerWrites(r, d)
	registerConfig(r, d)
	registerDetect(r, d)
	registerWebhook(r, d)
	if d.Privileged {
		registerPrivileged(r, d)
	}
	if d.Scripting {
		registerScript(r, d)
	}

	validateProfiles(r)
	// Not inside the d.Scripting branch above: the bundle is a constant of the binary, so
	// a bundle that must not ship should stop every start, not only the scripting ones.
	validateBundle(r)
	r.Seal()
	return r
}
